"""Sensitivity-labeled taint — the data-EGRESS tracer.

Runs the taint engine in reverse: a named sensitive value (env secret / credential)
is the SOURCE and a trust-boundary exit (log / response / browser storage / a
third-party SDK) is the SINK. The two guarantees this pins down: (1) it fires on a
secret actually leaving the boundary, and (2) it NEVER perturbs the injection
analysis and never fires on generic names or non-egress reads.
"""

from __future__ import annotations

import pytest

from conftest import scan

pytestmark = pytest.mark.asyncio


def _app(tmp_path, src: str):
    (tmp_path / "app" / "api" / "x").mkdir(parents=True, exist_ok=True)
    (tmp_path / "app" / "api" / "x" / "route.ts").write_text(src)
    (tmp_path / "package.json").write_text('{"name":"a","dependencies":{"next":"14.0.0"}}')
    return tmp_path


async def _dataflow_rules(tmp_path):
    r = await scan(tmp_path, only_detectors=["taint"])
    return [f for f in r.findings if f.rule_id.startswith("dataflow.")]


async def test_env_secret_and_credential_to_log(tmp_path):
    app = _app(tmp_path, """
export async function POST(req, user) {
  console.log("k", process.env.STRIPE_SECRET_KEY);
  console.log("h", user.passwordHash);
}
""".lstrip())
    hits = await _dataflow_rules(app)
    rules = sorted(f.rule_id for f in hits)
    assert rules == ["dataflow.sensitive-to-log", "dataflow.sensitive-to-log"]
    assets = {f.metadata.get("data_asset") for f in hits}
    assert assets == {"secret.env", "secret.credential"}


async def test_each_egress_destination(tmp_path):
    app = _app(tmp_path, """
import * as Sentry from "@sentry/node";
export async function POST(req, user) {
  NextResponse.json(user.passwordHash);
  localStorage.setItem("t", user.accessToken);
  Sentry.captureException(process.env.DATABASE_URL);
}
""".lstrip())
    rules = sorted(f.rule_id for f in await _dataflow_rules(app))
    assert rules == [
        "dataflow.sensitive-to-browser-storage",
        "dataflow.sensitive-to-response",
        "dataflow.sensitive-to-thirdparty",
    ]


async def test_non_sensitive_and_generic_names_not_flagged(tmp_path):
    app = _app(tmp_path, """
export async function POST(req, user) {
  console.log("hi", user.displayName);       // not sensitive
  const token = theme.token;                 // generic 'token' — must not match
  console.log("theme", token);
  analytics.track("evt", { name: user.name });
}
""".lstrip())
    assert await _dataflow_rules(app) == []


async def test_no_arg_json_read_is_not_egress(tmp_path):
    # response.json() with no args READS a body — it is not a sink
    app = _app(tmp_path, """
export async function GET(req) {
  const data = await fetch("/x").then(r => r.json());
  return Response.json({ ok: true });
}
""".lstrip())
    assert await _dataflow_rules(app) == []


async def test_credential_through_a_variable(tmp_path):
    # LHS credential-name labeling: a value held in a credential-named var, then logged
    app = _app(tmp_path, """
export async function POST(req) {
  const accessToken = mintToken(req);
  console.log("token is", accessToken);
}
""".lstrip())
    hits = await _dataflow_rules(app)
    assert [f.rule_id for f in hits] == ["dataflow.sensitive-to-log"]
    assert hits[0].taint_flow and hits[0].taint_flow[0].kind == "source"


async def test_secret_in_eval_is_NOT_an_injection_finding(tmp_path):
    # process.env feeding eval must not become injection.eval (env is trusted for
    # injection); the capability split guarantees this.
    app = _app(tmp_path, """
export async function POST(req) {
  eval(process.env.SOME_CODE);
}
""".lstrip())
    r = await scan(app, only_detectors=["taint"])
    assert not any(f.rule_id == "injection.eval" for f in r.findings)


async def test_robust_on_empty_and_weird(tmp_path):
    app = _app(tmp_path, "export const x = 1;\n")
    assert await _dataflow_rules(app) == []


# ── adversarial-review regression guards ──────────────────────────────────────

async def test_public_and_diagnostic_env_vars_not_flagged(tmp_path):
    app = _app(tmp_path, """
export async function POST(req) {
  console.log(process.env.NODE_ENV);
  console.log(process.env.PORT);
  console.log(process.env.NEXT_PUBLIC_API_URL);
  console.log(process.env.VITE_PUBLIC_THING);
}
""".lstrip())
    assert await _dataflow_rules(app) == []


async def test_nonrevealing_derivations_not_flagged(tmp_path):
    # the tool must not flag the very redaction its fix text recommends
    app = _app(tmp_path, """
export async function POST(req) {
  console.log(process.env.STRIPE_SECRET_KEY.slice(-4));
  console.log(process.env.STRIPE_SECRET_KEY.length);
  if (process.env.API_SECRET === "x") {}
  console.log(Boolean(process.env.JWT_SECRET));
}
""".lstrip())
    assert await _dataflow_rules(app) == []


async def test_credential_named_var_with_literal_rhs_not_flagged(tmp_path):
    app = _app(tmp_path, """
export async function POST(req) {
  const password = "Please enter your password";
  console.log(password);
  const accessToken = "";
  console.log(accessToken);
}
""".lstrip())
    assert await _dataflow_rules(app) == []


async def test_compound_credential_names_flag_lookalikes_dont(tmp_path):
    app = _app(tmp_path, """
export async function POST(req, user) {
  console.log(user.userPassword);     // FLAG
  console.log(user.stripeSecretKey);  // FLAG
  console.log(user.hashedPassword);   // FLAG
  const passwordless = true; console.log(passwordless);  // no
  const tokenizer = mk(); console.log(tokenizer);        // no
  console.log(user.displayName);                          // no
}
""".lstrip())
    hits = await _dataflow_rules(app)
    assert len(hits) == 3
    assert all(f.rule_id == "dataflow.sensitive-to-log" for f in hits)


async def test_object_shorthand_property_is_resolved(tmp_path):
    app = _app(tmp_path, """
export async function GET(req) {
  const apiKey = process.env.MY_SECRET_KEY;
  return NextResponse.json({ apiKey });
}
""".lstrip())
    hits = await _dataflow_rules(app)
    assert [f.rule_id for f in hits] == ["dataflow.sensitive-to-response"]


async def test_cross_function_egress_and_injection_coexist(tmp_path):
    app = _app(tmp_path, """
function leak(x) { console.log(x); }
function run(cmd) { execSync(cmd); }
export function handler(req) {
  leak(process.env.SECRET_KEY);
  run(req.body.cmd);
  leak(req.body.name);
}
""".lstrip())
    r = await scan(app, only_detectors=["taint"])
    rules = {f.rule_id for f in r.findings}
    assert "dataflow.sensitive-to-log" in rules     # cross-function secret egress
    assert "injection.command" in rules             # cross-function injection still works
    # the injectable-but-not-secret leak(req.body.name) must NOT be a secret egress
    egress = [f for f in r.findings if f.rule_id.startswith("dataflow.")]
    assert len(egress) == 1


async def test_user_method_named_like_egress_still_detects_injection(tmp_path):
    # D1 regression: a user method named send/json must not shadow the injection pass
    app = _app(tmp_path, """
const client = { send(u) { return execSync("curl " + u); } };
export async function GET(req) {
  client.send(req.query.t);
}
""".lstrip())
    r = await scan(app, only_detectors=["taint"])
    assert any(f.rule_id == "injection.command" for f in r.findings)
