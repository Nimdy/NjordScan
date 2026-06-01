"""The knowledge base: one :class:`Rule` per detectable issue.

This module is what makes NjordScan friendly to non-security developers. Detectors
only need to emit a ``rule_id`` and a location; everything a developer needs to
*understand and fix* the issue lives here, in one place, reviewed like prose.

Each rule carries:
  - default ``severity`` (a detector may override per-occurrence)
  - ``cwe`` / ``owasp`` standards mappings
  - ``why``  — plain English, no jargon: why this is dangerous
  - ``fix``  — plain English: what to do about it
  - ``secure_example`` — a corrected code snippet to copy
  - ``references`` — links to learn more
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from ..core.severity import Severity


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: Severity
    why: str
    fix: str
    secure_example: str = ""
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    references: List[str] = field(default_factory=list)


def _rule(r: Rule) -> tuple[str, Rule]:
    return r.id, r


# NOTE: keep wording concrete and beginner-friendly. Assume the reader has never
# heard of "XSS". Explain the consequence ("an attacker can run JavaScript in your
# users' browsers and steal their session") before the label.
RULES: Dict[str, Rule] = dict(
    [
        _rule(Rule(
            id="xss.dangerously-set-inner-html",
            title="Untrusted data rendered with dangerouslySetInnerHTML",
            severity=Severity.HIGH,
            cwe="CWE-79",
            owasp="A03:2021-Injection",
            why=(
                "React normally escapes everything you render, which protects your "
                "users automatically. `dangerouslySetInnerHTML` turns that protection "
                "OFF and injects raw HTML. If any part of that HTML comes from a user "
                "(a form field, a URL, an API response, the database), an attacker can "
                "smuggle in a <script> tag and run their own JavaScript in your users' "
                "browsers — stealing logins, cookies, or making requests as the victim. "
                "This is called cross-site scripting (XSS)."
            ),
            fix=(
                "Prefer rendering text as `{value}` and let React escape it. If you "
                "truly need to render HTML (e.g. rich text from a CMS), sanitize it "
                "first with a library like DOMPurify and only then pass the cleaned "
                "string to dangerouslySetInnerHTML."
            ),
            secure_example=(
                "import DOMPurify from 'isomorphic-dompurify';\n"
                "const clean = DOMPurify.sanitize(userHtml);\n"
                "return <div dangerouslySetInnerHTML={{ __html: clean }} />;"
            ),
            references=[
                "https://react.dev/reference/react-dom/components/common#dangerously-setting-the-inner-html",
                "https://owasp.org/www-community/attacks/xss/",
            ],
        )),
        _rule(Rule(
            id="xss.inner-html",
            title="User input assigned to innerHTML / outerHTML",
            severity=Severity.HIGH,
            cwe="CWE-79",
            owasp="A03:2021-Injection",
            why=(
                "Assigning a string to `element.innerHTML` parses it as HTML. When the "
                "string contains data an attacker controls, they can inject markup that "
                "runs JavaScript in your users' browsers (cross-site scripting), letting "
                "them hijack accounts or steal data."
            ),
            fix=(
                "Use `element.textContent` to insert text safely, or build DOM nodes "
                "explicitly. In React, render `{value}` instead of touching innerHTML. "
                "If raw HTML is unavoidable, sanitize with DOMPurify first."
            ),
            secure_example="element.textContent = userInput; // rendered as text, never executed",
            references=["https://owasp.org/www-community/attacks/xss/"],
        )),
        _rule(Rule(
            id="injection.eval",
            title="eval() / Function() called on dynamic input",
            severity=Severity.CRITICAL,
            cwe="CWE-95",
            owasp="A03:2021-Injection",
            why=(
                "`eval()` (and `new Function(...)`) runs whatever string you give it as "
                "live code. If any part of that string can be influenced by a user, an "
                "attacker can execute arbitrary JavaScript — on the server this can mean "
                "full takeover of your app and its data."
            ),
            fix=(
                "There is almost always a safer alternative. Parse data with "
                "`JSON.parse`, look up behavior in an object/map, or use a real "
                "expression library. Never pass user-influenced strings to eval/Function."
            ),
            secure_example=(
                "// instead of eval(userInput)\n"
                "const actions = { start, stop };\n"
                "actions[userChoice]?.();"
            ),
            references=["https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval#never_use_eval!"],
        )),
        _rule(Rule(
            id="injection.command",
            title="Shell command built from untrusted input",
            severity=Severity.CRITICAL,
            cwe="CWE-78",
            owasp="A03:2021-Injection",
            why=(
                "Building a shell command by concatenating user input lets an attacker "
                "add their own commands (e.g. `; rm -rf /`). Functions like `exec` and "
                "`execSync` run through a shell, so injected text is executed on your "
                "server."
            ),
            fix=(
                "Use `execFile`/`spawn` with an arguments array (no shell), validate "
                "inputs against an allowlist, and never interpolate user data into a "
                "command string."
            ),
            secure_example="execFile('convert', [inputPath, outputPath]); // args are not parsed by a shell",
            references=["https://owasp.org/www-community/attacks/Command_Injection"],
        )),
        _rule(Rule(
            id="ssrf.fetch",
            title="Server-side fetch to a user-controlled URL (SSRF)",
            severity=Severity.HIGH,
            cwe="CWE-918",
            owasp="A10:2021-SSRF",
            why=(
                "When your server fetches a URL that the user chose, an attacker can "
                "point it at internal services or cloud metadata endpoints "
                "(e.g. http://169.254.169.254) that are normally unreachable from the "
                "outside — leaking credentials or letting them reach your private "
                "network. This is server-side request forgery (SSRF)."
            ),
            fix=(
                "Validate the destination against an allowlist of hosts you trust, "
                "reject private/loopback/link-local IP ranges, and disable automatic "
                "redirect-following for user-supplied URLs."
            ),
            secure_example=(
                "const url = new URL(userUrl);\n"
                "if (!ALLOWED_HOSTS.has(url.hostname)) throw new Error('host not allowed');"
            ),
            references=["https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"],
        )),
        _rule(Rule(
            id="open-redirect",
            title="Redirect to a user-controlled URL",
            severity=Severity.MEDIUM,
            cwe="CWE-601",
            owasp="A01:2021-Broken Access Control",
            why=(
                "Redirecting to a URL taken straight from user input lets attackers send "
                "your users to a look-alike phishing site through a link that starts on "
                "your trusted domain."
            ),
            fix="Only redirect to relative paths you control, or check the target against an allowlist.",
            secure_example="if (!target.startsWith('/')) target = '/'; res.redirect(target);",
            references=["https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"],
        )),
        # --- secrets ---
        _rule(Rule(
            id="secret.generic",
            title="Hard-coded secret or credential",
            severity=Severity.HIGH,
            cwe="CWE-798",
            owasp="A07:2021-Identification and Authentication Failures",
            why=(
                "A secret committed to your code (API key, password, token) is visible to "
                "anyone who can see the repository — and stays in git history forever, "
                "even if you delete the line later. Leaked keys are routinely scraped from "
                "public repos within minutes and used to run up bills or steal data."
            ),
            fix=(
                "Move the value to an environment variable, add the env file to "
                ".gitignore, and ROTATE the exposed secret now (assume it is already "
                "compromised). On Next.js, only expose values to the browser via the "
                "NEXT_PUBLIC_ prefix when you intend them to be public."
            ),
            secure_example="const apiKey = process.env.API_KEY; // set in your host's env / .env.local (gitignored)",
            references=["https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"],
        )),
        _rule(Rule(
            id="secret.aws-access-key",
            title="AWS access key committed to the repository",
            severity=Severity.CRITICAL,
            cwe="CWE-798",
            owasp="A07:2021-Identification and Authentication Failures",
            why=(
                "An AWS access key pair grants programmatic access to your cloud account. "
                "Committed AWS keys are scraped automatically and can be used to spin up "
                "servers (huge bills) or read your data within minutes of being pushed."
            ),
            fix=(
                "Deactivate and delete this key in the AWS IAM console immediately, then "
                "issue a new one and store it in your host's secret manager / environment "
                "— never in code."
            ),
            secure_example="// load from process.env at runtime; configure via AWS IAM roles where possible",
            references=["https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html"],
        )),
        _rule(Rule(
            id="secret.private-key",
            title="Private key committed to the repository",
            severity=Severity.CRITICAL,
            cwe="CWE-798",
            owasp="A07:2021-Identification and Authentication Failures",
            why=(
                "A private key (RSA/EC/SSH/PGP) is the master credential for whatever it "
                "protects — TLS, signing, server access. If it is in your repo, anyone "
                "with the code can impersonate your service or decrypt traffic."
            ),
            fix="Remove the key, rotate it, and store it in a secret manager. Purge it from git history.",
            secure_example="",
            references=["https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"],
        )),
        _rule(Rule(
            id="secret.public-env-exposure",
            title="Secret exposed to the browser via NEXT_PUBLIC_ / VITE_",
            severity=Severity.HIGH,
            cwe="CWE-200",
            owasp="A01:2021-Broken Access Control",
            why=(
                "Variables prefixed with NEXT_PUBLIC_ (Next.js) or VITE_ (Vite) are "
                "inlined into the JavaScript bundle that ships to every visitor. Putting a "
                "real secret (private API key, DB password) behind that prefix publishes "
                "it to the whole world."
            ),
            fix=(
                "Only use the public prefix for values that are safe to be public. Keep "
                "real secrets unprefixed and read them only in server code (Route "
                "Handlers, Server Actions, getServerSideProps)."
            ),
            secure_example="// server only:\nconst key = process.env.STRIPE_SECRET_KEY; // NOT NEXT_PUBLIC_",
            references=["https://nextjs.org/docs/app/building-your-application/configuring/environment-variables"],
        )),
        # --- supply chain / deps ---
        _rule(Rule(
            id="supply-chain.dangerous-install-script",
            title="Dangerous install lifecycle script in package.json",
            severity=Severity.CRITICAL,
            cwe="CWE-506",
            owasp="A08:2021-Software and Data Integrity Failures",
            why=(
                "`preinstall`/`postinstall` scripts run automatically on `npm install`, "
                "with your user's permissions. A script that pipes a remote file into a "
                "shell (curl | sh), opens a reverse shell, or reads credentials is a "
                "classic supply-chain attack — it runs before you ever start your app."
            ),
            fix=(
                "Review the script and the package that ships it. Install untrusted "
                "packages with `npm install --ignore-scripts`. Remove any install script "
                "that fetches and executes remote code."
            ),
            secure_example="npm install --ignore-scripts   # then run only the build steps you trust",
            references=["https://docs.npmjs.com/cli/v10/using-npm/scripts#best-practices"],
        )),
        _rule(Rule(
            id="supply-chain.dependency-install-script",
            title="An installed dependency has a dangerous install script",
            severity=Severity.CRITICAL,
            cwe="CWE-506",
            owasp="A08:2021-Software and Data Integrity Failures",
            why=(
                "One of your installed dependencies (in node_modules) runs a dangerous "
                "install script — it pipes remote content into a shell, opens a reverse "
                "shell, or reads your credentials, automatically, with your permissions, "
                "during `npm install`. This is exactly how real supply-chain attacks work: "
                "a popular package gets compromised and a malicious `postinstall` is added. "
                "You don't have to run the app — installing it is enough to be hit."
            ),
            fix=(
                "Do NOT run the app or `npm ci` again until you've investigated. Pin the "
                "dependency to a known-good earlier version, report it to npm, and install "
                "with `--ignore-scripts` in the meantime. Rotate any credentials the script "
                "could have read (npm token, cloud keys, SSH)."
            ),
            secure_example="npm install --ignore-scripts\n# then pin the package to a prior, trusted version",
            references=[
                "https://docs.npmjs.com/cli/v10/using-npm/scripts#best-practices",
                "https://owasp.org/www-community/attacks/Software_Supply_Chain_Attacks",
            ],
        )),
        _rule(Rule(
            id="supply-chain.dependency-script-changed",
            title="A dependency's install script is NEW or CHANGED since your last scan",
            severity=Severity.CRITICAL,
            cwe="CWE-506",
            owasp="A08:2021-Software and Data Integrity Failures",
            why=(
                "Since the last time NjordScan scanned this project, a dependency either "
                "GAINED an install script or its install script CHANGED. That is the #1 "
                "signal of a freshly-compromised package version — an attacker pushes a "
                "malicious patch release and your next `npm install` / redeploy picks it up "
                "before anyone has published an advisory. A trusted library does not normally "
                "start running new install-time code."
            ),
            fix=(
                "Treat this as a possible compromise. Diff the dependency against its previous "
                "version, check the npm release history and the maintainer, and do not deploy "
                "until you've confirmed the change is legitimate. Pin back to the last "
                "known-good version if in doubt."
            ),
            secure_example="npm view <pkg> versions   # inspect what changed; pin to a trusted version",
            references=["https://owasp.org/www-community/attacks/Software_Supply_Chain_Attacks"],
        )),
        _rule(Rule(
            id="supply-chain.integrity-changed",
            title="A pinned dependency's integrity hash changed under you",
            severity=Severity.CRITICAL,
            cwe="CWE-494",
            owasp="A08:2021-Software and Data Integrity Failures",
            why=(
                "The integrity hash for a dependency at the SAME version changed since your last "
                "scan. A published version is supposed to be immutable, so the same version should "
                "always have the same hash. A change means the content you'd install is now "
                "different — a sign of a re-published (compromised) version, a poisoned cache/mirror, "
                "or a tampered lockfile. This is the kind of integrity break that lets malicious "
                "code slip in without any version bump."
            ),
            fix=(
                "Do not install or deploy. Compare the lockfile against version control, clear your "
                "npm cache, re-resolve from the official registry, and verify the package on npm. "
                "If the hash genuinely changed upstream, treat the version as compromised and pin "
                "to a known-good one."
            ),
            secure_example="npm cache clean --force && rm -rf node_modules && npm ci   # re-resolve cleanly",
            references=["https://docs.npmjs.com/cli/v10/configuring-npm/package-lock-json#integrity"],
        )),
        _rule(Rule(
            id="supply-chain.missing-integrity",
            title="A dependency in the lockfile has no integrity hash",
            severity=Severity.MEDIUM,
            cwe="CWE-353",
            owasp="A08:2021-Software and Data Integrity Failures",
            why=(
                "This dependency is recorded in your lockfile without an integrity (subresource) "
                "hash, so npm cannot verify that what it downloads is what was published. Without "
                "it, a compromised registry, mirror, or man-in-the-middle could serve different "
                "content and you'd never know."
            ),
            fix=(
                "Re-generate the lockfile against the official registry (`rm package-lock.json && "
                "npm install`) so every entry gets an integrity hash. Avoid git/URL/file "
                "dependencies for anything security-sensitive."
            ),
            secure_example="rm package-lock.json && npm install   # regenerate with integrity hashes",
            references=["https://docs.npmjs.com/cli/v10/configuring-npm/package-lock-json#integrity"],
        )),
        _rule(Rule(
            id="supply-chain.missing-lockfile",
            title="No lockfile committed",
            severity=Severity.MEDIUM,
            cwe="CWE-1104",
            owasp="A06:2021-Vulnerable and Outdated Components",
            why=(
                "Without a lockfile (package-lock.json / yarn.lock / pnpm-lock.yaml), every "
                "install can pull different dependency versions. That means a malicious or "
                "broken version can slip in without any change to your code, and builds are "
                "not reproducible."
            ),
            fix="Commit your lockfile and install with `npm ci` in CI for exact, reproducible installs.",
            secure_example="git add package-lock.json && git commit -m 'add lockfile'",
            references=["https://docs.npmjs.com/cli/v10/configuring-npm/package-lock-json"],
        )),
        _rule(Rule(
            id="deps.known-vulnerability",
            title="Dependency with a known security vulnerability",
            severity=Severity.HIGH,
            cwe="CWE-1395",
            owasp="A06:2021-Vulnerable and Outdated Components",
            why=(
                "This package version has a publicly documented security flaw (a CVE/"
                "advisory). Attackers actively scan for apps using vulnerable versions "
                "because a working exploit is already published."
            ),
            fix="Upgrade to the patched version listed in the advisory (`npm update <pkg>` or bump it in package.json).",
            secure_example="npm install <package>@<patched-version>",
            references=["https://github.com/advisories"],
        )),
        _rule(Rule(
            id="deps.typosquat",
            title="Dependency name looks like a typosquat",
            severity=Severity.HIGH,
            cwe="CWE-427",
            owasp="A08:2021-Software and Data Integrity Failures",
            why=(
                "Attackers publish packages whose names are one keystroke away from a "
                "popular library (e.g. `reactt`, `loadsh`). Install the wrong one and you "
                "are running their code. The name in your package.json is very close to a "
                "well-known package but not exactly it."
            ),
            fix="Double-check the package name against the official docs and the publisher on npm before installing.",
            secure_example="",
            references=["https://owasp.org/www-community/attacks/Software_Supply_Chain_Attacks"],
        )),
        # --- config / headers ---
        _rule(Rule(
            id="config.missing-security-headers",
            title="Missing security response headers",
            severity=Severity.MEDIUM,
            cwe="CWE-693",
            owasp="A05:2021-Security Misconfiguration",
            why=(
                "Security headers (Content-Security-Policy, X-Frame-Options, "
                "Strict-Transport-Security, X-Content-Type-Options) are extra guardrails "
                "the browser enforces for you — blocking clickjacking, forcing HTTPS, and "
                "limiting the damage of an XSS bug. Without them you lose defense in depth."
            ),
            fix="Set security headers in next.config.js `headers()` (or your server/middleware).",
            secure_example=(
                "// next.config.js\n"
                "async headers() {\n"
                "  return [{ source: '/(.*)', headers: [\n"
                "    { key: 'X-Frame-Options', value: 'DENY' },\n"
                "    { key: 'X-Content-Type-Options', value: 'nosniff' },\n"
                "    { key: 'Strict-Transport-Security', value: 'max-age=63072000; includeSubDomains; preload' },\n"
                "  ]}];\n"
                "}"
            ),
            references=["https://nextjs.org/docs/app/api-reference/next-config-js/headers"],
        )),
        _rule(Rule(
            id="config.disabled-tls-verification",
            title="TLS certificate verification disabled",
            severity=Severity.HIGH,
            cwe="CWE-295",
            owasp="A02:2021-Cryptographic Failures",
            why=(
                "Setting NODE_TLS_REJECT_UNAUTHORIZED=0 or `rejectUnauthorized: false` "
                "turns off the check that you're really talking to the server you think "
                "you are. Anyone on the network can then impersonate that server and read "
                "or modify the traffic (man-in-the-middle)."
            ),
            fix="Remove the override. If you use self-signed certs in development, add the specific CA instead of disabling verification globally.",
            secure_example="// remove rejectUnauthorized:false; pass { ca: fs.readFileSync('dev-ca.pem') } if needed",
            references=["https://cwe.mitre.org/data/definitions/295.html"],
        )),
        _rule(Rule(
            id="react.unsafe-target-blank",
            title='Link opens with target="_blank" but no rel="noopener"',
            severity=Severity.LOW,
            cwe="CWE-1022",
            owasp="A01:2021-Broken Access Control",
            why=(
                "When a link opens a new tab with target=\"_blank\", the page it opens "
                "gets a reference back to your page via window.opener. A malicious "
                "destination can use that to silently redirect your tab to a phishing "
                "page (\"tabnabbing\"). Modern browsers mitigate this, but older ones "
                "and webviews do not."
            ),
            fix='Add rel="noopener noreferrer" to any link that uses target="_blank".',
            secure_example='<a href={url} target="_blank" rel="noopener noreferrer">Open</a>',
            references=["https://owasp.org/www-community/attacks/Reverse_Tabnabbing"],
        )),
        _rule(Rule(
            id="crypto.weak-hash",
            title="Weak hash algorithm (MD5/SHA-1)",
            severity=Severity.MEDIUM,
            cwe="CWE-327",
            owasp="A02:2021-Cryptographic Failures",
            why=(
                "MD5 and SHA-1 are broken: attackers can find collisions and, for "
                "passwords, crack them at billions of guesses per second. Using them to "
                "hash passwords or verify integrity gives a false sense of security."
            ),
            fix=(
                "For passwords use a slow, salted password hash (bcrypt, scrypt, or "
                "argon2). For integrity use SHA-256 or better."
            ),
            secure_example="import bcrypt from 'bcrypt';\nconst hash = await bcrypt.hash(password, 12);",
            references=["https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html"],
        )),
        _rule(Rule(
            id="crypto.insecure-random",
            title="Insecure randomness used for a security value",
            severity=Severity.MEDIUM,
            cwe="CWE-338",
            owasp="A02:2021-Cryptographic Failures",
            why=(
                "Math.random() is fast but predictable — an attacker who sees a few "
                "outputs can predict the rest. Using it to generate tokens, session ids, "
                "OTPs, or password-reset links lets an attacker guess them."
            ),
            fix=(
                "Use a cryptographically secure source: crypto.randomUUID(), "
                "crypto.getRandomValues() in the browser, or crypto.randomBytes() in Node."
            ),
            secure_example="import { randomUUID } from 'crypto';\nconst token = randomUUID();",
            references=["https://cwe.mitre.org/data/definitions/338.html"],
        )),
        _rule(Rule(
            id="nextjs.dangerous-config",
            title="Insecure Next.js configuration",
            severity=Severity.MEDIUM,
            cwe="CWE-16",
            owasp="A05:2021-Security Misconfiguration",
            why=(
                "Some next.config options loosen safety in ways that are easy to ship by "
                "accident — e.g. ignoring build/type errors hides real bugs, and overly "
                "broad image `domains`/`remotePatterns` let attackers proxy arbitrary "
                "content through your domain."
            ),
            fix="Don't ignore type/lint errors in production builds, and scope image and rewrite patterns to hosts you control.",
            secure_example="images: { remotePatterns: [{ protocol: 'https', hostname: 'assets.example.com' }] }",
            references=["https://nextjs.org/docs/app/api-reference/next-config-js"],
        )),
    ]
)


def get_rule(rule_id: str) -> Optional[Rule]:
    return RULES.get(rule_id)


def all_rules() -> List[Rule]:
    return list(RULES.values())
