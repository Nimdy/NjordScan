"""Dependency reachability / true VEX — do you actually call the vulnerable function?"""

from __future__ import annotations

import pytest

from njordscan.core.config import Config
from njordscan.core.project import Project
from njordscan.core.usage import UsageIndex

from conftest import scan


def _project(tmp_path, code: str, *, lodash="4.17.4"):
    (tmp_path / "package.json").write_text(
        '{"name":"t","dependencies":{"lodash":"%s"}}' % lodash)
    (tmp_path / "lib").mkdir(exist_ok=True)
    (tmp_path / "lib" / "x.js").write_text(code)
    return tmp_path


def _deps(result):
    return {f.metadata["advisory_id"]: f for f in result.findings
            if f.rule_id == "deps.known-vulnerability"}


@pytest.mark.asyncio
async def test_exploitable_when_vulnerable_fn_is_called(tmp_path):
    p = _project(tmp_path, "import { template } from 'lodash';\nexport const f = (s) => template(s);")
    by = _deps(await scan(p, only_detectors=["dependencies"]))
    assert by["CVE-2021-23337"].reachable is True          # template() is the vuln fn
    assert by["CVE-2021-23337"].metadata["vex_state"] == "exploitable"
    assert by["CVE-2021-23337"].effective_severity.value == "high"
    # the prototype-pollution CVEs target other functions you don't call
    assert by["CVE-2019-10744"].reachable is False
    assert by["CVE-2019-10744"].metadata["vex_state"] == "not_affected"
    assert by["CVE-2019-10744"].effective_severity.value == "low"


@pytest.mark.asyncio
async def test_not_affected_when_only_safe_fn_used(tmp_path):
    p = _project(tmp_path, "import { map } from 'lodash';\nexport const f = (a) => map(a, (n) => n);")
    deps = [f for f in (await scan(p, only_detectors=["dependencies"])).findings
            if f.rule_id == "deps.known-vulnerability"]
    assert deps and all(f.reachable is False for f in deps)
    assert all(f.metadata["vex_justification"] == "vulnerable_code_not_in_execute_path" for f in deps)


@pytest.mark.asyncio
async def test_not_affected_when_package_not_imported(tmp_path):
    p = _project(tmp_path, "export const f = (a) => a.map((n) => n);")   # lodash declared but never imported
    deps = [f for f in (await scan(p, only_detectors=["dependencies"])).findings
            if f.rule_id == "deps.known-vulnerability"]
    assert deps and all(f.reachable is False for f in deps)
    assert all(f.metadata["vex_justification"] == "code_not_present" for f in deps)


def test_usage_index_parses_import_forms(tmp_path):
    (tmp_path / "package.json").write_text('{"name":"t"}')
    (tmp_path / "a.js").write_text("import _ from 'lodash';\nconst x = _.template('y');\n")
    (tmp_path / "b.ts").write_text("import { merge as m } from 'lodash';\n")
    (tmp_path / "c.js").write_text("const { set } = require('lodash');\n")
    (tmp_path / "d.js").write_text("import tpl from 'lodash/template';\n")
    proj = Project.load(Config(target=tmp_path))
    idx = UsageIndex(proj)
    syms = idx.for_package("lodash").symbols
    assert {"template", "merge", "set"} <= syms   # default-member, named, require-destructure, subpath
    assert idx.uses_symbol("lodash", {"template"}) is True
    assert idx.uses_symbol("lodash", {"zipObjectDeep"}) is False
    assert idx.uses_symbol("react", {"useState"}) is None   # not imported anywhere
