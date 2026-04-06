#!/usr/bin/env python3
"""
Tests for tree-sitter based taint tracking.
"""

import pytest
import sys
import os
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

try:
    from njordscan.analysis.taint_tracker import TaintTracker, TREE_SITTER_AVAILABLE
except ImportError:
    TREE_SITTER_AVAILABLE = False

pytestmark = pytest.mark.skipif(not TREE_SITTER_AVAILABLE, reason="tree-sitter not installed")


@pytest.fixture
def tracker():
    return TaintTracker()


# --------------------------------------------------------------------- #
#  Basic taint source -> sink detection
# --------------------------------------------------------------------- #

class TestBasicTaintFlows:

    def test_req_body_to_innerhtml(self, tracker):
        code = 'const x = req.body.name;\nel.innerHTML = x;'
        flows = tracker.analyze_file(Path("app.js"), code)
        assert len(flows) == 1
        assert flows[0].cwe_id == "CWE-79"
        assert flows[0].source.source_type == "req.body"
        assert flows[0].sink.sink_type == "innerHTML"

    def test_req_query_to_eval(self, tracker):
        code = 'const cmd = req.query.cmd;\neval(cmd);'
        flows = tracker.analyze_file(Path("app.js"), code)
        assert len(flows) == 1
        assert flows[0].cwe_id == "CWE-95"
        assert flows[0].sink.sink_type == "eval"

    def test_req_params_to_exec(self, tracker):
        code = 'const input = req.params.file;\nexec(input);'
        flows = tracker.analyze_file(Path("app.js"), code)
        assert len(flows) == 1
        assert flows[0].cwe_id == "CWE-78"

    def test_req_body_to_document_write(self, tracker):
        code = 'const data = req.body.html;\ndocument.write(data);'
        flows = tracker.analyze_file(Path("app.js"), code)
        assert len(flows) == 1
        assert flows[0].sink.sink_type == "document.write"

    def test_window_location_to_innerhtml(self, tracker):
        code = 'const loc = window.location.search;\nel.innerHTML = loc;'
        flows = tracker.analyze_file(Path("app.js"), code)
        assert len(flows) == 1
        assert flows[0].source.source_type == "window.location"

    def test_prompt_to_eval(self, tracker):
        code = 'const input = prompt("enter code");\neval(input);'
        flows = tracker.analyze_file(Path("app.js"), code)
        assert len(flows) == 1
        assert flows[0].source.source_type == "prompt()"

    def test_req_body_to_redirect(self, tracker):
        code = 'const url = req.body.url;\nres.redirect(url);'
        flows = tracker.analyze_file(Path("app.js"), code)
        assert len(flows) == 1
        assert flows[0].cwe_id == "CWE-601"

    def test_req_body_to_readfile(self, tracker):
        code = 'const p = req.query.path;\nreadFile(p);'
        flows = tracker.analyze_file(Path("api.js"), code)
        assert len(flows) == 1
        assert flows[0].cwe_id == "CWE-22"


# --------------------------------------------------------------------- #
#  Taint propagation through assignments
# --------------------------------------------------------------------- #

class TestTaintPropagation:

    def test_single_hop(self, tracker):
        code = 'const raw = req.body.x;\nconst data = raw;\neval(data);'
        flows = tracker.analyze_file(Path("app.js"), code)
        assert len(flows) >= 1
        assert flows[0].source.source_type == "req.body"

    def test_two_hops(self, tracker):
        code = 'const a = req.body.x;\nconst b = a;\nconst c = b;\neval(c);'
        flows = tracker.analyze_file(Path("app.js"), code)
        assert len(flows) >= 1

    def test_reassignment(self, tracker):
        code = 'let x = req.body.data;\nx = x;\neval(x);'
        flows = tracker.analyze_file(Path("app.js"), code)
        assert len(flows) >= 1


# --------------------------------------------------------------------- #
#  Safe code — no false positives
# --------------------------------------------------------------------- #

class TestNoFalsePositives:

    def test_safe_arithmetic(self, tracker):
        code = 'const x = 1 + 2;\nconsole.log(x);'
        assert tracker.analyze_file(Path("safe.js"), code) == []

    def test_safe_string_literal(self, tracker):
        code = 'const msg = "hello";\nel.innerHTML = msg;'
        # msg is a literal, not from user input — should NOT be flagged
        flows = tracker.analyze_file(Path("safe.js"), code)
        assert len(flows) == 0

    def test_safe_eval_with_literal(self, tracker):
        code = 'eval("console.log(1)");'
        flows = tracker.analyze_file(Path("safe.js"), code)
        assert len(flows) == 0

    def test_safe_function_call(self, tracker):
        code = 'function greet(name) { return "Hello " + name; }'
        assert tracker.analyze_file(Path("safe.js"), code) == []


# --------------------------------------------------------------------- #
#  TypeScript / TSX support
# --------------------------------------------------------------------- #

class TestTypeScriptSupport:

    def test_tsx_file_parses(self, tracker):
        code = 'const x: string = req.body.name;\neval(x);'
        flows = tracker.analyze_file(Path("app.tsx"), code)
        assert len(flows) >= 1

    def test_ts_file_parses(self, tracker):
        code = 'const input: string = req.query.q;\ndocument.write(input);'
        flows = tracker.analyze_file(Path("handler.ts"), code)
        assert len(flows) >= 1


# --------------------------------------------------------------------- #
#  Flow metadata
# --------------------------------------------------------------------- #

# --------------------------------------------------------------------- #
#  Cross-function taint tracking
# --------------------------------------------------------------------- #

class TestCrossFunctionTaint:

    def test_function_passing_param_to_innerhtml(self, tracker):
        code = (
            'function render(html) {\n'
            '  document.getElementById("out").innerHTML = html;\n'
            '}\n'
            'const input = req.body.content;\n'
            'render(input);\n'
        )
        flows = tracker.analyze_file(Path("app.js"), code)
        cross_flows = [f for f in flows if 'render()' in f.sink.sink_type]
        assert len(cross_flows) == 1
        assert cross_flows[0].cwe_id == "CWE-79"

    def test_function_passing_param_to_eval(self, tracker):
        code = (
            'function run(code) {\n'
            '  eval(code);\n'
            '}\n'
            'const cmd = req.query.cmd;\n'
            'run(cmd);\n'
        )
        flows = tracker.analyze_file(Path("app.js"), code)
        cross_flows = [f for f in flows if 'run()' in f.sink.sink_type]
        assert len(cross_flows) == 1
        assert cross_flows[0].cwe_id == "CWE-95"

    def test_safe_function_no_flow(self, tracker):
        code = (
            'function log(msg) {\n'
            '  console.log(msg);\n'
            '}\n'
            'const x = req.body.name;\n'
            'log(x);\n'
        )
        flows = tracker.analyze_file(Path("safe.js"), code)
        # console.log is not a sink, so no cross-function flow
        cross_flows = [f for f in flows if 'log()' in f.sink.sink_type]
        assert len(cross_flows) == 0

    def test_second_param_is_tainted(self, tracker):
        code = (
            'function setContent(el, html) {\n'
            '  el.innerHTML = html;\n'
            '}\n'
            'const data = req.body.html;\n'
            'setContent(element, data);\n'
        )
        flows = tracker.analyze_file(Path("app.js"), code)
        cross_flows = [f for f in flows if 'setContent()' in f.sink.sink_type]
        assert len(cross_flows) == 1


class TestFlowMetadata:

    def test_flow_has_line_numbers(self, tracker):
        code = 'const x = req.body.a;\neval(x);'
        flows = tracker.analyze_file(Path("app.js"), code)
        assert flows[0].source.line == 1
        assert flows[0].sink.line == 2

    def test_flow_has_file_path(self, tracker):
        code = 'const x = req.body.a;\neval(x);'
        flows = tracker.analyze_file(Path("src/handler.js"), code)
        assert flows[0].file_path == "src/handler.js"

    def test_flow_has_confidence(self, tracker):
        code = 'const x = req.body.a;\neval(x);'
        flows = tracker.analyze_file(Path("app.js"), code)
        assert 0.0 < flows[0].confidence <= 1.0
