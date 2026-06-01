"""Taint tracking — NjordScan's headline detector.

Parses JS/JSX/TS/TSX into a tree-sitter AST and tracks how user-controlled data
(SOURCES, e.g. ``req.body``, ``searchParams.get(...)``, ``window.location``)
flows into dangerous SINKS (``innerHTML``, ``eval``, ``child_process.exec``,
server-side ``fetch``, ``res.redirect``, and React's ``dangerouslySetInnerHTML``).

Improvements over V1 (``njordscan/analysis/taint_tracker.py``):
  - **JSX attributes** are handled, so ``dangerouslySetInnerHTML={{ __html: X }}``
    — the #1 React XSS sink — is now detected. V1 missed it entirely.
  - **Cross-function** tracking handles not just plain named functions but also
    arrow functions assigned to a ``const`` and member-expression callees. If a
    function writes one of its parameters into a sink, calling it with a tainted
    argument is reported, with a ``taint_flow`` showing source -> call -> sink.

Design constraints honoured here:
  - ``scan()`` never raises: every file is parsed inside try/except and partial
    results are returned. A scanner that dies on one weird file is useless.
  - Parsing (CPU-bound) is offloaded with ``asyncio.to_thread``.
  - Only stdlib + tree-sitter (already installed). Imports are guarded so the
    module still imports (and yields ``[]``) if tree-sitter is ever absent.
  - Only rule_ids that exist in :mod:`njordscan.knowledge.rules` are emitted.
"""

from __future__ import annotations

import asyncio
import logging
import re
from pathlib import Path, PurePosixPath
from typing import Dict, List, Optional, Set, Tuple

from ..core.finding import Finding, TaintStep
from ..core.project import Project
from .base import Detector

logger = logging.getLogger(__name__)

# Guard the parser imports: if tree-sitter is missing the module still imports
# and the detector degrades to yielding nothing (the registry tolerates this).
try:
    import tree_sitter as ts
    import tree_sitter_javascript as tsjs
    import tree_sitter_typescript as tsts

    _TREE_SITTER_OK = True
except Exception as exc:  # noqa: BLE001 — optional dependency, degrade gracefully
    logger.debug("tree-sitter unavailable, taint detector will yield nothing: %s", exc)
    _TREE_SITTER_OK = False


# --------------------------------------------------------------------------- #
#  Source / sink definitions
# --------------------------------------------------------------------------- #

# Member-expression prefixes that introduce user-controlled data. Matched as an
# (object, property) pair anywhere inside a flattened member chain, so both
# ``req.query`` and ``req.query.id.foo`` are recognised.
_SOURCE_MEMBERS: Dict[Tuple[str, str], str] = {
    ("req", "body"): "req.body",
    ("req", "query"): "req.query",
    ("req", "params"): "req.params",
    ("req", "cookies"): "req.cookies",
    ("req", "headers"): "req.headers",
    ("req", "url"): "req.url",
    ("request", "body"): "request.body",
    ("request", "query"): "request.query",
    ("request", "params"): "request.params",
    ("request", "cookies"): "request.cookies",
    ("request", "headers"): "request.headers",
    ("request", "url"): "request.url",
    ("request", "nextUrl"): "request.nextUrl",
    ("ctx", "query"): "ctx.query",
    ("ctx", "params"): "ctx.params",
    ("router", "query"): "router.query",
    ("router", "asPath"): "router.asPath",
    ("window", "location"): "window.location",
    ("document", "location"): "document.location",
    ("document", "URL"): "document.URL",
    ("document", "referrer"): "document.referrer",
    ("document", "cookie"): "document.cookie",
    ("location", "search"): "location.search",
    ("location", "hash"): "location.hash",
    ("location", "href"): "location.href",
    ("event", "data"): "event.data",
    ("e", "data"): "e.data",
    ("process", "argv"): "process.argv",
    ("process", "env"): None,  # sentinel: env is NOT user-controlled; never a source
}

# Bare identifiers that are themselves a source (the whole `window` object, etc.).
_SOURCE_IDENTIFIERS: Dict[str, str] = {
    "searchParams": "searchParams",
}

# Calls whose return value is tainted. Key may be a bare name ("useSearchParams")
# or a member property ("get" on a *.searchParams/*.query-ish receiver — kept
# permissive but only when the receiver is itself a known params object/var).
_SOURCE_CALLS_BARE: Dict[str, str] = {
    "useSearchParams": "useSearchParams()",
    "useRouter": None,  # the router object is not itself tainted; .query is
    "prompt": "prompt()",
}

# .get(...) is treated as a source only when called on one of these receivers
# (or a variable known to hold one), so we don't flag every Map/cache .get().
_GET_SOURCE_RECEIVERS = {"searchParams", "useSearchParams"}

# ---- sinks -------------------------------------------------------------------

# Property-assignment sinks: ``<obj>.<prop> = <tainted>``  ->  rule_id
_ASSIGN_SINK_PROPS: Dict[str, str] = {
    "innerHTML": "xss.inner-html",
    "outerHTML": "xss.inner-html",
}

# Member-call sinks keyed by property name -> rule_id. ``obj`` constrains the
# receiver where it matters (None = any receiver).
_MEMBER_CALL_SINKS: Dict[str, Tuple[Optional[str], str]] = {
    "insertAdjacentHTML": (None, "xss.inner-html"),
    "write": ("document", "xss.inner-html"),
    "writeln": ("document", "xss.inner-html"),
    "redirect": (None, "open-redirect"),  # res.redirect / Response.redirect / NextResponse.redirect
    "push": ("router", "open-redirect"),
    "replace": ("router", "open-redirect"),
    "assign": ("location", "open-redirect"),
}

# Bare-call sinks keyed by callee identifier -> rule_id.
_BARE_CALL_SINKS: Dict[str, str] = {
    "eval": "injection.eval",
    "Function": "injection.eval",     # new Function(...) and Function(...)
    "exec": "injection.command",
    "execSync": "injection.command",
    "spawn": "injection.command",
    "spawnSync": "injection.command",
    "fetch": "ssrf.fetch",
}

# Member-call sinks where the *argument* (not a property assignment) is the
# tainted value: child_process.exec(...), axios.get(url), http.get(url), etc.
_MEMBER_ARG_SINKS: Dict[str, str] = {
    "exec": "injection.command",
    "execSync": "injection.command",
    "spawn": "injection.command",
    "spawnSync": "injection.command",
    "get": "ssrf.fetch",      # axios.get / http.get / https.get
    "request": "ssrf.fetch",  # http.request / axios.request
}
# Only treat axios/http/https/fetch receivers as SSRF sinks, to keep precision.
_SSRF_RECEIVERS = {"axios", "http", "https", "fetch", "got", "superagent", "request"}

# setTimeout/setInterval are sinks only when the first arg is a STRING (or tainted
# string), never when it's a function. Handled specially.
_TIMER_SINKS = {"setTimeout", "setInterval"}

# Literal / clearly-safe node types — passing only these to a sink is not a flow.
_LITERAL_TYPES = {
    "string", "template_string", "number", "true", "false", "null",
    "undefined", "regex",
}


class TaintDetector(Detector):
    """Source-to-sink taint tracking for JS/TS/JSX/TSX, including cross-function flows."""

    id = "taint"
    name = "Taint analysis (source → sink)"
    kind = "static"

    def __init__(self) -> None:
        self._languages: Dict[str, "ts.Language"] = {}
        if _TREE_SITTER_OK:
            try:
                self._languages["js"] = ts.Language(tsjs.language())
                self._languages["tsx"] = ts.Language(tsts.language_tsx())
            except Exception as exc:  # noqa: BLE001
                logger.debug("Failed to init tree-sitter languages: %s", exc)
                self._languages = {}

    def applies(self, project: Project) -> bool:
        # No point running if we can't parse anything.
        return bool(self._languages)

    async def scan(self, project: Project) -> List[Finding]:
        if not self._languages:
            return []
        files = [p for p in project.source_files if _is_code(p)]
        file_rels = {project.rel(p) for p in files}

        # Phase A: parse every file once and summarise which functions forward a
        # parameter into a sink (the per-file summary needed for interprocedural taint).
        prep = await asyncio.gather(
            *(asyncio.to_thread(self._parse_and_summarize, project, path) for path in files),
            return_exceptions=True,
        )
        parsed: Dict[str, Tuple[object, str]] = {}
        summaries: Dict[str, Dict[str, Dict[int, Tuple[str, str]]]] = {}
        imports: Dict[str, Dict[str, Tuple[str, str]]] = {}
        for res in prep:
            if isinstance(res, Exception) or res is None:
                continue
            rel, root, text, sink_funcs = res
            parsed[rel] = (root, text)
            summaries[rel] = sink_funcs
            imports[rel] = _named_imports(text)

        # Phase B: full analysis per file, injecting summaries of imported functions
        # that are defined (and sink-forwarding) in another module (cross-file flows).
        def analyze(rel: str) -> List[Finding]:
            root, text = parsed[rel]
            extra: Dict[str, Tuple[Dict[int, Tuple[str, str]], str]] = {}
            for local, (spec, orig) in imports.get(rel, {}).items():
                target = _resolve_import(rel, spec, file_rels)
                if target and orig in summaries.get(target, {}):
                    extra[local] = (summaries[target][orig], target)
            try:
                return _FileAnalyzer(rel, text, self.id).run(root, extra_sink_funcs=extra)
            except Exception as exc:  # noqa: BLE001 — never crash on weird input
                logger.debug("taint: analysis failed on %s: %r", rel, exc)
                return []

        results = await asyncio.gather(
            *(asyncio.to_thread(analyze, rel) for rel in parsed), return_exceptions=True
        )
        findings: List[Finding] = []
        for res in results:
            if isinstance(res, Exception):
                continue
            findings.extend(res)
        return _dedup(findings)

    # -- per-file ------------------------------------------------------------

    def _parse_and_summarize(self, project: Project, path: Path):
        """Parse a file and return (rel, root, text, sink_func_summary) or None."""
        try:
            text = project.read_text(path)
            if not text.strip():
                return None
            lang_key = "tsx" if path.suffix.lower() in (".ts", ".tsx") else "js"
            language = self._languages.get(lang_key) or self._languages.get("js")
            if language is None:
                return None
            tree = ts.Parser(language).parse(text.encode("utf-8"))
            root = tree.root_node   # Node keeps the Tree alive
            rel = project.rel(path)
            analyzer = _FileAnalyzer(rel, text, self.id)
            analyzer._collect_sink_functions(root)
            return rel, root, text, analyzer.sink_funcs
        except Exception as exc:  # noqa: BLE001
            logger.debug("taint: parse failed on %s: %r", path, exc)
            return None


# --------------------------------------------------------------------------- #
#  Per-file analysis
# --------------------------------------------------------------------------- #


class _FileAnalyzer:
    """Holds the taint state for a single file and produces findings."""

    def __init__(self, rel: str, text: str, detector_id: str) -> None:
        self.rel = rel
        self.text = text
        self.detector_id = detector_id
        # func name -> {param_index: (rule_id, sink_label, sink_prop)}
        self.sink_funcs: Dict[str, Dict[int, Tuple[str, str]]] = {}
        # local imported name -> source file, for sink functions defined in another module
        self.cross_file_src: Dict[str, str] = {}
        self.findings: List[Finding] = []
        self._seen: Set[Tuple[str, int, str]] = set()

    # -- entry point ---------------------------------------------------------

    def run(self, root, extra_sink_funcs: Optional[Dict[str, Tuple[Dict[int, Tuple[str, str]], str]]] = None) -> List[Finding]:
        # Pass 1: which user-defined functions forward a parameter into a sink?
        self._collect_sink_functions(root)
        # Inject summaries of imported functions defined in OTHER files (interprocedural,
        # cross-module). A local definition always wins over an injected one.
        if extra_sink_funcs:
            for name, (summary, src_file) in extra_sink_funcs.items():
                if name not in self.sink_funcs:
                    self.sink_funcs[name] = summary
                    self.cross_file_src[name] = src_file
        # Pass 2: track sources and detect direct + cross-function (+ cross-file) flows.
        self._walk(root, tainted={})
        return self.findings

    # -- pass 1 --------------------------------------------------------------

    def _collect_sink_functions(self, node) -> None:
        for fn_node, fn_name in _iter_named_functions(node):
            params = _param_names(fn_node)
            if not params:
                continue
            body = fn_node.child_by_field_name("body")
            if body is None:
                continue
            for idx, pname in enumerate(params):
                hit = self._param_reaches_sink(body, pname)
                if hit is not None:
                    self.sink_funcs.setdefault(fn_name, {})[idx] = hit

    def _param_reaches_sink(self, body, param: str) -> Optional[Tuple[str, str]]:
        """Return (rule_id, sink_label) if ``param`` (taint-propagated) hits a sink in body."""
        probe = _FileAnalyzer(self.rel, self.text, self.detector_id)
        probe.sink_funcs = self.sink_funcs  # allow nested cross-function reuse
        seed = {param: _Taint(label=f"parameter:{param}", line=0, snippet="")}
        probe._walk(body, tainted=seed, record=False)
        if probe._probe_hit is not None:
            return probe._probe_hit
        return None

    _probe_hit: Optional[Tuple[str, str]] = None

    # -- pass 2 (also reused as a probe in pass 1) ---------------------------

    def _walk(self, node, tainted: Dict[str, "_Taint"], record: bool = True) -> None:
        """Recursively walk, mutating ``tainted`` in scope order (single pass)."""
        ntype = node.type

        if ntype in ("variable_declarator",):
            self._handle_declarator(node, tainted)
        elif ntype == "assignment_expression":
            self._handle_assignment(node, tainted, record)
        elif ntype in ("call_expression", "new_expression"):
            self._handle_call(node, tainted, record)
        elif ntype == "jsx_attribute":
            self._handle_jsx_attribute(node, tainted, record)

        for child in node.children:
            self._walk(child, tainted, record)

    # -- declarations / assignments -----------------------------------------

    def _handle_declarator(self, node, tainted: Dict[str, "_Taint"]) -> None:
        name_node = node.child_by_field_name("name")
        value_node = node.child_by_field_name("value")
        if name_node is None or value_node is None:
            return
        if name_node.type != "identifier":
            return  # skip destructuring for assignment LHS (sources still matched in RHS)
        var = _text(name_node)
        taint = self._taint_of_expr(value_node, tainted)
        if taint is not None:
            tainted[var] = taint.renamed(var, node.start_point.row + 1)

    def _handle_assignment(self, node, tainted: Dict[str, "_Taint"], record: bool) -> None:
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left is None or right is None:
            return

        # Sink: <obj>.innerHTML = <tainted/non-literal>
        if left.type in ("member_expression", "subscript_expression"):
            prop = _prop_name(left)
            if prop in _ASSIGN_SINK_PROPS:
                self._maybe_report_value(
                    right, tainted, rule_id=_ASSIGN_SINK_PROPS[prop],
                    sink_label=f"{_receiver_text(left)}.{prop}", node=node, record=record,
                )
                return

        # Plain variable assignment propagates taint.
        if left.type == "identifier":
            var = _text(left)
            taint = self._taint_of_expr(right, tainted)
            if taint is not None:
                tainted[var] = taint.renamed(var, node.start_point.row + 1)
            elif var in tainted:
                # Reassigned to something clean -> drop the taint.
                del tainted[var]

    # -- calls ---------------------------------------------------------------

    def _handle_call(self, node, tainted: Dict[str, "_Taint"], record: bool) -> None:
        fn_node = node.child_by_field_name("function") or node.child_by_field_name("constructor")
        args_node = node.child_by_field_name("arguments")
        if fn_node is None:
            return

        # --- bare callee: eval(x), exec(x), fetch(url), Function(...), setTimeout(str) ---
        if fn_node.type == "identifier":
            name = _text(fn_node)
            if name in _TIMER_SINKS:
                self._handle_timer(node, args_node, tainted, record)
            elif name in _BARE_CALL_SINKS:
                self._report_first_tainted_arg(
                    args_node, tainted, rule_id=_BARE_CALL_SINKS[name],
                    sink_label=f"{name}(...)", node=node, record=record,
                )
            else:
                self._handle_cross_function(name, args_node, tainted, record)

        # --- member callee: obj.method(x) ---
        elif fn_node.type == "member_expression":
            prop = _prop_name(fn_node)
            recv = _root_object_name(fn_node)
            self._handle_member_call(node, fn_node, prop, recv, args_node, tainted, record)

    def _handle_member_call(
        self, node, fn_node, prop: Optional[str], recv: Optional[str],
        args_node, tainted: Dict[str, "_Taint"], record: bool,
    ) -> None:
        if prop is None:
            return

        # document.write(...), el.insertAdjacentHTML(...), res.redirect(...), router.push(...)
        if prop in _MEMBER_CALL_SINKS:
            want_recv, rule_id = _MEMBER_CALL_SINKS[prop]
            if want_recv is None or recv == want_recv:
                # A redirect to a constant same-origin path — redirect(new URL("/x", base))
                # or redirect("/x") — can't be an open redirect; don't flag it.
                if rule_id == "open-redirect" and _is_same_origin_redirect(args_node):
                    return
                # insertAdjacentHTML's HTML payload is the 2nd arg; others use 1st.
                arg_index = 1 if prop == "insertAdjacentHTML" else 0
                self._report_tainted_arg_at(
                    args_node, tainted, rule_id=rule_id,
                    sink_label=f"{recv or ''}.{prop}(...)".lstrip("."),
                    node=node, record=record, index=arg_index,
                )
                return

        # child_process.exec(...), axios.get(url), http.request(url)
        if prop in _MEMBER_ARG_SINKS:
            rule_id = _MEMBER_ARG_SINKS[prop]
            if rule_id == "ssrf.fetch" and recv not in _SSRF_RECEIVERS:
                pass  # not a recognised HTTP client receiver
            else:
                self._report_first_tainted_arg(
                    args_node, tainted, rule_id=rule_id,
                    sink_label=f"{recv or ''}.{prop}(...)".lstrip("."),
                    node=node, record=record,
                )
                return

        # Cross-function: obj.method(taint) where method forwards a param to a sink.
        if prop in self.sink_funcs:
            self._handle_cross_function(prop, args_node, tainted, record)

    def _handle_timer(self, node, args_node, tainted, record: bool) -> None:
        """setTimeout/setInterval are sinks only when the first arg is a string-ish value."""
        if args_node is None:
            return
        first = _first_arg(args_node)
        if first is None:
            return
        # A function/arrow callback is the safe, normal case — ignore it.
        if first.type in ("function", "arrow_function", "function_expression"):
            return
        if first.type in ("string", "template_string"):
            # constant string code — flag (could embed tainted via template)
            taint = self._taint_of_expr(first, tainted)
            conf = "high" if taint else "medium"
            self._report(
                rule_id="injection.eval", node=node, value_node=first,
                sink_label="setTimeout/setInterval(string)", taint=taint,
                confidence=conf, record=record,
            )
            return
        # identifier or member: only flag if tainted (otherwise likely a fn ref)
        taint = self._taint_of_expr(first, tainted)
        if taint is not None:
            self._report(
                rule_id="injection.eval", node=node, value_node=first,
                sink_label="setTimeout/setInterval(string)", taint=taint,
                confidence="high", record=record,
            )

    def _handle_cross_function(self, fn_name: str, args_node, tainted, record: bool) -> None:
        spec = self.sink_funcs.get(fn_name)
        if not spec or args_node is None:
            return
        args = _arg_list(args_node)
        for idx, arg in enumerate(args):
            if idx not in spec:
                continue
            taint = self._taint_of_expr(arg, tainted)
            if taint is None:
                continue
            rule_id, sink_label = spec[idx]
            src_file = self.cross_file_src.get(fn_name)
            if src_file:   # the sink lives in another module — make the flow say so
                step_label = f"{fn_name}() in {src_file} (param {idx} -> {sink_label})"
                sink_text = f"{fn_name}() -> {sink_label} [in {src_file}]"
                step_file = src_file
            else:
                step_label = f"{fn_name}(... param {idx} -> sink)"
                sink_text = f"{fn_name}() -> {sink_label}"
                step_file = self.rel
            extra = [TaintStep(
                label=step_label, file=step_file, line=arg.start_point.row + 1,
                kind="propagation", code=_line_text(self.text, arg.start_point.row + 1),
            )]
            self._report(
                rule_id=rule_id, node=arg, value_node=arg,
                sink_label=sink_text, taint=taint,
                confidence="high", record=record, extra_steps=extra,
            )
            return  # one finding per call is plenty

    # -- JSX -----------------------------------------------------------------

    def _handle_jsx_attribute(self, node, tainted, record: bool) -> None:
        # children: property_identifier '=' jsx_expression
        attr_name_node = node.children[0] if node.children else None
        if attr_name_node is None or _text(attr_name_node) != "dangerouslySetInnerHTML":
            return
        # find the value expression: jsx_expression -> object -> pair(__html: X)
        value_expr = None
        for child in node.children:
            if child.type == "jsx_expression":
                value_expr = child
                break
        if value_expr is None:
            return
        html_node = _find_html_value(value_expr)
        if html_node is None:
            return
        # A literal string is the (rare) safe case; flag anything non-literal.
        if html_node.type in _LITERAL_TYPES:
            return
        taint = self._taint_of_expr(html_node, tainted)
        confidence = "high" if taint is not None else "medium"
        self._report(
            rule_id="xss.dangerously-set-inner-html", node=node, value_node=html_node,
            sink_label="dangerouslySetInnerHTML __html", taint=taint,
            confidence=confidence, record=record,
        )

    # -- taint evaluation of an expression -----------------------------------

    def _taint_of_expr(self, node, tainted: Dict[str, "_Taint"]) -> Optional["_Taint"]:
        """Return a _Taint if ``node`` is/contains user-controlled data, else None."""
        # Direct source member expression (req.body, window.location, ...).
        src = self._source_label(node)
        if src is not None:
            return _Taint(label=src, line=node.start_point.row + 1,
                          snippet=_line_text(self.text, node.start_point.row + 1))

        # A tainted call return: useSearchParams(), searchParams.get(...), prompt().
        if node.type in ("call_expression",):
            csrc = self._call_source_label(node)
            if csrc is not None:
                return _Taint(label=csrc, line=node.start_point.row + 1,
                              snippet=_line_text(self.text, node.start_point.row + 1))

        # A reference to an already-tainted variable.
        if node.type == "identifier":
            t = tainted.get(_text(node))
            return t

        # Composite expressions: any tainted sub-part taints the whole.
        if node.type in (
            "binary_expression", "template_string", "template_substitution",
            "parenthesized_expression", "member_expression", "subscript_expression",
            "ternary_expression", "sequence_expression", "augmented_assignment_expression",
            "call_expression", "spread_element", "object", "array", "pair",
        ):
            for child in node.children:
                t = self._taint_of_expr(child, tainted)
                if t is not None:
                    return t
        return None

    def _source_label(self, node) -> Optional[str]:
        """If ``node`` is a member chain rooted at a known source, return its label."""
        if node.type == "identifier":
            return _SOURCE_IDENTIFIERS.get(_text(node))
        if node.type not in ("member_expression", "subscript_expression"):
            return None
        parts = _flatten_member(node)
        if not parts:
            return None
        # process.env is explicitly NOT a source.
        for i in range(len(parts) - 1):
            key = (parts[i], parts[i + 1])
            if key in _SOURCE_MEMBERS:
                label = _SOURCE_MEMBERS[key]
                if label is None:  # sentinel (process.env) -> not tainted
                    return None
                return ".".join(parts[: i + 2])
        # bare source identifier as the root (searchParams.get handled via call)
        if parts[0] in _SOURCE_IDENTIFIERS:
            return _SOURCE_IDENTIFIERS[parts[0]]
        return None

    def _call_source_label(self, node) -> Optional[str]:
        fn = node.child_by_field_name("function")
        if fn is None:
            return None
        if fn.type == "identifier":
            name = _text(fn)
            label = _SOURCE_CALLS_BARE.get(name)
            return label  # None for useRouter (not itself tainted)
        if fn.type == "member_expression":
            prop = _prop_name(fn)
            recv = _root_object_name(fn)
            if prop == "get" and recv in _GET_SOURCE_RECEIVERS:
                return f"{recv}.get(...)"
        return None

    # -- reporting helpers ---------------------------------------------------

    def _maybe_report_value(self, value_node, tainted, *, rule_id, sink_label, node, record) -> None:
        """Report an assignment sink. Tainted -> high; risky non-literal -> medium; safe -> skip."""
        if value_node.type in _LITERAL_TYPES:
            return
        taint = self._taint_of_expr(value_node, tainted)
        if taint is None:
            # A bare unresolved identifier (e.g. a function parameter, or a value
            # we never saw tainted) is too weak to flag on its own — the real
            # vulnerability, if any, is caught at the tainted call site by the
            # cross-function pass. Only flag medium-confidence when the RHS is a
            # *constructed* expression (concatenation, template, member access),
            # which is the classic "someone built HTML from data" smell.
            if value_node.type == "identifier":
                return
        confidence = "high" if taint is not None else "medium"
        self._report(
            rule_id=rule_id, node=node, value_node=value_node,
            sink_label=sink_label, taint=taint, confidence=confidence, record=record,
        )

    def _report_first_tainted_arg(self, args_node, tainted, *, rule_id, sink_label, node, record) -> None:
        if args_node is None:
            return
        for arg in _arg_list(args_node):
            taint = self._taint_of_expr(arg, tainted)
            if taint is not None:
                self._report(
                    rule_id=rule_id, node=node, value_node=arg,
                    sink_label=sink_label, taint=taint, confidence="high", record=record,
                )
                return

    def _report_tainted_arg_at(self, args_node, tainted, *, rule_id, sink_label, node, record, index) -> None:
        if args_node is None:
            return
        args = _arg_list(args_node)
        if index >= len(args):
            return
        arg = args[index]
        if arg.type in _LITERAL_TYPES:
            return
        taint = self._taint_of_expr(arg, tainted)
        if taint is None and arg.type == "identifier":
            # Bare unresolved identifier (e.g. a forwarded parameter) — too weak
            # on its own; the tainted call site is reported by the cross-function
            # pass instead. Keeps precision high.
            return
        confidence = "high" if taint is not None else "medium"
        self._report(
            rule_id=rule_id, node=node, value_node=arg,
            sink_label=sink_label, taint=taint, confidence=confidence, record=record,
        )

    def _report(
        self, *, rule_id, node, value_node, sink_label, taint, confidence,
        record: bool, extra_steps: Optional[List[TaintStep]] = None,
    ) -> None:
        # In probe mode (pass 1) we only need to know that a parameter reaches a
        # sink — record the hit and return without producing a real finding.
        if not record:
            if self._probe_hit is None:
                self._probe_hit = (rule_id, sink_label)
            return

        line = node.start_point.row + 1
        snippet = _line_text(self.text, line)
        key = (rule_id, line, snippet)
        if key in self._seen:
            return
        self._seen.add(key)

        flow: List[TaintStep] = []
        if taint is not None and taint.line:
            flow.append(TaintStep(
                label=taint.label, file=self.rel, line=taint.line,
                kind="source", code=taint.snippet,
            ))
        if extra_steps:
            flow.extend(extra_steps)
        flow.append(TaintStep(
            label=sink_label, file=self.rel, line=line, kind="sink", code=snippet,
        ))

        if taint is not None and taint.label:
            message = f"User input from `{taint.label}` flows into {sink_label}."
        else:
            message = f"Non-literal (possibly user-controlled) value reaches {sink_label}."

        self.findings.append(Finding(
            rule_id=rule_id,
            file=self.rel,
            line=line,
            column=node.start_point.column + 1,
            code_snippet=snippet,
            detector=self.detector_id,
            confidence=confidence,
            message=message,
            taint_flow=flow,
        ))


# --------------------------------------------------------------------------- #
#  Lightweight value object for a tainted variable
# --------------------------------------------------------------------------- #


class _Taint:
    __slots__ = ("label", "line", "snippet")

    def __init__(self, label: str, line: int, snippet: str) -> None:
        self.label = label
        self.line = line
        self.snippet = snippet

    def renamed(self, var: str, line: int) -> "_Taint":
        # Keep the original source label so the flow points back to the real source.
        return _Taint(label=self.label, line=self.line or line, snippet=self.snippet)


# --------------------------------------------------------------------------- #
#  AST helpers (module-level, no parser state)
# --------------------------------------------------------------------------- #


def _text(node) -> str:
    try:
        return node.text.decode("utf-8") if node.text is not None else ""
    except Exception:  # noqa: BLE001
        return ""


def _line_text(text: str, line: int) -> str:
    lines = text.splitlines()
    if 1 <= line <= len(lines):
        return lines[line - 1].strip()
    return ""


def _flatten_member(node) -> List[str]:
    """Flatten ``a.b.c`` (member/subscript) into ['a', 'b', 'c']. Best-effort."""
    if node.type == "identifier":
        return [_text(node)]
    if node.type in ("member_expression", "subscript_expression"):
        obj = node.child_by_field_name("object")
        prop = node.child_by_field_name("property") or node.child_by_field_name("index")
        parts = _flatten_member(obj) if obj is not None else []
        if prop is not None and prop.type in ("property_identifier", "identifier"):
            parts.append(_text(prop))
        return parts
    return []


def _prop_name(node) -> Optional[str]:
    prop = node.child_by_field_name("property")
    if prop is not None:
        return _text(prop)
    return None


def _receiver_text(node) -> str:
    obj = node.child_by_field_name("object")
    return _text(obj) if obj is not None else ""


def _root_object_name(node) -> Optional[str]:
    """For ``a.b.c`` return 'a'; for ``a.b`` return 'a'. Used to constrain receivers."""
    parts = _flatten_member(node)
    return parts[0] if parts else None


def _arg_list(args_node) -> List:
    return [c for c in args_node.children if c.type not in (",", "(", ")")]


def _first_arg(args_node):
    args = _arg_list(args_node)
    return args[0] if args else None


def _param_names(fn_node) -> List[str]:
    params_node = fn_node.child_by_field_name("parameters")
    if params_node is None:
        # arrow with a single unparenthesised param: `x => ...`
        single = fn_node.child_by_field_name("parameter")
        if single is not None and single.type == "identifier":
            return [_text(single)]
        return []
    names: List[str] = []
    for p in params_node.children:
        if p.type == "identifier":
            names.append(_text(p))
        elif p.type in ("required_parameter", "optional_parameter"):
            pat = p.child_by_field_name("pattern") or p.child_by_field_name("name")
            if pat is not None and pat.type == "identifier":
                names.append(_text(pat))
            else:
                names.append("")  # keep index alignment for destructured params
        elif p.type in ("object_pattern", "array_pattern", "assignment_pattern", "rest_pattern"):
            names.append("")  # index placeholder; we can't track destructured params yet
    return names


def _iter_named_functions(root):
    """Yield (function_node, name) for named declarations and ``const f = (..)=>{}``."""
    stack = [root]
    while stack:
        node = stack.pop()
        if node.type == "function_declaration":
            name = node.child_by_field_name("name")
            if name is not None:
                yield node, _text(name)
        elif node.type == "variable_declarator":
            name = node.child_by_field_name("name")
            value = node.child_by_field_name("value")
            if (
                name is not None and name.type == "identifier"
                and value is not None
                and value.type in ("arrow_function", "function", "function_expression")
            ):
                yield value, _text(name)
        elif node.type == "method_definition":
            name = node.child_by_field_name("name")
            if name is not None:
                yield node, _text(name)
        for child in node.children:
            stack.append(child)


def _find_html_value(jsx_expression_node):
    """Inside ``{{ __html: X }}`` return the node for X."""
    for child in jsx_expression_node.children:
        if child.type == "object":
            for pair in child.children:
                if pair.type == "pair":
                    key = pair.child_by_field_name("key")
                    if key is not None and _text(key) == "__html":
                        return pair.child_by_field_name("value")
        # Also handle a spread or direct value: dangerouslySetInnerHTML={x.__html}
    return None


def _is_code(path: Path) -> bool:
    return path.suffix.lower() in (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx")


def _dedup(findings: List[Finding]) -> List[Finding]:
    seen: Set[str] = set()
    out: List[Finding] = []
    for f in findings:
        fp = f.fingerprint
        if fp in seen:
            continue
        seen.add(fp)
        out.append(f)
    return out


# --------------------------------------------------------------------------- #
#  Cross-file import resolution (for interprocedural taint)
# --------------------------------------------------------------------------- #

_NAMED_IMPORT = re.compile(r"""import\s*\{([^}]*)\}\s*from\s*['"]([^'"]+)['"]""")
_CODE_EXT = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs")


def _named_imports(text: str) -> Dict[str, Tuple[str, str]]:
    """{local_name: (module_spec, original_export)} for `import { a, b as c } from './m'`."""
    out: Dict[str, Tuple[str, str]] = {}
    for m in _NAMED_IMPORT.finditer(text):
        spec = m.group(2)
        if not spec.startswith("."):
            continue  # only local modules can be cross-file-analyzed
        for part in m.group(1).split(","):
            part = part.strip()
            if not part or part == "type" or part.startswith("type "):
                continue  # type-only imports aren't runtime functions
            bits = re.split(r"\s+as\s+", part)
            orig, local = bits[0].strip(), bits[-1].strip()
            if re.fullmatch(r"[A-Za-z0-9_$]+", local) and re.fullmatch(r"[A-Za-z0-9_$]+", orig):
                out[local] = (spec, orig)
    return out


def _norm_parts(parts) -> List[str]:
    out: List[str] = []
    for part in parts:
        if part == "..":
            if out:
                out.pop()
        elif part not in (".", ""):
            out.append(part)
    return out


def _resolve_import(importer_rel: str, spec: str, file_rels: Set[str]) -> Optional[str]:
    """Resolve a relative import spec to a file path in the project."""
    base = PurePosixPath(importer_rel).parent / spec
    base = PurePosixPath(*_norm_parts(base.parts))
    s = base.as_posix()
    if s in file_rels:
        return s
    for ext in _CODE_EXT:
        if s + ext in file_rels:
            return s + ext
    for ext in _CODE_EXT:
        cand = (base / ("index" + ext)).as_posix()
        if cand in file_rels:
            return cand
    return None


def _is_same_origin_redirect(args_node) -> bool:
    """True if a redirect target is a constant same-origin path (so not an open redirect):
    redirect("/path"), redirect(`/path?x=...`), or redirect(new URL("/path", base))."""
    if args_node is None:
        return False
    first = _first_arg(args_node)
    if first is None:
        return False
    if first.type in ("string", "template_string"):
        return _starts_with_path(first)
    if first.type == "new_expression":
        ctor = first.child_by_field_name("constructor")
        if ctor is not None and _text(ctor) == "URL":
            inner = first.child_by_field_name("arguments")
            url_first = _first_arg(inner) if inner is not None else None
            if url_first is not None and url_first.type in ("string", "template_string"):
                return _starts_with_path(url_first)
    return False


def _starts_with_path(node) -> bool:
    """A string/template literal whose value is a relative/same-origin path ('/', './', '../')."""
    raw = _text(node).strip()
    inner = raw[1:-1] if len(raw) >= 2 and raw[0] in "\"'`" else raw
    return inner.startswith(("/", "./", "../"))
