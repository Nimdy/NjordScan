"""
Tree-sitter based taint tracking for JavaScript/TypeScript.

Parses source files into ASTs, identifies taint sources (user input),
tracks how tainted data flows through assignments and function calls,
and reports when tainted data reaches dangerous sinks.

This is intra-file, intra-function taint tracking — it does not follow
data across module boundaries or through async callbacks.
"""

import logging
from pathlib import Path
from typing import Dict, List, Set, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)

try:
    import tree_sitter as ts
    import tree_sitter_javascript as tsjs
    import tree_sitter_typescript as tsts
    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False

# --------------------------------------------------------------------- #
#  Data structures
# --------------------------------------------------------------------- #

class TaintSeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"


@dataclass
class TaintSource:
    """A location where user-controlled data enters the program."""
    variable: str
    line: int
    column: int
    source_type: str  # e.g. "req.body", "window.location"


@dataclass
class TaintSink:
    """A dangerous function/property that should not receive tainted data."""
    name: str
    line: int
    column: int
    sink_type: str  # e.g. "innerHTML", "eval", "exec"
    severity: TaintSeverity


@dataclass
class TaintFlow:
    """A confirmed flow from a taint source to a taint sink."""
    source: TaintSource
    sink: TaintSink
    path: List[str]  # variable names in the chain
    file_path: str
    confidence: float
    cwe_id: str
    description: str


# --------------------------------------------------------------------- #
#  Source and sink definitions
# --------------------------------------------------------------------- #

# Member-expression patterns that introduce tainted data
TAINT_SOURCES = {
    # Express / Node.js request
    ("req", "body"): "req.body",
    ("req", "query"): "req.query",
    ("req", "params"): "req.params",
    ("req", "headers"): "req.headers",
    ("req", "cookies"): "req.cookies",
    ("request", "body"): "request.body",
    ("request", "query"): "request.query",
    ("request", "params"): "request.params",
    # Next.js
    ("router", "query"): "router.query",
    ("searchParams", "get"): "searchParams.get",
    # Browser
    ("window", "location"): "window.location",
    ("document", "location"): "document.location",
    ("document", "URL"): "document.URL",
    ("document", "referrer"): "document.referrer",
    ("location", "search"): "location.search",
    ("location", "hash"): "location.hash",
    ("location", "href"): "location.href",
    # DOM
    ("document", "cookie"): "document.cookie",
}

# Functions whose return value is tainted
TAINT_RETURN_FUNCTIONS = {
    "prompt",
    "decodeURIComponent",
    "decodeURI",
    "atob",
}

# Sinks: (object_or_none, property_or_function) -> (sink_type, severity, cwe)
TAINT_SINKS: Dict[Tuple[Optional[str], str], Tuple[str, TaintSeverity, str]] = {
    # XSS sinks
    (None, "innerHTML"): ("innerHTML", TaintSeverity.HIGH, "CWE-79"),
    (None, "outerHTML"): ("outerHTML", TaintSeverity.HIGH, "CWE-79"),
    ("document", "write"): ("document.write", TaintSeverity.HIGH, "CWE-79"),
    ("document", "writeln"): ("document.writeln", TaintSeverity.HIGH, "CWE-79"),
    # Code execution sinks
    (None, "eval"): ("eval", TaintSeverity.CRITICAL, "CWE-95"),
    (None, "Function"): ("Function constructor", TaintSeverity.CRITICAL, "CWE-95"),
    (None, "setTimeout"): ("setTimeout with string", TaintSeverity.HIGH, "CWE-95"),
    (None, "setInterval"): ("setInterval with string", TaintSeverity.HIGH, "CWE-95"),
    # Command injection sinks
    (None, "exec"): ("exec", TaintSeverity.CRITICAL, "CWE-78"),
    (None, "execSync"): ("execSync", TaintSeverity.CRITICAL, "CWE-78"),
    (None, "spawn"): ("spawn", TaintSeverity.HIGH, "CWE-78"),
    (None, "spawnSync"): ("spawnSync", TaintSeverity.HIGH, "CWE-78"),
    # SQL injection sinks
    (None, "query"): ("SQL query", TaintSeverity.CRITICAL, "CWE-89"),
    (None, "execute"): ("SQL execute", TaintSeverity.HIGH, "CWE-89"),
    # Path traversal sinks
    (None, "readFile"): ("readFile", TaintSeverity.HIGH, "CWE-22"),
    (None, "readFileSync"): ("readFileSync", TaintSeverity.HIGH, "CWE-22"),
    (None, "writeFile"): ("writeFile", TaintSeverity.HIGH, "CWE-22"),
    (None, "writeFileSync"): ("writeFileSync", TaintSeverity.HIGH, "CWE-22"),
    (None, "createReadStream"): ("createReadStream", TaintSeverity.HIGH, "CWE-22"),
    # Open redirect
    (None, "redirect"): ("redirect", TaintSeverity.MEDIUM, "CWE-601"),
    ("res", "redirect"): ("res.redirect", TaintSeverity.MEDIUM, "CWE-601"),
    ("window", "open"): ("window.open", TaintSeverity.MEDIUM, "CWE-601"),
    # React-specific
    (None, "dangerouslySetInnerHTML"): ("dangerouslySetInnerHTML", TaintSeverity.HIGH, "CWE-79"),
}


# --------------------------------------------------------------------- #
#  Tree-sitter taint tracker
# --------------------------------------------------------------------- #

class TaintTracker:
    """Intra-file taint tracker using tree-sitter ASTs."""

    def __init__(self):
        if not TREE_SITTER_AVAILABLE:
            raise ImportError(
                "tree-sitter, tree-sitter-javascript, and tree-sitter-typescript "
                "are required for taint tracking. Install with: "
                "pip install tree-sitter tree-sitter-javascript tree-sitter-typescript"
            )
        self._js_lang = ts.Language(tsjs.language())
        self._tsx_lang = ts.Language(tsts.language_tsx())

    def _parser_for_file(self, path: Path) -> ts.Parser:
        suffix = path.suffix.lower()
        if suffix in ('.ts', '.tsx'):
            return ts.Parser(self._tsx_lang)
        return ts.Parser(self._js_lang)

    def analyze_file(self, file_path: Path, content: str) -> List[TaintFlow]:
        """Analyze a single file for taint flows."""
        try:
            parser = self._parser_for_file(file_path)
            tree = parser.parse(content.encode('utf-8'))
            return self._analyze_tree(tree.root_node, content, str(file_path))
        except Exception as e:
            logger.debug(f"Taint analysis failed for {file_path}: {e}")
            return []

    # ----------------------------------------------------------------- #
    #  AST walking
    # ----------------------------------------------------------------- #

    def _analyze_tree(self, root, content: str, file_path: str) -> List[TaintFlow]:
        """Walk the AST in two passes:

        Pass 1 — collect function signatures that propagate a parameter
                 to a dangerous sink (e.g. function render(html) { el.innerHTML = html; })
        Pass 2 — normal taint tracking plus cross-function detection:
                 if tainted data is passed to a sink-propagating function, flag it.
        """
        lines = content.split('\n')

        # Pass 1: build map of func_name -> set of param indices that reach sinks
        self._func_sinks: Dict[str, Dict[int, Tuple[str, TaintSeverity, str]]] = {}
        self._collect_function_sinks(root)

        # Pass 2: walk with taint state
        tainted: Dict[str, TaintSource] = {}
        flows: List[TaintFlow] = []
        self._walk(root, tainted, flows, file_path, lines)
        return flows

    # ----------------------------------------------------------------- #
    #  Pass 1 — collect functions whose params reach sinks
    # ----------------------------------------------------------------- #

    def _collect_function_sinks(self, node):
        """Find function declarations/expressions where a parameter flows
        directly to a known sink within the function body."""
        func_types = ('function_declaration', 'function',
                      'arrow_function', 'method_definition')
        if node.type in func_types:
            self._analyze_function_for_sink(node)

        for child in node.children:
            self._collect_function_sinks(child)

    def _analyze_function_for_sink(self, func_node):
        """Check if any parameter of this function reaches a sink."""
        # Get function name
        name_node = func_node.child_by_field_name('name')
        if not name_node:
            # arrow functions assigned to variables are handled elsewhere
            return
        func_name = self._node_text(name_node)

        # Get parameter names
        params_node = func_node.child_by_field_name('parameters')
        if not params_node:
            return
        param_names = [self._node_text(p) for p in params_node.children
                       if p.type == 'identifier' or p.type == 'required_parameter']
        # For TS required_parameter, extract the name child
        clean_params = []
        for p in params_node.children:
            if p.type == 'identifier':
                clean_params.append(self._node_text(p))
            elif p.type in ('required_parameter', 'optional_parameter'):
                pn = p.child_by_field_name('pattern') or p.child_by_field_name('name')
                if pn:
                    clean_params.append(self._node_text(pn))
        param_names = clean_params

        if not param_names:
            return

        # Get function body
        body = func_node.child_by_field_name('body')
        if not body:
            return

        # Simulate taint for each param and see if any reach a sink
        for idx, param in enumerate(param_names):
            tainted = {param: TaintSource(
                variable=param, line=0, column=0,
                source_type=f"parameter:{param}"
            )}
            flows: List[TaintFlow] = []
            self._walk(body, tainted, flows, "", [])
            if flows:
                sink_info = (flows[0].sink.sink_type,
                             flows[0].sink.severity,
                             flows[0].cwe_id)
                self._func_sinks.setdefault(func_name, {})[idx] = sink_info

    # ----------------------------------------------------------------- #
    #  Pass 2 — main walk
    # ----------------------------------------------------------------- #

    def _walk(self, node, tainted: Dict[str, TaintSource],
              flows: List[TaintFlow], file_path: str, lines: List[str]):
        """Recursively walk AST nodes."""

        # Variable declaration:  const x = <expr>
        if node.type == 'variable_declarator':
            self._handle_variable_declarator(node, tainted, flows, file_path, lines)

        # Assignment:  x = <expr>
        elif node.type == 'assignment_expression':
            self._handle_assignment(node, tainted, flows, file_path, lines)

        # Function call — check both built-in sinks and user-defined sink functions
        elif node.type == 'call_expression':
            self._check_call_sink(node, tainted, flows, file_path, lines)
            self._check_cross_function_sink(node, tainted, flows, file_path)

        # Recurse
        for child in node.children:
            self._walk(child, tainted, flows, file_path, lines)

    def _check_cross_function_sink(self, node, tainted, flows, file_path):
        """If calling a function whose param reaches a sink, and the arg is tainted, flag it."""
        fn_node = node.child_by_field_name('function')
        args_node = node.child_by_field_name('arguments')
        if not fn_node or not args_node:
            return

        fn_name = self._node_text(fn_node) if fn_node.type == 'identifier' else None
        if not fn_name or fn_name not in self._func_sinks:
            return

        # Check each argument
        arg_nodes = [a for a in args_node.children if a.type not in (',', '(', ')')]
        for idx, arg in enumerate(arg_nodes):
            if idx not in self._func_sinks[fn_name]:
                continue
            arg_vars = self._extract_identifiers(arg)
            for av in arg_vars:
                if av in tainted:
                    sink_type, severity, cwe = self._func_sinks[fn_name][idx]
                    flows.append(self._make_flow(
                        tainted[av],
                        f"{fn_name}() -> {sink_type}",
                        severity, cwe, node, file_path,
                        [tainted[av].variable, av, fn_name, sink_type]
                    ))
                    return

    def _handle_variable_declarator(self, node, tainted, flows, file_path, lines):
        """Handle: const x = <expr>"""
        name_node = node.child_by_field_name('name')
        value_node = node.child_by_field_name('value')
        if not name_node or not value_node:
            return

        var_name = self._node_text(name_node)

        # Check if RHS is a taint source
        source = self._extract_taint_source(value_node)
        if source:
            source.variable = var_name
            tainted[var_name] = source
            return

        # Check if RHS is a tainted variable (propagation)
        rhs_vars = self._extract_identifiers(value_node)
        for rv in rhs_vars:
            if rv in tainted:
                tainted[var_name] = TaintSource(
                    variable=var_name,
                    line=name_node.start_point.row + 1,
                    column=name_node.start_point.column,
                    source_type=tainted[rv].source_type
                )
                break

        # Also check for tainted call return:  const x = prompt()
        if value_node.type == 'call_expression':
            fn = value_node.child_by_field_name('function')
            if fn and self._node_text(fn) in TAINT_RETURN_FUNCTIONS:
                tainted[var_name] = TaintSource(
                    variable=var_name,
                    line=name_node.start_point.row + 1,
                    column=name_node.start_point.column,
                    source_type=self._node_text(fn) + "()"
                )

    def _handle_assignment(self, node, tainted, flows, file_path, lines):
        """Handle: x = <expr>  or  el.innerHTML = <expr>"""
        left = node.child_by_field_name('left')
        right = node.child_by_field_name('right')
        if not left or not right:
            return

        # Check if this is a sink assignment: el.innerHTML = taintedVar
        if left.type == 'member_expression':
            prop_node = left.child_by_field_name('property')
            obj_node = left.child_by_field_name('object')
            if prop_node:
                prop = self._node_text(prop_node)
                obj = self._node_text(obj_node) if obj_node else None

                # Check sinks
                for (sink_obj, sink_prop), (sink_type, severity, cwe) in TAINT_SINKS.items():
                    if prop == sink_prop and (sink_obj is None or obj == sink_obj):
                        rhs_vars = self._extract_identifiers(right)
                        for rv in rhs_vars:
                            if rv in tainted:
                                flows.append(self._make_flow(
                                    tainted[rv], sink_type, severity, cwe,
                                    node, file_path, [tainted[rv].variable, rv, prop]
                                ))
                                return

        # Simple variable assignment: x = <expr>
        if left.type == 'identifier':
            var_name = self._node_text(left)
            source = self._extract_taint_source(right)
            if source:
                source.variable = var_name
                tainted[var_name] = source
                return
            rhs_vars = self._extract_identifiers(right)
            for rv in rhs_vars:
                if rv in tainted:
                    tainted[var_name] = TaintSource(
                        variable=var_name,
                        line=left.start_point.row + 1,
                        column=left.start_point.column,
                        source_type=tainted[rv].source_type
                    )
                    break

    def _check_call_sink(self, node, tainted, flows, file_path, lines):
        """Check if a function call passes tainted data to a sink."""
        fn_node = node.child_by_field_name('function')
        args_node = node.child_by_field_name('arguments')
        if not fn_node or not args_node:
            return

        fn_text = self._node_text(fn_node)

        # Direct call: eval(x), exec(x)
        if fn_node.type == 'identifier':
            key = (None, fn_text)
            if key in TAINT_SINKS:
                self._check_args_tainted(
                    args_node, tainted, flows, file_path, node,
                    TAINT_SINKS[key]
                )

        # Member call: res.redirect(x), document.write(x)
        elif fn_node.type == 'member_expression':
            obj_node = fn_node.child_by_field_name('object')
            prop_node = fn_node.child_by_field_name('property')
            if obj_node and prop_node:
                obj = self._node_text(obj_node)
                prop = self._node_text(prop_node)
                for (sink_obj, sink_prop), sink_info in TAINT_SINKS.items():
                    if prop == sink_prop and (sink_obj is None or obj == sink_obj):
                        self._check_args_tainted(
                            args_node, tainted, flows, file_path, node, sink_info
                        )
                        break

    def _check_args_tainted(self, args_node, tainted, flows, file_path, call_node, sink_info):
        """Check if any argument to a call is tainted."""
        sink_type, severity, cwe = sink_info
        for arg in args_node.children:
            if arg.type in (',', '(', ')'):
                continue
            arg_vars = self._extract_identifiers(arg)
            for av in arg_vars:
                if av in tainted:
                    flows.append(self._make_flow(
                        tainted[av], sink_type, severity, cwe,
                        call_node, file_path,
                        [tainted[av].variable, av, sink_type]
                    ))
                    return

    # ----------------------------------------------------------------- #
    #  Helpers
    # ----------------------------------------------------------------- #

    def _extract_taint_source(self, node) -> Optional[TaintSource]:
        """Check if an expression node is a taint source."""
        if node.type == 'member_expression':
            parts = self._flatten_member_expr(node)
            if len(parts) >= 2:
                key = (parts[0], parts[1])
                if key in TAINT_SOURCES:
                    return TaintSource(
                        variable="",
                        line=node.start_point.row + 1,
                        column=node.start_point.column,
                        source_type=TAINT_SOURCES[key]
                    )
            # Also check deeper: req.body.username
            for i in range(len(parts) - 1):
                key = (parts[i], parts[i + 1])
                if key in TAINT_SOURCES:
                    return TaintSource(
                        variable="",
                        line=node.start_point.row + 1,
                        column=node.start_point.column,
                        source_type=TAINT_SOURCES[key]
                    )
        # Check for tainted function return: prompt(), decodeURIComponent()
        if node.type == 'call_expression':
            fn = node.child_by_field_name('function')
            if fn and self._node_text(fn) in TAINT_RETURN_FUNCTIONS:
                return TaintSource(
                    variable="",
                    line=node.start_point.row + 1,
                    column=node.start_point.column,
                    source_type=self._node_text(fn) + "()"
                )
        return None

    def _flatten_member_expr(self, node) -> List[str]:
        """Flatten a.b.c into ['a', 'b', 'c']."""
        if node.type == 'member_expression':
            obj = node.child_by_field_name('object')
            prop = node.child_by_field_name('property')
            parts = self._flatten_member_expr(obj) if obj else []
            if prop:
                parts.append(self._node_text(prop))
            return parts
        elif node.type == 'identifier':
            return [self._node_text(node)]
        return [self._node_text(node)]

    def _extract_identifiers(self, node) -> Set[str]:
        """Extract all identifier names from an expression subtree."""
        ids: Set[str] = set()
        if node.type == 'identifier':
            ids.add(self._node_text(node))
        for child in node.children:
            ids.update(self._extract_identifiers(child))
        return ids

    def _node_text(self, node) -> str:
        return node.text.decode('utf-8') if node.text else ''

    def _make_flow(self, source: TaintSource, sink_type: str,
                   severity: TaintSeverity, cwe: str,
                   sink_node, file_path: str, path: List[str]) -> TaintFlow:
        sink = TaintSink(
            name=sink_type,
            line=sink_node.start_point.row + 1,
            column=sink_node.start_point.column,
            sink_type=sink_type,
            severity=severity
        )
        return TaintFlow(
            source=source,
            sink=sink,
            path=path,
            file_path=file_path,
            confidence=0.85,
            cwe_id=cwe,
            description=(
                f"Tainted data from {source.source_type} (line {source.line}) "
                f"flows to {sink_type} (line {sink.line})"
            )
        )
