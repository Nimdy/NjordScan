"""Excessive-Agency / Improper-Output-Handling detection for AI apps.

The "Predict" engine pointed at the AI-agent attack surface: when a value the
**LLM controls** reaches a genuinely **dangerous sink**, the model — and anyone who
can steer it via prompt injection — gains that capability. Two source kinds:

  * a ``tool({ execute })`` argument — the model *chooses* this value (Vercel AI SDK,
    LangChain ``tool()``, or any object tool definition);
  * an **LLM output** (``generateText`` / ``streamText`` / ``...completions.create``).

Dangerous sinks are the same curated ones the taint detector already trusts —
``exec``/``spawn`` (command), ``eval``/``Function`` (code), ``fs.write*`` (arbitrary
files), ``$queryRawUnsafe`` (raw SQL), plus ``fetch`` to a **dynamic host** (SSRF).
Crucially the sink is dangerous *regardless of surrounding context*, so there is no
"authorized elsewhere" ambiguity — every finding is a concrete source→sink path.

Maps to OWASP LLM Top-10: **LLM06 Excessive Agency** and **LLM05 Improper Output
Handling**. Design constraints match the taint detector: ``scan`` never raises, parsing
is offloaded, only stdlib + tree-sitter, only rule_ids that exist in the knowledge base.
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

try:
    import tree_sitter as ts
    import tree_sitter_javascript as tsjs
    import tree_sitter_typescript as tsts

    _TREE_SITTER_OK = True
except Exception as exc:  # noqa: BLE001 — optional dependency, degrade gracefully
    logger.debug("tree-sitter unavailable, ai_agency detector will yield nothing: %s", exc)
    _TREE_SITTER_OK = False


# --------------------------------------------------------------------------- #
#  Dangerous sinks + their rule_ids / severity-by-confidence
# --------------------------------------------------------------------------- #

_CMD_BARE = {"exec", "execSync", "spawn", "spawnSync", "execFile", "execFileSync", "fork"}
_EVAL_BARE = {"eval", "Function"}
_CMD_PROP = {"exec", "execSync", "spawn", "spawnSync", "execFile", "execFileSync"}
_FS_WRITE = {"writeFile", "writeFileSync", "appendFile", "appendFileSync", "unlink",
             "unlinkSync", "rm", "rmSync", "rmdir", "mkdir", "createWriteStream", "outputFile"}
_FS_RECV = {"fs", "fsp", "fse", "fsExtra", "promises"}
_SQL_RAW = {"$queryRawUnsafe", "$executeRawUnsafe"}
_SSRF_PROP = {"get", "request", "post", "put", "patch", "delete"}
_SSRF_RECV = {"axios", "http", "https", "got", "fetch", "superagent", "ky", "request"}

# sink class -> (rule_id when source is a tool arg, default confidence)
_TOOL_RULE: Dict[str, str] = {
    "command-exec": "ai.excessive-agency-command",
    "code-eval": "ai.excessive-agency-code",
    "fs-write": "ai.excessive-agency-filesystem",
    "sql-raw": "ai.excessive-agency-sql",
    "ssrf-fetch": "ai.tool-ssrf",
}
# A bare LLM output reaching any of these is "improper output handling".
_OUTPUT_RULE = "ai.improper-output-handling"
# sandbox libraries: model code-exec is real but lower priority (confirm sandbox config).
_SANDBOX_HINTS = ("isolated-vm", "isolated_vm", "ivm.", "vm2", "NodeVM", "@e2b", "e2b/",
                  "Sandbox.create", "lockdown(", "new Compartment", "quickjs", "ses/")

_LLM_CALLS = {"generateText", "streamText", "generateObject", "streamObject",
              "createCompletion", "createChatCompletion"}
_CODE_EXT = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx")


def _is_code(path: Path) -> bool:
    return path.suffix.lower() in _CODE_EXT


# --------------------------------------------------------------------------- #
#  AST helpers (module-level, no parser state)
# --------------------------------------------------------------------------- #


def _text(n) -> str:
    try:
        return n.text.decode("utf-8") if (n is not None and n.text is not None) else ""
    except Exception:  # noqa: BLE001
        return ""


def _line_text(text: str, line: int) -> str:
    lines = text.splitlines()
    return lines[line - 1].strip() if 1 <= line <= len(lines) else ""


def _flatten_member(node) -> List[str]:
    if node is None:
        return []
    if node.type == "identifier":
        return [_text(node)]
    if node.type in ("member_expression", "subscript_expression"):
        obj = node.child_by_field_name("object")
        prop = node.child_by_field_name("property") or node.child_by_field_name("index")
        parts = _flatten_member(obj)
        if prop is not None and prop.type in ("property_identifier", "identifier"):
            parts.append(_text(prop))
        return parts
    return []


def _walk(node):
    stack = [node]
    while stack:
        n = stack.pop()
        yield n
        stack.extend(n.children)


def _arg_list(args_node) -> List:
    return [c for c in args_node.children if c.type not in (",", "(", ")")] if args_node else []


def _obj_pat_names(pat) -> List[str]:
    names: List[str] = []
    for c in pat.children:
        if c.type == "shorthand_property_identifier_pattern":
            names.append(_text(c))
        elif c.type == "pair_pattern":
            v = c.child_by_field_name("value")
            if v is not None and v.type == "identifier":
                names.append(_text(v))
    return names


def _param_names(fn) -> List[str]:
    out: List[str] = []
    pn = fn.child_by_field_name("parameters")
    cand = list(pn.children) if pn is not None else []
    single = fn.child_by_field_name("parameter")
    if single is not None:
        cand.append(single)
    for p in cand:
        if p.type in ("(", ")", ","):
            continue  # punctuation children of the parameter list are not params
        if p.type == "identifier":
            out.append(_text(p))
        elif p.type in ("required_parameter", "optional_parameter"):
            pat = p.child_by_field_name("pattern") or p.child_by_field_name("name")
            if pat is not None and pat.type == "identifier":
                out.append(_text(pat))
            elif pat is not None and pat.type == "object_pattern":
                out.extend(_obj_pat_names(pat))
            else:
                out.append("")
        elif p.type == "object_pattern":
            out.extend(_obj_pat_names(p))
        else:
            out.append("")
    return out


def _host_dynamic(arg) -> bool:
    """A fetch to a FIXED literal host is not SSRF (only the path/query is model-fed)."""
    raw = _text(arg).strip()
    if arg.type in ("string", "template_string"):
        inner = raw[1:-1] if len(raw) >= 2 and raw[0] in "\"'`" else raw
        for scheme in ("http://", "https://"):
            if inner.startswith(scheme):
                rest = inner[len(scheme):]
                return rest[:1] in ("$", "{", "")
        if inner.startswith(("/", "./", "../")):
            return False
    return True


def _expr_tainted(node, tainted: Set[str]) -> bool:
    if node is None:
        return False
    t = node.type
    if t == "await_expression" and node.children:
        return _expr_tainted(node.children[-1], tainted)
    if t in ("identifier", "shorthand_property_identifier"):
        return _text(node) in tainted
    if t in ("member_expression", "subscript_expression"):
        parts = _flatten_member(node)
        return bool(parts) and parts[0] in tainted
    if t in ("template_string", "binary_expression", "template_substitution",
             "parenthesized_expression", "call_expression", "object", "array", "pair",
             "ternary_expression", "spread_element", "arguments", "new_expression"):
        return any(_expr_tainted(c, tainted) for c in node.children)
    return False


def _sink_of(call, tainted: Set[str]) -> Optional[Tuple[str, str]]:
    """Return (sink_class, label) if a TAINTED value reaches a dangerous sink, else None."""
    fn = call.child_by_field_name("function") or call.child_by_field_name("constructor")
    al = _arg_list(call.child_by_field_name("arguments"))
    if fn is None:
        return None
    if fn.type == "identifier":
        name = _text(fn)
        if name in _EVAL_BARE and al and _expr_tainted(al[0], tainted):
            return ("code-eval", f"{name}(...)")
        if name in _CMD_BARE and al and _expr_tainted(al[0], tainted):
            return ("command-exec", f"{name}(...)")
        if name == "fetch" and al and _expr_tainted(al[0], tainted) and _host_dynamic(al[0]):
            return ("ssrf-fetch", "fetch(...)")
    elif fn.type == "member_expression":
        parts = _flatten_member(fn)
        prop = parts[-1] if parts else ""
        recv = parts[0] if parts else ""
        if prop in _CMD_PROP and any(_expr_tainted(a, tainted) for a in al):
            return ("command-exec", f"{recv}.{prop}(...)")
        if prop in _FS_WRITE and (recv in _FS_RECV or "fs" in parts) and any(_expr_tainted(a, tainted) for a in al):
            return ("fs-write", f"{recv}.{prop}(...)")
        if prop in _SQL_RAW and any(_expr_tainted(a, tainted) for a in al):
            return ("sql-raw", f"{recv}.{prop}(...)")
        if prop in _SSRF_PROP and recv in _SSRF_RECV and al and _expr_tainted(al[0], tainted) and _host_dynamic(al[0]):
            return ("ssrf-fetch", f"{recv}.{prop}(...)")
    return None


def _iter_named_functions(root):
    for n in _walk(root):
        if n.type == "function_declaration":
            nm = n.child_by_field_name("name")
            if nm is not None:
                yield n, _text(nm)
        elif n.type == "variable_declarator":
            nm = n.child_by_field_name("name")
            val = n.child_by_field_name("value")
            if (nm is not None and nm.type == "identifier" and val is not None
                    and val.type in ("arrow_function", "function", "function_expression")):
                yield val, _text(nm)
        elif n.type == "method_definition":
            nm = n.child_by_field_name("name")
            if nm is not None:
                yield n, _text(nm)


def _taint_body(body, seed: Set[str], summaries: Optional[Dict] = None) -> List[Tuple[str, str, int]]:
    """Propagate taint from ``seed`` through ``body``; return (sink_class, label, line) hits."""
    tainted = set(seed)
    for _ in range(3):  # tiny fixpoint for chained assignments
        for n in _walk(body):
            if n.type == "variable_declarator":
                name = n.child_by_field_name("name")
                val = n.child_by_field_name("value")
                if name is not None and val is not None and name.type == "identifier" and _expr_tainted(val, tainted):
                    tainted.add(_text(name))
    hits: List[Tuple[str, str, int]] = []
    for n in _walk(body):
        if n.type not in ("call_expression", "new_expression"):
            continue
        hit = _sink_of(n, tainted)
        if hit is not None:
            hits.append((hit[0], hit[1], n.start_point.row + 1))
        elif summaries:
            fn = n.child_by_field_name("function")
            nm = ""
            if fn is not None and fn.type == "identifier":
                nm = _text(fn)
            elif fn is not None and fn.type == "member_expression":
                p = _flatten_member(fn)
                nm = p[-1] if p else ""
            spec = summaries.get(nm)
            if spec:
                for idx, a in enumerate(_arg_list(n.child_by_field_name("arguments"))):
                    if idx in spec and _expr_tainted(a, tainted):
                        sc, label = spec[idx]
                        hits.append((sc, f"{nm}() → {label}", n.start_point.row + 1))
                        break
    return hits


def _collect_fn_summaries(root) -> Dict[str, Dict[int, Tuple[str, str]]]:
    """{fn_name: {param_index: (sink_class, label)}} — a param that reaches a dangerous sink."""
    summaries: Dict[str, Dict[int, Tuple[str, str]]] = {}
    for fn, name in _iter_named_functions(root):
        body = fn.child_by_field_name("body")
        params = _param_names(fn)
        if body is None or not params:
            continue
        for idx, p in enumerate(params):
            if not p:
                continue
            hits = _taint_body(body, {p})
            if hits:
                summaries.setdefault(name, {})[idx] = (hits[0][0], hits[0][1])
    return summaries


def _find_tool_executes(root):
    """Yield execute-function nodes for tool({execute}) / object tool defs / LangChain tool()."""
    for n in _walk(root):
        if n.type == "object":
            keys = {}
            for c in n.children:
                if c.type == "pair":
                    k = c.child_by_field_name("key")
                    v = c.child_by_field_name("value")
                    if k is not None:
                        keys[_text(k)] = v
            ex = keys.get("execute") or keys.get("func") or keys.get("handler")
            if ex is not None and ex.type in ("arrow_function", "function", "function_expression") \
                    and any(k in keys for k in ("parameters", "inputSchema", "description", "schema", "name")):
                yield ex
        elif n.type == "call_expression":
            fn = n.child_by_field_name("function")
            if fn is not None and fn.type == "identifier" and _text(fn) == "tool":
                a = _arg_list(n.child_by_field_name("arguments"))
                if a and a[0].type in ("arrow_function", "function", "function_expression"):
                    yield a[0]


def _find_llm_output_vars(scope) -> Set[str]:
    """idents bound to an LLM call's result within a block scope."""
    out: Set[str] = set()
    for d in _walk(scope):
        if d.type != "variable_declarator":
            continue
        name = d.child_by_field_name("name")
        val = d.child_by_field_name("value")
        if val is None:
            continue
        v = val.children[-1] if (val.type == "await_expression" and val.children) else val
        if v.type != "call_expression":
            continue
        f = v.child_by_field_name("function")
        nm = ""
        if f is not None and f.type == "identifier":
            nm = _text(f)
        elif f is not None and f.type == "member_expression":
            parts = _flatten_member(f)
            nm = parts[-1] if parts else ""
            if nm == "create" and not any(x in parts for x in ("completions", "messages", "chat", "responses")):
                nm = ""
        if nm in _LLM_CALLS or nm == "create":
            if name is not None and name.type == "identifier":
                out.add(_text(name))
            elif name is not None and name.type == "object_pattern":
                out.update(_obj_pat_names(name))
    return out


# --------------------------------------------------------------------------- #
#  Cross-file: import resolution + cheap content gates
# --------------------------------------------------------------------------- #

_SINK_HINTS = ("exec", "spawn", "fork", "eval", "Function", "writeFile", "appendFile",
               "unlink", "rmSync", "rmdir", "mkdir", "$queryRawUnsafe", "$executeRawUnsafe",
               "fetch", "axios", "http.get", "https.get", "got", "ky", "outputFile")
_AI_HINTS = ("execute", "tool(", "generateText", "streamText", "generateObject",
             "streamObject", ".create(", "func:", "handler:")


def _has_sink(text: str) -> bool:
    return any(h in text for h in _SINK_HINTS)


def _has_ai(text: str) -> bool:
    return any(h in text for h in _AI_HINTS)


_NAMED_IMPORT = re.compile(r"""import\s*\{([^}]*)\}\s*from\s*['"]([^'"]+)['"]""")
_CODE_EXTS = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs")


def _named_imports(text: str) -> Dict[str, Tuple[str, str]]:
    """{local_name: (module_spec, original_export)} for local (relative) imports only."""
    out: Dict[str, Tuple[str, str]] = {}
    for m in _NAMED_IMPORT.finditer(text):
        spec = m.group(2)
        if not spec.startswith("."):
            continue
        for part in m.group(1).split(","):
            part = part.strip()
            if not part or part.startswith("type "):
                continue
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
    base = PurePosixPath(importer_rel).parent / spec
    base = PurePosixPath(*_norm_parts(base.parts))
    s = base.as_posix()
    if s in file_rels:
        return s
    for ext in _CODE_EXTS:
        if s + ext in file_rels:
            return s + ext
    for ext in _CODE_EXTS:
        cand = (base / ("index" + ext)).as_posix()
        if cand in file_rels:
            return cand
    return None


# --------------------------------------------------------------------------- #
#  Multi-hop chain: untrusted content → model prompt → dangerous tool → sink
# --------------------------------------------------------------------------- #

_ACTION = {
    "command-exec": "run shell commands",
    "code-eval": "execute arbitrary code",
    "fs-write": "read/write/delete files",
    "sql-raw": "run raw SQL",
    "ssrf-fetch": "make the server fetch arbitrary URLs",
}

# Sources of untrusted EXTERNAL content that, if fed into a prompt, enable indirect
# prompt injection: a fetched page, a file, a RAG retrieval, a request, a tool result.
_UNTRUSTED_CALLS = {"fetch", "readFile", "readFileSync", "similaritySearch",
                    "getRelevantDocuments", "maxMarginalRelevanceSearch", "retrieve",
                    "scrape", "crawl", "load", "loadDocuments"}
_UNTRUSTED_PROPS = {"json", "text"}            # response.json() / response.text()
_REQ_ROOTS = {"req", "request"}
_REQ_PROPS = {"body", "query", "params", "nextUrl", "json", "formData"}
_REQ_BARE = {"searchParams", "params", "body", "formData"}
_LLM_PROMPT_KEYS = ("prompt", "system", "input")
_TOOLS_KEYS = ("tools", "toolset", "experimental_activeTools")


def _is_untrusted_expr(node) -> bool:
    if node is None:
        return False
    t = node.type
    if t == "await_expression" and node.children:
        return _is_untrusted_expr(node.children[-1])
    if t in ("member_expression", "subscript_expression"):
        parts = _flatten_member(node)
        if not parts:
            return False
        if parts[0] in _REQ_BARE:
            return True
        return any(parts[i] in _REQ_ROOTS and parts[i + 1] in _REQ_PROPS for i in range(len(parts) - 1))
    if t == "call_expression":
        f = node.child_by_field_name("function")
        nm = ""
        if f is not None and f.type == "identifier":
            nm = _text(f)
        elif f is not None and f.type == "member_expression":
            p = _flatten_member(f)
            nm = p[-1] if p else ""
        return nm in _UNTRUSTED_CALLS or nm in _UNTRUSTED_PROPS
    return False


def _collect_untrusted(scope) -> Set[str]:
    u: Set[str] = set()
    for _ in range(3):
        for n in _walk(scope):
            if n.type != "variable_declarator":
                continue
            name = n.child_by_field_name("name")
            val = n.child_by_field_name("value")
            if name is None or val is None:
                continue
            if _is_untrusted_expr(val) or _expr_tainted(val, u):
                if name.type == "identifier":
                    u.add(_text(name))
                elif name.type == "object_pattern":
                    u.update(_obj_pat_names(name))
    return u


def _obj_field(obj, *keys):
    if obj is None or obj.type != "object":
        return None
    for c in obj.children:
        if c.type == "pair":
            k = c.child_by_field_name("key")
            if k is not None and _text(k) in keys:
                return c.child_by_field_name("value")
        elif c.type == "shorthand_property_identifier" and _text(c) in keys:
            return c
    return None


def _execute_of_tool_value(val):
    """The execute/func node of a `tool({...})` call or `tool(fn, ...)` or tool object."""
    obj = None
    if val.type == "call_expression":
        f = val.child_by_field_name("function")
        if f is not None and f.type == "identifier" and _text(f) == "tool":
            args = _arg_list(val.child_by_field_name("arguments"))
            if args and args[0].type in ("arrow_function", "function", "function_expression"):
                return args[0]
            obj = next((a for a in args if a.type == "object"), None)
    elif val.type == "object":
        obj = val
    if obj is not None:
        for c in obj.children:
            if c.type == "pair":
                k = c.child_by_field_name("key")
                v = c.child_by_field_name("value")
                if (k is not None and _text(k) in ("execute", "func", "handler")
                        and v is not None and v.type in ("arrow_function", "function", "function_expression")):
                    return v
    return None


def _dangerous_tool_names(root, summaries) -> Dict[str, str]:
    """{tool_variable_name: sink_class} for tools whose execute reaches a dangerous sink."""
    names: Dict[str, str] = {}
    for n in _walk(root):
        if n.type != "variable_declarator":
            continue
        nm = n.child_by_field_name("name")
        val = n.child_by_field_name("value")
        if nm is None or nm.type != "identifier" or val is None:
            continue
        ex = _execute_of_tool_value(val)
        if ex is None:
            continue
        body = ex.child_by_field_name("body")
        if body is None:
            continue
        hits = _taint_body(body, set(_param_names(ex)), summaries)
        if hits:
            names[_text(nm)] = hits[0][0]
    return names


def _iter_llm_calls(root):
    for n in _walk(root):
        if n.type != "call_expression":
            continue
        f = n.child_by_field_name("function")
        nm = ""
        if f is not None and f.type == "identifier":
            nm = _text(f)
        elif f is not None and f.type == "member_expression":
            p = _flatten_member(f)
            nm = p[-1] if p else ""
        if nm in _LLM_CALLS or nm == "create":
            obj = next((a for a in _arg_list(n.child_by_field_name("arguments")) if a.type == "object"), None)
            if obj is not None:
                yield n, obj


def _tools_field_dangerous(arg_obj, names: Dict[str, str]):
    tv = _obj_field(arg_obj, *_TOOLS_KEYS)
    if tv is None:
        return None
    candidates: List[str] = []
    if tv.type == "object":
        for c in tv.children:
            if c.type == "shorthand_property_identifier":
                candidates.append(_text(c))
            elif c.type == "pair":
                k = c.child_by_field_name("key")
                v = c.child_by_field_name("value")
                if k is not None:
                    candidates.append(_text(k))
                if v is not None and v.type == "identifier":
                    candidates.append(_text(v))
    elif tv.type == "identifier":
        candidates.append(_text(tv))
    for nm in candidates:
        if nm in names:
            return nm, names[nm]
    return None


def _prompt_untrusted(arg_obj, untrusted: Set[str]) -> bool:
    for key in _LLM_PROMPT_KEYS:
        v = _obj_field(arg_obj, key)
        if v is not None and (_is_untrusted_expr(v) or _expr_tainted(v, untrusted)):
            return True
    mv = _obj_field(arg_obj, "messages")
    if mv is not None:
        for n in _walk(mv):
            if _is_untrusted_expr(n):
                return True
            if n.type == "identifier" and _text(n) in untrusted:
                return True
    return False


# --------------------------------------------------------------------------- #
#  Detector
# --------------------------------------------------------------------------- #


class AIAgencyDetector(Detector):
    """Model-controlled value (tool arg / LLM output) reaching a dangerous sink."""

    id = "ai_agency"
    name = "AI excessive agency (model → dangerous sink)"
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
        return bool(self._languages)

    async def scan(self, project: Project) -> List[Finding]:
        if not self._languages:
            return []
        files = [p for p in project.source_files if _is_code(p)]
        file_rels = {project.rel(p) for p in files}

        # Phase A: parse + summarise every relevant file (which functions forward a
        # parameter into a dangerous sink). Helper-only files are summarised too, so a
        # tool calling an imported dangerous helper in another module is still caught.
        prep = await asyncio.gather(
            *(asyncio.to_thread(self._parse_summarize, project, path) for path in files),
            return_exceptions=True,
        )
        parsed: Dict[str, Tuple[object, str]] = {}
        summaries_by_file: Dict[str, Dict[str, Dict[int, Tuple[str, str]]]] = {}
        imports_by_file: Dict[str, Dict[str, Tuple[str, str]]] = {}
        for res in prep:
            if isinstance(res, Exception) or res is None:
                continue
            rel, root, text, summ, imps = res
            parsed[rel] = (root, text)
            summaries_by_file[rel] = summ
            imports_by_file[rel] = imps

        # Phase B: analyse each file, injecting summaries of imported helpers (cross-file).
        def analyze(rel: str) -> List[Finding]:
            root, text = parsed[rel]
            merged = dict(summaries_by_file.get(rel, {}))
            for local, (spec, orig) in imports_by_file.get(rel, {}).items():
                target = _resolve_import(rel, spec, file_rels)
                if target and orig in summaries_by_file.get(target, {}):
                    merged.setdefault(local, summaries_by_file[target][orig])
            try:
                return self._analyze(rel, text, root, merged)
            except Exception as exc:  # noqa: BLE001 — never crash on weird input
                logger.debug("ai_agency: analysis failed on %s: %r", rel, exc)
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

    def _parse_summarize(self, project: Project, path: Path):
        """Parse a file → (rel, root, text, fn_summaries, named_imports), or None."""
        try:
            text = project.read_text(path)
            if not text.strip() or not (_has_ai(text) or _has_sink(text)):
                return None  # neither an AI source nor a possible dangerous helper
            lang = self._languages.get("tsx" if path.suffix.lower() in (".ts", ".tsx") else "js") \
                or self._languages.get("js")
            if lang is None:
                return None
            root = ts.Parser(lang).parse(text.encode("utf-8")).root_node
            rel = project.rel(path)
            return rel, root, text, _collect_fn_summaries(root), _named_imports(text)
        except Exception as exc:  # noqa: BLE001 — never crash on weird input
            logger.debug("ai_agency: parse failed on %s: %r", path, exc)
            return None

    def _analyze(self, rel: str, text: str, root, summaries) -> List[Finding]:
        if not _has_ai(text):
            return []  # only files with a tool/LLM source can produce findings
        sandboxed = any(h in text for h in _SANDBOX_HINTS)
        out: List[Finding] = []
        seen: Set[Tuple[str, int]] = set()

        # 1) tool({execute}) args — the model chooses them
        for ex_fn in _find_tool_executes(root):
            body = ex_fn.child_by_field_name("body")
            if body is None:
                continue
            src_line = ex_fn.start_point.row + 1
            for sink_class, label, line in _taint_body(body, set(_param_names(ex_fn)), summaries):
                out.append(self._make(rel, text, "tool argument", "the model chooses",
                                      sink_class, label, src_line, line, sandboxed, seen))

        # 2) LLM output flowing into a dangerous sink — improper output handling
        for scope in _walk(root):
            if scope.type not in ("statement_block", "program"):
                continue
            llm_vars = _find_llm_output_vars(scope)
            if not llm_vars:
                continue
            for sink_class, label, line in _taint_body(scope, llm_vars, summaries):
                out.append(self._make(rel, text, "LLM output", "the model produces",
                                      sink_class, label, scope.start_point.row + 1, line,
                                      sandboxed, seen, output=True))
            if scope.type == "program":
                break

        # 3) the multi-hop chain — only when a dangerous tool ACTUALLY exists in this
        # file (the precise anchor): an LLM call wired to that tool AND fed untrusted
        # external content is a full indirect-prompt-injection → exploit chain.
        dangerous_names = _dangerous_tool_names(root, summaries)
        if dangerous_names:
            untrusted = _collect_untrusted(root)
            chain_seen: Set[int] = set()
            for call, arg_obj in _iter_llm_calls(root):
                used = _tools_field_dangerous(arg_obj, dangerous_names)
                if used is None or not _prompt_untrusted(arg_obj, untrusted):
                    continue
                line = call.start_point.row + 1
                if line in chain_seen:
                    continue
                chain_seen.add(line)
                out.append(self._make_chain(rel, text, line, used))

        return [f for f in out if f is not None]

    def _make_chain(self, rel, text, line, used) -> Finding:
        tool_name, sink_class = used
        action = _ACTION.get(sink_class, "a dangerous operation")
        message = (
            f"Indirect prompt injection → excessive agency: this model call is fed untrusted "
            f"external content (a fetched page, a RAG document, a file, or request input) AND is "
            f"wired to the `{tool_name}` tool, which can {action}. Attacker-controlled content can "
            f"steer the model into triggering it — a full inject-the-content → run-the-exploit chain."
        )
        flow = [
            TaintStep(label="untrusted external content reaches the model's prompt", file=rel,
                      line=line, kind="source", code=_line_text(text, line)),
            TaintStep(label=f"model can call `{tool_name}` → {action}", file=rel, line=line,
                      kind="sink", code=_line_text(text, line)),
        ]
        return Finding(
            rule_id="ai.prompt-injection-to-agency", file=rel, line=line, column=1,
            code_snippet=_line_text(text, line), detector=self.id, confidence="high",
            message=message, taint_flow=flow, metadata={},
        )

    def _make(self, rel, text, src_label, src_phrase, sink_class, label, src_line, sink_line,
              sandboxed, seen, output=False) -> Optional[Finding]:
        rule_id = _OUTPUT_RULE if output else _TOOL_RULE.get(sink_class)
        if rule_id is None:
            return None
        key = (rule_id, sink_line)
        if key in seen:
            return None
        seen.add(key)

        confidence = "high"
        note = ""
        if sink_class == "ssrf-fetch":
            confidence = "medium"
        if sandboxed and sink_class in ("command-exec", "code-eval"):
            confidence = "low"
            note = " It looks sandboxed (vm2/isolated-vm/e2b) — confirm the sandbox blocks network/filesystem and resource abuse."

        action = {
            "command-exec": "run shell commands",
            "code-eval": "execute arbitrary code",
            "fs-write": "read/write/delete files",
            "sql-raw": "run raw SQL",
            "ssrf-fetch": "make the server fetch arbitrary URLs",
        }.get(sink_class, "reach a dangerous operation")
        if output:
            message = (f"Unverified LLM output flows into `{label}` — {src_phrase} text that is "
                       f"then used to {action}. A prompt-injected response becomes code execution." + note)
        else:
            message = (f"A value the model controls (this tool's {src_label}) reaches `{label}` — "
                       f"the model (or anyone who can prompt-inject it) can {action}." + note)

        flow = [
            TaintStep(label=f"{src_label} ({src_phrase} this)", file=rel, line=src_line,
                      kind="source", code=_line_text(text, src_line)),
            TaintStep(label=label, file=rel, line=sink_line, kind="sink",
                      code=_line_text(text, sink_line)),
        ]
        return Finding(
            rule_id=rule_id, file=rel, line=sink_line, column=1,
            code_snippet=_line_text(text, sink_line), detector=self.id,
            confidence=confidence, message=message, taint_flow=flow, metadata={},
        )


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
