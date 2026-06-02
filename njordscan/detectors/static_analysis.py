"""Static analysis detector — fast, dependency-free pattern matching.

This detector complements the taint analyzer. Taint analysis can prove that a
value flows from a user-controlled source into a dangerous sink, but it depends
on a working tree-sitter parser and can only see flows it can trace. This
detector is the cheap, always-available safety net: a line-by-line regex/
heuristic pass that catches the *obvious* same-line issues (``el.innerHTML =
req.body.x``, ``eval(code)``, ``res.redirect(req.query.next)``) even when the
parser is unavailable or the flow is too dynamic to trace.

Because regex cannot *prove* taint, findings are emitted at "medium" confidence
(or "low" for the weakest heuristics). The orchestrator de-duplicates by
``(rule_id, file, line, snippet)``, so overlap with the taint detector is
harmless — whichever produces the higher-confidence finding wins.

Precision is the priority: we only flag a sink when its argument / right-hand
side is *not* a plain string literal (a literal is, by definition, attacker-
free). We skip comment lines and very long / minified lines, and we ignore
known-safe constructs (React text interpolation ``{name}``, server-only
``process.env`` reads).
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from ..core.finding import Finding
from ..core.project import Project
from .base import Detector
from .urlheuristics import fetch_host_is_dynamic

# Lines longer than this are almost certainly minified/bundled or data blobs;
# they explode regex cost and are not human-written source worth flagging.
_MAX_LINE = 400


# --------------------------------------------------------------------------- #
# Helpers for deciding whether an expression is a "safe" string literal vs a   #
# variable / dynamic expression that could carry attacker-controlled data.     #
# --------------------------------------------------------------------------- #

# A quoted string with NO interpolation. Single, double, or a backtick template
# that contains no ${...} substitution. These are constants — never tainted.
_PLAIN_SINGLE = re.compile(r"""^\s*'(?:[^'\\]|\\.)*'\s*$""")
_PLAIN_DOUBLE = re.compile(r'''^\s*"(?:[^"\\]|\\.)*"\s*$''')
_PLAIN_TEMPLATE_NO_SUBST = re.compile(r"""^\s*`(?:[^`\\$]|\\.|\$(?!\{))*`\s*$""")
# A ${...} substitution whose contents are themselves a literal (string/number/
# boolean) — interpolating a constant keeps the whole template constant.
_TEMPLATE_LITERAL_SUBST = re.compile(
    r"""\$\{\s*(?:'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"|-?\d[\d_.eE]*|true|false|null|undefined)\s*\}"""
)

# Tokens that, when present in an expression, strongly suggest the value is
# request-derived (used to *raise* confidence, never as the sole trigger).
_REQUEST_HINT = re.compile(
    r"""\b(
        req(?:uest)?\.(?:query|body|params|cookies|headers|url)
      | request\.(?:nextUrl|url|headers|cookies)
      | searchParams
      | ctx\.query
      | location\.(?:href|search|hash|pathname)
      | window\.location
      | document\.(?:URL|location|cookie|referrer)
      | params\.
      | query\.
      | process\.argv
    )""",
    re.VERBOSE,
)


def _strip_line_comment(line: str) -> str:
    """Return ``line`` with a trailing ``//`` comment removed.

    We avoid stripping a ``//`` that lives inside a string literal by tracking
    quote state. This is a heuristic, not a full lexer — good enough to stop us
    from matching sinks that only appear in comments.
    """
    in_single = in_double = in_back = False
    i = 0
    n = len(line)
    while i < n:
        ch = line[i]
        if in_single:
            if ch == "\\":
                i += 2
                continue
            if ch == "'":
                in_single = False
        elif in_double:
            if ch == "\\":
                i += 2
                continue
            if ch == '"':
                in_double = False
        elif in_back:
            if ch == "\\":
                i += 2
                continue
            if ch == "`":
                in_back = False
        else:
            if ch == "'":
                in_single = True
            elif ch == '"':
                in_double = True
            elif ch == "`":
                in_back = True
            elif ch == "/" and i + 1 < n and line[i + 1] == "/":
                return line[:i]
        i += 1
    return line


def _is_comment_line(stripped: str) -> bool:
    return stripped.startswith("//") or stripped.startswith("*") or stripped.startswith("/*")


def _is_plain_string_literal(expr: str) -> bool:
    """True if ``expr`` is a single quoted/template constant with no interpolation."""
    expr = expr.strip()
    if not expr:
        return False
    if _PLAIN_SINGLE.match(expr) or _PLAIN_DOUBLE.match(expr) or _PLAIN_TEMPLATE_NO_SUBST.match(expr):
        return True
    # A backtick template whose every ${...} substitution is itself a literal is
    # still a constant (e.g. `prefix ${''}`). Remove literal substitutions and
    # re-check for a no-substitution template.
    if expr.startswith("`") and expr.endswith("`"):
        reduced = _TEMPLATE_LITERAL_SUBST.sub("", expr)
        if _PLAIN_TEMPLATE_NO_SUBST.match(reduced):
            return True
    return False


def _matching_paren(text: str, open_idx: int) -> int:
    """Index of the ``)`` matching the ``(`` at ``open_idx`` (quote-aware).

    Returns ``-1`` if no match is found on this single line (multi-line call).
    """
    depth = 0
    in_single = in_double = in_back = False
    i = open_idx
    n = len(text)
    while i < n:
        ch = text[i]
        if in_single:
            if ch == "\\":
                i += 2
                continue
            if ch == "'":
                in_single = False
        elif in_double:
            if ch == "\\":
                i += 2
                continue
            if ch == '"':
                in_double = False
        elif in_back:
            if ch == "\\":
                i += 2
                continue
            if ch == "`":
                in_back = False
        else:
            if ch == "'":
                in_single = True
            elif ch == '"':
                in_double = True
            elif ch == "`":
                in_back = True
            elif ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    return i
        i += 1
    return -1


def _first_arg(args: str) -> str:
    """The first top-level (comma-separated) argument from a call's arg string."""
    depth = 0
    in_single = in_double = in_back = False
    out: List[str] = []
    i = 0
    n = len(args)
    while i < n:
        ch = args[i]
        if in_single:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(args[i + 1])
                i += 2
                continue
            if ch == "'":
                in_single = False
        elif in_double:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(args[i + 1])
                i += 2
                continue
            if ch == '"':
                in_double = False
        elif in_back:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(args[i + 1])
                i += 2
                continue
            if ch == "`":
                in_back = False
        else:
            if ch == "'":
                in_single = True
            elif ch == '"':
                in_double = True
            elif ch == "`":
                in_back = True
            elif ch in "([{":
                depth += 1
            elif ch in ")]}":
                depth -= 1
            elif ch == "," and depth == 0:
                break
            out.append(ch)
        i += 1
    return "".join(out).strip()


def _has_dynamic_concat(expr: str) -> bool:
    """True if ``expr`` looks like a string built with concatenation / a template.

    Used for command-injection: a literal command is fine, but ``'rm ' + name``
    or `` `rm ${name}` `` is the classic injection shape.
    """
    if re.search(r"`(?:[^`\\]|\\.)*\$\{[^}]+\}", expr):
        return True  # template literal with substitution
    # string-literal followed by + ... (concatenation with a non-literal)
    if re.search(r"""['"][^'"]*['"]\s*\+""", expr) or re.search(
        r"""\+\s*['"]""", expr
    ):
        return True
    return False


# --------------------------------------------------------------------------- #
# Pattern definitions                                                          #
# --------------------------------------------------------------------------- #

# JSX: dangerouslySetInnerHTML={{ __html: <expr> }}
_DANGEROUS_HTML = re.compile(
    r"dangerouslySetInnerHTML\s*=\s*\{\{\s*__html\s*:\s*(?P<val>[^}]+?)\s*\}\s*\}"
)

# Assignment sinks: .innerHTML = / .outerHTML =  (capture RHS to end of statement)
_HTML_ASSIGN = re.compile(
    r"(?P<prop>\.(?:inner|outer)HTML)\s*=\s*(?P<val>[^;]+)"
)

# insertAdjacentHTML('pos', <val>) and document.write(<val>)
_INSERT_ADJACENT = re.compile(r"\.insertAdjacentHTML\s*\(")
_DOC_WRITE = re.compile(r"\bdocument\s*\.\s*write(?:ln)?\s*\(")

# eval( and new Function(
_EVAL = re.compile(r"(?<![.\w])eval\s*\(")
_NEW_FUNCTION = re.compile(r"\bnew\s+Function\s*\(")

# child_process exec/execSync/spawn(... ) — capture the call's args.
_CHILD_PROC = re.compile(
    r"\b(?:cp|child_process)?\.?(?P<fn>exec|execSync|spawn|spawnSync|execFile|execFileSync)\s*\("
)

# .redirect( — Express/Next response redirect.
_REDIRECT = re.compile(r"\.redirect\s*\(")
# new URL("/path", base) / new URL(`/path`, base) — a constant same-origin path, not an open redirect.
_SAME_ORIGIN_URL = re.compile(r"""new\s+URL\s*\(\s*['"`](?:\.\.?)?/""")

# Server-side fetch( / axios( / axios.get( etc.
_FETCH = re.compile(r"(?<![.\w])fetch\s*\(")
_AXIOS = re.compile(r"\baxios(?:\s*\.\s*(?:get|post|put|delete|patch|request|head))?\s*\(")


@dataclass(frozen=True)
class _Finding:
    rule_id: str
    column: int
    confidence: str
    message: str


class StaticAnalysisDetector(Detector):
    """Heuristic same-line pattern matching for common web vulnerabilities."""

    id = "static"
    name = "Static pattern analysis"
    kind = "static"

    async def scan(self, project: Project) -> List[Finding]:
        files = list(project.source_files)
        try:
            chunks = await asyncio.gather(
                *(asyncio.to_thread(self._scan_file, project, path) for path in files),
                return_exceptions=True,
            )
        except Exception:  # noqa: BLE001 — never let scanning crash the run
            return []
        findings: List[Finding] = []
        for chunk in chunks:
            if isinstance(chunk, list):
                findings.extend(chunk)
        return findings

    # -- per-file ----------------------------------------------------------- #

    def _scan_file(self, project: Project, path: Path) -> List[Finding]:
        try:
            text = project.read_text(path)
            if not text:
                return []
            rel = project.rel(path)
            is_jsx = path.suffix.lower() in (".jsx", ".tsx", ".js", ".mjs", ".cjs", ".ts")
            findings: List[Finding] = []
            for line_no, raw_line in enumerate(text.splitlines(), start=1):
                if len(raw_line) > _MAX_LINE:
                    continue
                stripped = raw_line.strip()
                if not stripped or _is_comment_line(stripped):
                    continue
                code = _strip_line_comment(raw_line)
                if not code.strip():
                    continue
                for hit in self._scan_line(code, is_jsx):
                    findings.append(Finding(
                        rule_id=hit.rule_id,
                        file=rel,
                        line=line_no,
                        column=hit.column,
                        code_snippet=stripped,
                        detector=self.id,
                        confidence=hit.confidence,
                        message=hit.message,
                    ))
            return findings
        except Exception:  # noqa: BLE001 — one bad file must not sink the scan
            return []

    # -- per-line ----------------------------------------------------------- #

    def _scan_line(self, line: str, is_jsx: bool) -> List[_Finding]:
        out: List[_Finding] = []
        self._check_dangerous_html(line, out)
        self._check_html_assign(line, out)
        self._check_html_calls(line, out)
        self._check_eval(line, out)
        self._check_command(line, out)
        self._check_redirect(line, out)
        self._check_ssrf(line, out)
        return out

    # dangerouslySetInnerHTML={{ __html: <non-literal> }}
    def _check_dangerous_html(self, line: str, out: List[_Finding]) -> None:
        for m in _DANGEROUS_HTML.finditer(line):
            val = m.group("val").strip()
            if _is_plain_string_literal(val):
                continue
            conf = "high" if _REQUEST_HINT.search(val) else "medium"
            out.append(_Finding(
                "xss.dangerously-set-inner-html",
                m.start() + 1,
                conf,
                "dangerouslySetInnerHTML receives a non-literal value; "
                "if any part is user-controlled this is an XSS sink.",
            ))

    # .innerHTML = / .outerHTML = <non-literal>
    def _check_html_assign(self, line: str, out: List[_Finding]) -> None:
        for m in _HTML_ASSIGN.finditer(line):
            val = m.group("val").strip()
            # equality / comparison, not assignment
            if val.startswith("=") or val.startswith("=="):
                continue
            if _is_plain_string_literal(val):
                continue
            # `el.innerHTML = ''` style clears are literals already handled above;
            # also ignore assignment of another *.innerHTML read (rare, low value).
            conf = "high" if _REQUEST_HINT.search(val) else "medium"
            prop = m.group("prop").lstrip(".")
            out.append(_Finding(
                "xss.inner-html",
                m.start() + 1,
                conf,
                f"{prop} assigned a non-literal value; renders as HTML and can "
                "execute injected scripts if user-controlled.",
            ))

    # insertAdjacentHTML(pos, <non-literal>) and document.write(<non-literal>)
    def _check_html_calls(self, line: str, out: List[_Finding]) -> None:
        for m in _INSERT_ADJACENT.finditer(line):
            open_idx = line.index("(", m.start())
            args = self._call_args(line, open_idx)
            if args is None:
                continue
            # second argument carries the HTML
            parts = self._split_args(args)
            html_arg = parts[1] if len(parts) > 1 else (parts[0] if parts else "")
            if not html_arg or _is_plain_string_literal(html_arg):
                continue
            conf = "high" if _REQUEST_HINT.search(html_arg) else "medium"
            out.append(_Finding(
                "xss.inner-html",
                m.start() + 1,
                conf,
                "insertAdjacentHTML receives a non-literal HTML string (XSS sink).",
            ))
        for m in _DOC_WRITE.finditer(line):
            open_idx = line.index("(", m.start())
            arg = self._first_call_arg(line, open_idx)
            if arg is None or _is_plain_string_literal(arg):
                continue
            conf = "high" if _REQUEST_HINT.search(arg) else "low"
            out.append(_Finding(
                "xss.inner-html",
                m.start() + 1,
                conf,
                "document.write receives a non-literal value (XSS sink).",
            ))

    # eval(<non-literal>) / new Function(<non-literal>)
    def _check_eval(self, line: str, out: List[_Finding]) -> None:
        for pat, label in ((_EVAL, "eval"), (_NEW_FUNCTION, "new Function")):
            for m in pat.finditer(line):
                open_idx = line.index("(", m.start())
                arg = self._first_call_arg(line, open_idx)
                # multi-line / unreadable arg -> still flag eval (it is dangerous)
                if arg is not None and _is_plain_string_literal(arg):
                    continue
                conf = "high" if (arg and _REQUEST_HINT.search(arg)) else "medium"
                out.append(_Finding(
                    "injection.eval",
                    m.start() + 1,
                    conf,
                    f"{label} runs its argument as live code; a non-literal "
                    "argument can execute attacker-supplied JavaScript.",
                ))

    # child_process exec/spawn with concatenation or a template variable
    def _check_command(self, line: str, out: List[_Finding]) -> None:
        for m in _CHILD_PROC.finditer(line):
            open_idx = line.index("(", m.start())
            arg = self._first_call_arg(line, open_idx)
            if arg is None:
                continue
            if _is_plain_string_literal(arg):
                continue
            # Only flag when the command string is *built* dynamically — a bare
            # variable could be a constant defined elsewhere, so require the
            # concat/template shape OR a request hint to keep precision high.
            dynamic = _has_dynamic_concat(arg)
            hinted = bool(_REQUEST_HINT.search(arg))
            if not (dynamic or hinted):
                continue
            conf = "high" if hinted else "medium"
            out.append(_Finding(
                "injection.command",
                m.start() + 1,
                conf,
                f"{m.group('fn')} builds a shell command from a dynamic string; "
                "use an args array (execFile/spawn) instead of string interpolation.",
            ))

    # res.redirect(<variable>) — open redirect
    def _check_redirect(self, line: str, out: List[_Finding]) -> None:
        for m in _REDIRECT.finditer(line):
            open_idx = line.index("(", m.start())
            arg = self._first_call_arg(line, open_idx)
            if arg is None:
                continue
            # A status-code first arg (res.redirect(301, url)) — inspect the URL arg.
            parts = self._split_args(self._call_args(line, open_idx) or arg)
            target = parts[-1].strip() if parts else arg
            if not target or _is_plain_string_literal(target):
                continue
            if _SAME_ORIGIN_URL.search(target):   # new URL("/path", base) — same origin, safe
                continue
            # A relative path literal is safe; a bare variable / expression is not.
            conf = "high" if _REQUEST_HINT.search(target) else "low"
            out.append(_Finding(
                "open-redirect",
                m.start() + 1,
                conf,
                "redirect target is a non-literal value; validate it against an "
                "allowlist or restrict to relative paths.",
            ))

    # server-side fetch/axios with a request-derived URL (SSRF)
    def _check_ssrf(self, line: str, out: List[_Finding]) -> None:
        for pat in (_FETCH, _AXIOS):
            for m in pat.finditer(line):
                open_idx = line.index("(", m.start())
                arg = self._first_call_arg(line, open_idx)
                if arg is None or _is_plain_string_literal(arg):
                    continue
                # A relative / fixed-literal-host URL is same-origin: request-derived
                # data in the path or query of `fetch(`/api/...`)` is not SSRF.
                if not fetch_host_is_dynamic(arg):
                    continue
                # High precision: only flag when the URL clearly looks
                # request-derived. A bare internal variable is too noisy.
                if not _REQUEST_HINT.search(arg):
                    continue
                out.append(_Finding(
                    "ssrf.fetch",
                    m.start() + 1,
                    "medium",
                    "server-side request to a user-controlled URL; validate the "
                    "host against an allowlist to prevent SSRF.",
                ))

    # -- call-arg extraction ------------------------------------------------- #

    @staticmethod
    def _call_args(line: str, open_idx: int) -> Optional[str]:
        close_idx = _matching_paren(line, open_idx)
        if close_idx < 0:
            return None
        return line[open_idx + 1:close_idx]

    def _first_call_arg(self, line: str, open_idx: int) -> Optional[str]:
        args = self._call_args(line, open_idx)
        if args is None:
            return None
        return _first_arg(args)

    @staticmethod
    def _split_args(args: str) -> List[str]:
        """Split a call's arg string into top-level comma-separated arguments."""
        parts: List[str] = []
        depth = 0
        in_single = in_double = in_back = False
        cur: List[str] = []
        i = 0
        n = len(args)
        while i < n:
            ch = args[i]
            if in_single:
                cur.append(ch)
                if ch == "\\" and i + 1 < n:
                    cur.append(args[i + 1])
                    i += 2
                    continue
                if ch == "'":
                    in_single = False
            elif in_double:
                cur.append(ch)
                if ch == "\\" and i + 1 < n:
                    cur.append(args[i + 1])
                    i += 2
                    continue
                if ch == '"':
                    in_double = False
            elif in_back:
                cur.append(ch)
                if ch == "\\" and i + 1 < n:
                    cur.append(args[i + 1])
                    i += 2
                    continue
                if ch == "`":
                    in_back = False
            else:
                if ch == "'":
                    in_single = True
                elif ch == '"':
                    in_double = True
                elif ch == "`":
                    in_back = True
                elif ch in "([{":
                    depth += 1
                elif ch in ")]}":
                    depth -= 1
                elif ch == "," and depth == 0:
                    parts.append("".join(cur).strip())
                    cur = []
                    i += 1
                    continue
                cur.append(ch)
            i += 1
        if cur:
            parts.append("".join(cur).strip())
        return parts
