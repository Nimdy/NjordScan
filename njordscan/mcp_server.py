"""A minimal Model Context Protocol (MCP) server over stdio.

This is what lets an AI coding assistant (Claude Code, Cursor, Windsurf, …) run
NjordScan *while you build* — it can scan the file/project it just wrote and get
back plain-English findings + fixes, the same ones you'd see in the terminal.

It speaks JSON-RPC 2.0 over stdio with newline-delimited messages (the MCP stdio
transport), implemented with the standard library only — no extra dependency.

Register it with your assistant, e.g. Claude Code:
    claude mcp add njordscan -- njordscan mcp
or in an MCP client config:
    { "mcpServers": { "njordscan": { "command": "njordscan", "args": ["mcp"] } } }
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import __version__
from .core.config import Config
from .core.orchestrator import Orchestrator
from .core.severity import Severity
from .knowledge import all_rules, get_rule

PROTOCOL_VERSION = "2025-03-26"

_TOOLS: List[Dict[str, Any]] = [
    {
        "name": "njordscan_scan",
        "description": (
            "Scan a Next.js/React/Vite project directory for security issues "
            "(secrets, XSS, taint, vulnerable dependencies, supply-chain, AI-app risks, "
            "misconfig). Returns findings with a plain-English why + fix for each. "
            "Call this after writing or editing code."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Directory to scan (absolute or relative)."},
                "min_severity": {
                    "type": "string", "enum": [s.value for s in Severity],
                    "description": "Hide findings below this severity (default: low).",
                },
                "only": {
                    "type": "array", "items": {"type": "string"},
                    "description": "Optional detector ids to run (e.g. ['secrets','taint']).",
                },
            },
            "required": ["path"],
        },
    },
    {
        "name": "njordscan_explain",
        "description": "Explain a NjordScan rule in depth: why it matters, how to fix it, and a secure example.",
        "inputSchema": {
            "type": "object",
            "properties": {"rule_id": {"type": "string", "description": "e.g. xss.dangerously-set-inner-html"}},
            "required": ["rule_id"],
        },
    },
    {
        "name": "njordscan_list_rules",
        "description": "List every rule NjordScan can detect (id, severity, title).",
        "inputSchema": {"type": "object", "properties": {}},
    },
]


def run() -> None:
    """Blocking stdio loop. Reads one JSON-RPC message per line, writes responses."""
    out = sys.stdout
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        response = _handle(msg)
        if response is not None:  # notifications get no response
            out.write(json.dumps(response) + "\n")
            out.flush()


def _handle(msg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    method = msg.get("method")
    msg_id = msg.get("id")
    is_notification = "id" not in msg

    if method == "initialize":
        return _ok(msg_id, {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "njordscan", "version": __version__},
        })
    if method in ("notifications/initialized", "notifications/cancelled"):
        return None
    if method == "ping":
        return _ok(msg_id, {})
    if method == "tools/list":
        return _ok(msg_id, {"tools": _TOOLS})
    if method == "tools/call":
        if is_notification:
            return None
        return _call_tool(msg_id, msg.get("params") or {})
    if is_notification:
        return None
    return _err(msg_id, -32601, f"Method not found: {method}")


def _call_tool(msg_id: Any, params: Dict[str, Any]) -> Dict[str, Any]:
    name = params.get("name")
    args = params.get("arguments") or {}
    try:
        if name == "njordscan_scan":
            text = _tool_scan(args)
        elif name == "njordscan_explain":
            text = _tool_explain(args)
        elif name == "njordscan_list_rules":
            text = _tool_list_rules()
        else:
            return _ok(msg_id, _content(f"Unknown tool: {name}", is_error=True))
        return _ok(msg_id, _content(text))
    except Exception as exc:  # noqa: BLE001 — report tool errors as content, don't kill the server
        return _ok(msg_id, _content(f"njordscan error: {exc!r}", is_error=True))


def _tool_scan(args: Dict[str, Any]) -> str:
    path = Path(args.get("path", ".")).expanduser()
    if not path.exists():
        return f"Path does not exist: {path}"
    if not path.is_dir():
        path = path.parent
    min_sev = Severity.from_str(args.get("min_severity", "low"))
    config = Config(target=path, min_severity=min_sev, only_detectors=args.get("only") or None)
    result = asyncio.run(Orchestrator(config).run())

    if not result.findings:
        return f"✅ NjordScan: no security issues found in {path} ({result.files_scanned} files)."

    c = result.counts
    lines = [
        f"NjordScan found {result.total} issue(s) in {path}: "
        f"{c[Severity.CRITICAL]} critical, {c[Severity.HIGH]} high, {c[Severity.MEDIUM]} medium, "
        f"{c[Severity.LOW]} low.\n",
    ]

    # Lead with the attack paths — the highest-leverage thing for an assistant to act on:
    # fixing the ★ step of a path collapses several findings at once.
    if result.attack_paths:
        lines.append(f"🎯 {len(result.attack_paths)} ATTACK PATH(S) — how these issues chain into a breach:")
        for p in result.attack_paths[:5]:
            lines.append(f"\n  {p.id} [score {p.score}/{p.band.value}] {p.title}")
            lines.append(f"    Impact: {p.impact}")
            for s in p.steps:
                star = "★ " if s.breakpoint else "  "
                lines.append(f"    {star}{s.order}. [{s.tactic}] {s.title} — {s.location}")
            if p.advice:
                lines.append(f"    → {p.advice}")
        lines.append("")

    for f in result.findings[:40]:
        sev = f.effective_severity.value.upper()
        lines.append(f"[{sev}] {f.title} — {f.location}  (rule: {f.rule_id})")
        if f.message:
            lines.append(f"    {f.message}")
        if f.fix:
            lines.append(f"    FIX: {f.fix}")
        if f.secure_example:
            ex = f.secure_example.replace("\n", "\n         ")
            lines.append(f"    SECURE:  {ex}")
        lines.append("")
    if result.total > 40:
        lines.append(f"... and {result.total - 40} more.")
    return "\n".join(lines)


def _tool_explain(args: Dict[str, Any]) -> str:
    rule = get_rule(args.get("rule_id", ""))
    if rule is None:
        return f"Unknown rule: {args.get('rule_id')!r}. Use njordscan_list_rules to see all."
    parts = [
        f"{rule.title}  [{rule.id}]  severity={rule.severity.value}",
        f"CWE: {rule.cwe or 'n/a'}   OWASP: {rule.owasp or 'n/a'}\n",
        f"WHY THIS MATTERS:\n{rule.why}\n",
        f"HOW TO FIX IT:\n{rule.fix}",
    ]
    if rule.secure_example:
        parts.append(f"\nSECURE EXAMPLE:\n{rule.secure_example}")
    if rule.references:
        parts.append("\nReferences:\n" + "\n".join(f"- {u}" for u in rule.references))
    return "\n".join(parts)


def _tool_list_rules() -> str:
    rows = sorted(all_rules(), key=lambda r: (-r.severity.rank, r.id))
    return f"{len(rows)} rules:\n" + "\n".join(
        f"  {r.severity.value:8} {r.id:42} {r.title}" for r in rows
    )


def _content(text: str, is_error: bool = False) -> Dict[str, Any]:
    return {"content": [{"type": "text", "text": text}], "isError": is_error}


def _ok(msg_id: Any, result: Dict[str, Any]) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": msg_id, "result": result}


def _err(msg_id: Any, code: int, message: str) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}
