# Using NjordScan with an AI coding assistant (via MCP)

Wouldn't it be nice if your AI coding assistant could security-check the code it just wrote —
*before* you ever commit it? That's exactly what this does. NjordScan ships an **MCP server**, so
assistants like Claude Code, Cursor, and Windsurf can run a scan inline and get back the same
warm, plain-English findings and fixes you'd see in your terminal.

**MCP** (the [Model Context Protocol](https://modelcontextprotocol.io)) is just a small, shared
language that lets AI assistants call external tools like NjordScan — no glue code required on your
side.

If you've never run a scan before, start with the [README](../README.md). The full list of every
issue NjordScan can catch lives in [RULES.md](RULES.md).

## Start the server

```bash
njordscan mcp
```

That's it. The command starts NjordScan as an MCP server that talks to your assistant over
**stdio** (standard input/output) — there's no port to open, no network to configure, and nothing
leaves your machine. You normally won't run this by hand; your assistant launches it for you once
you register it (below). It keeps running and waits for requests, so press `Ctrl+C` if you ever
start it manually and want to stop it.

## Register it with Claude Code

One command wires NjordScan into Claude Code:

```bash
claude mcp add njordscan -- njordscan mcp
```

Everything after the `--` is the command Claude Code will run to start the server. After this,
Claude Code can scan your project whenever you ask.

## Register it with any other MCP client

Most assistants (Cursor, Windsurf, and others) accept a small JSON config. Add this to your
client's MCP settings file:

```json
{
  "mcpServers": {
    "njordscan": {
      "command": "njordscan",
      "args": ["mcp"]
    }
  }
}
```

`command` is the program to run and `args` are the words that follow it — together they're just
`njordscan mcp`. If `njordscan` isn't found, use the full path to the executable (you can find it
with `which njordscan`).

## The three tools your assistant gets

Once registered, your assistant can call these on its own. You don't type them — you just ask in
plain English, and the assistant picks the right one.

| Tool | What it does |
|------|--------------|
| `njordscan_scan` | Scans a project directory for security issues — leaked secrets, XSS, vulnerable dependencies, supply-chain risks, AI-app risks, and misconfigurations. Returns each finding with a plain-English *why* and a concrete *fix*. This is the one the assistant reaches for after writing or editing code. It takes a `path` (which directory to scan), and optionally `min_severity` (hide findings below `info`/`low`/`medium`/`high`/`critical`) and `only` (limit to specific detectors, e.g. `["secrets","taint"]`). |
| `njordscan_explain` | Explains a single rule in depth — why it matters, how to fix it, and a secure code example. Takes a `rule_id` like `xss.inner-html`. Great when the assistant (or you) wants the full story behind a finding. |
| `njordscan_list_rules` | Lists every rule NjordScan can detect (id, severity, and title). No arguments needed. Handy for the assistant to see the full catalog. |

These mirror the CLI: `njordscan_scan` is `njordscan scan`, `njordscan_explain` is
`njordscan explain <rule-id>`, and `njordscan_list_rules` is `njordscan explain` with no argument.

## Example: scan and fix, hands-free

Once NjordScan is registered, just tell your assistant what you want in normal words. For example:

> **Scan this project with njordscan and fix the criticals.**

Your assistant will call `njordscan_scan` on your project, read the findings, and walk through the
critical ones — using the suggested fixes (and, if it needs more detail, `njordscan_explain`) to
patch your code. A typical scan result it sees looks like this:

```text
NjordScan found 2 issue(s): 0 critical, 2 high, 0 medium, 0 low.

[HIGH] Hard-coded secret or credential — app.js:1  (rule: secret.generic)
    Looks like a OpenAI API key.
    FIX: Move the value to an environment variable, add the env file to .gitignore,
    and ROTATE the exposed secret now (assume it is already compromised).
    SECURE:  const apiKey = process.env.API_KEY; // set in your host's env / .env.local

[HIGH] User input assigned to innerHTML / outerHTML — app.js:2  (rule: xss.inner-html)
    innerHTML assigned a non-literal value; renders as HTML and can execute injected scripts.
    FIX: Use `element.textContent` to insert text safely, or build DOM nodes explicitly.
    SECURE:  element.textContent = userInput; // rendered as text, never executed
```

You can ask for anything in between, too — "explain why that innerHTML one is dangerous," "only
show me secrets and high-severity issues," or "rescan to confirm it's clean."

## Check that the server responds

Want to confirm the server works before handing it to an assistant? You can speak to it directly
by piping two JSON-RPC requests — an `initialize` handshake and a `tools/list` — into it:

```bash
printf '%s\n' \
'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"test","version":"0"}}}' \
'{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
| njordscan mcp
```

You'll see two JSON lines come back. The first confirms the handshake:

```json
{"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "2025-03-26", "capabilities": {"tools": {"listChanged": false}}, "serverInfo": {"name": "njordscan", "version": "2.0.0b1"}}}
```

The second lists the three tools above (`njordscan_scan`, `njordscan_explain`,
`njordscan_list_rules`). If you get both, the server is healthy and ready for your assistant.

To double-check everything else NjordScan can see on your machine — detectors, rule counts, advisory
freshness, and AI availability — run [`njordscan doctor`](../README.md#command-reference).

## Where to go next

- [README](../README.md) — install, your first scan, and every flag.
- [RULES.md](RULES.md) — the complete catalog of what NjordScan detects.
