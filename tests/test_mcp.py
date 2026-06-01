"""MCP server JSON-RPC dispatch."""

from __future__ import annotations

from njordscan import mcp_server as M

from conftest import VULN_APP


def test_initialize_advertises_server():
    r = M._handle({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    assert r["result"]["serverInfo"]["name"] == "njordscan"
    assert "tools" in r["result"]["capabilities"]


def test_notifications_get_no_response():
    assert M._handle({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None


def test_tools_list_has_scan_and_explain():
    r = M._handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    names = {t["name"] for t in r["result"]["tools"]}
    assert {"njordscan_scan", "njordscan_explain", "njordscan_list_rules"} <= names
    for t in r["result"]["tools"]:
        assert "inputSchema" in t and t["inputSchema"]["type"] == "object"


def test_scan_tool_returns_findings_text():
    r = M._handle({
        "jsonrpc": "2.0", "id": 3, "method": "tools/call",
        "params": {"name": "njordscan_scan", "arguments": {"path": str(VULN_APP), "min_severity": "high"}},
    })
    text = r["result"]["content"][0]["text"]
    assert "NjordScan found" in text
    assert "FIX:" in text          # the educational payload reaches the assistant
    assert r["result"]["isError"] is False


def test_explain_tool():
    r = M._handle({
        "jsonrpc": "2.0", "id": 4, "method": "tools/call",
        "params": {"name": "njordscan_explain", "arguments": {"rule_id": "xss.inner-html"}},
    })
    text = r["result"]["content"][0]["text"]
    assert "WHY THIS MATTERS" in text and "HOW TO FIX" in text


def test_unknown_method_errors():
    r = M._handle({"jsonrpc": "2.0", "id": 5, "method": "bogus/method"})
    assert r["error"]["code"] == -32601
