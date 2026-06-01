"""Self-contained HTML report — pretty, shareable, no external assets.

Everything (CSS) is inlined so the file works offline and can be attached to a PR
or emailed. All scanned content is HTML-escaped to avoid the report itself
becoming an injection vector.
"""

from __future__ import annotations

from html import escape
from typing import List

from .. import __version__
from ..core.finding import Finding
from ..core.orchestrator import ScanResult
from ..core.severity import Severity

_SEV_COLOR = {
    Severity.CRITICAL: "#dc2626",
    Severity.HIGH: "#ea580c",
    Severity.MEDIUM: "#ca8a04",
    Severity.LOW: "#0891b2",
    Severity.INFO: "#6b7280",
}


def render_html(result: ScanResult) -> str:
    counts = result.counts
    chips = "".join(
        f'<span class="chip" style="background:{_SEV_COLOR[s]}">{counts[s]} {s.value}</span>'
        for s in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO)
        if counts[s]
    ) or '<span class="chip ok">No issues found</span>'

    findings_html = "\n".join(_finding_html(i, f) for i, f in enumerate(result.findings, 1))
    if not result.findings:
        findings_html = '<p class="allclear">✅ No security issues found in this scan.</p>'

    return _TEMPLATE.format(
        version=escape(__version__),
        target=escape(str(result.project.root)),
        framework=escape(result.project.framework),
        files=result.files_scanned,
        duration=f"{result.duration_s:.2f}",
        total=result.total,
        chips=chips,
        findings=findings_html,
    )


def _finding_html(idx: int, f: Finding) -> str:
    sev = f.effective_severity
    color = _SEV_COLOR[sev]
    tags = " · ".join(escape(t) for t in [f.cwe or "", f.owasp or "", f"confidence: {f.confidence}"] if t)
    flow = ""
    if f.taint_flow:
        steps = "".join(
            f'<li><b>{escape(s.kind)}</b>: <code>{escape(s.label)}</code> '
            f'<span class="muted">({escape(s.file)}:{s.line})</span></li>'
            for s in f.taint_flow
        )
        flow = f'<div class="block"><h4>Data flow</h4><ol class="flow">{steps}</ol></div>'
    refs = "".join(f'<li><a href="{escape(u)}" rel="noopener noreferrer" target="_blank">{escape(u)}</a></li>'
                   for u in f.references[:4])
    ai = ""
    if f.ai_explanation:
        ai = f'<div class="block ai"><h4>🤖 AI review</h4><p>{escape(f.ai_explanation)}</p></div>'
    return f"""
    <details class="finding" style="border-left-color:{color}">
      <summary>
        <span class="sev" style="background:{color}">{escape(sev.value.upper())}</span>
        <span class="ftitle">{escape(f.title)}</span>
        <span class="floc">{escape(f.location)}</span>
      </summary>
      <div class="body">
        <p class="tags">{tags}</p>
        {f'<p class="msg">{escape(f.message)}</p>' if f.message else ''}
        {f'<div class="block"><h4>Found here</h4><pre><code>{escape(f.code_snippet)}</code></pre></div>' if f.code_snippet else ''}
        {flow}
        <div class="block"><h4>💡 Why this matters</h4><p>{escape(f.why)}</p></div>
        <div class="block"><h4>🛠 How to fix it</h4><p>{escape(f.fix)}</p>
          {f'<pre class="fix"><code>{escape(f.secure_example)}</code></pre>' if f.secure_example else ''}
        </div>
        {ai}
        {f'<div class="block"><h4>📚 Learn more</h4><ul>{refs}</ul></div>' if refs else ''}
      </div>
    </details>"""


_TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NjordScan report</title>
<style>
  :root {{ color-scheme: light dark; }}
  * {{ box-sizing: border-box; }}
  body {{ font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
         margin: 0; background: #0b1020; color: #e5e7eb; line-height: 1.55; }}
  .wrap {{ max-width: 920px; margin: 0 auto; padding: 32px 20px 64px; }}
  header h1 {{ margin: 0; font-size: 26px; }} header .sub {{ color: #94a3b8; margin-top: 4px; }}
  .meta {{ color: #94a3b8; font-size: 14px; margin: 6px 0 18px; }}
  .chips {{ display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 28px; }}
  .chip {{ color: #fff; padding: 4px 12px; border-radius: 999px; font-size: 13px; font-weight: 600; }}
  .chip.ok {{ background: #16a34a; }}
  .allclear {{ background: #052e16; border: 1px solid #16a34a; padding: 20px; border-radius: 12px; }}
  .finding {{ background: #111827; border: 1px solid #1f2937; border-left: 4px solid #888;
             border-radius: 10px; margin: 10px 0; overflow: hidden; }}
  summary {{ cursor: pointer; padding: 14px 16px; display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }}
  summary::-webkit-details-marker {{ display:none; }}
  .sev {{ color: #fff; font-size: 11px; font-weight: 700; padding: 2px 8px; border-radius: 6px; letter-spacing: .03em; }}
  .ftitle {{ font-weight: 600; }} .floc {{ color: #94a3b8; font-size: 13px; margin-left: auto; font-family: ui-monospace, monospace; }}
  .body {{ padding: 4px 18px 18px; border-top: 1px solid #1f2937; }}
  .tags {{ color: #94a3b8; font-size: 12px; font-style: italic; }}
  .block {{ margin: 14px 0; }} .block h4 {{ margin: 0 0 6px; font-size: 13px; text-transform: uppercase; letter-spacing: .04em; color: #cbd5e1; }}
  pre {{ background: #0b1020; border: 1px solid #1f2937; border-radius: 8px; padding: 12px; overflow:auto; margin: 6px 0; }}
  pre.fix {{ border-color: #166534; }} code {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 13px; }}
  .flow {{ margin: 0; padding-left: 20px; }} .muted {{ color: #64748b; }}
  .ai {{ background: #1e1b4b; border: 1px solid #4338ca; border-radius: 8px; padding: 4px 14px; }}
  a {{ color: #60a5fa; }} ul {{ margin: 6px 0; padding-left: 20px; }}
  footer {{ color: #64748b; font-size: 12px; margin-top: 32px; text-align: center; }}
</style></head>
<body><div class="wrap">
  <header>
    <h1>🛡 NjordScan report</h1>
    <div class="sub">Security scan — explained in plain English</div>
  </header>
  <div class="meta">{target} · {framework} · {files} files · {duration}s · {total} issue(s)</div>
  <div class="chips">{chips}</div>
  {findings}
  <footer>Generated by NjordScan v{version}. No scanner catches everything — review anything that handles user input.</footer>
</div></body></html>
"""
