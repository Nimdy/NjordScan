# 🧾 NjordScan Reporter Plugin Template

Welcome to the official **Reporter Plugin Template** for NjordScan — the extensible way to output security scan results in any format your workflow requires.

---

## 📁 Directory Structure

```
reporter_template/
├── config.yaml           # Plugin configuration schema and defaults
├── __init__.py           # Reporter plugin bootstrap
├── template_reporter.py  # Core logic (rename this)
└── README.md             # This file
```

---

## 🚀 Quick Start

### 1. Create Your Reporter

```bash
cp -r plugins/templates/reporter_template plugins/community/my_reporter
cd plugins/community/my_reporter
```

Then customize:

- Update `config.yaml` with your metadata and options
- Rename `template_reporter.py` to `my_reporter.py`
- Change the class name to `MyReporter`
- Update `__init__.py` to import the new class

---

## 🧠 Core Implementation

### Required Methods

- `generate_report(results: Dict, output_path: str) -> bool`  
  Your main output logic.

- `get_format_name() -> str`  
  CLI name used with `--report` (e.g., `"slack"`).

- `get_file_extension() -> str`  
  Default extension (e.g., `.json`, `.csv`, `.pdf`).

---

## ✨ Examples of Custom Formats

### 🧵 Slack Notifications

```python
def _generate_slack_format(self, results):
    import requests
    message = {
        "text": f"NjordScan Security Report",
        "attachments": [
            {
                "color": "danger",
                "fields": [
                    {"title": "Target", "value": results['target'], "short": True},
                    {"title": "Total Issues", "value": str(results['summary']['total_issues']), "short": True}
                ]
            }
        ]
    }
    requests.post(self._get_config_value('webhook_url'), json=message)
```

### 📄 PDF Summary

```python
def _generate_pdf_format(self, results):
    from reportlab.pdfgen import canvas
    c = canvas.Canvas(output_path)
    c.drawString(100, 750, "NjordScan Security Report")
    for i, (module, vulns) in enumerate(results['vulnerabilities'].items()):
        c.drawString(100, 730 - i * 20, f"{module}: {len(vulns)} issues")
    c.save()
```

### 📧 Email Report

```python
def _generate_email_format(self, results):
    import smtplib
    from email.mime.text import MIMEText
    html = self._format_as_html(results)
    msg = MIMEText(html, "html")
    msg['Subject'] = "NjordScan Report"
    msg['From'] = self._get_config_value("from_email")
    msg['To'] = self._get_config_value("to_email")
    smtp = smtplib.SMTP(self._get_config_value("smtp_server"))
    smtp.send_message(msg)
    smtp.quit()
```

---

## 🛠️ Configuration Options

In `config.yaml`:

```yaml
configuration:
  webhook_url:
    type: string
    description: "Slack webhook for alerts"
  smtp_server:
    type: string
    description: "SMTP server for sending reports"
  to_email:
    type: string
    description: "Recipient address"
```

Access in code:

```python
smtp = self._get_config_value("smtp_server")
```

---

## 🔍 Input Data Structure

`results` contains:

```python
{
  "target": "https://myapp.com",
  "framework": "nextjs",
  "scan_mode": "full",
  "scan_duration": 12.34,
  "modules_run": ["configs", "headers"],
  "vulnerabilities": {
    "headers": [ {...}, {...} ]
  },
  "njord_score": {
    "score": 85,
    "grade": "B+",
    "recommendation": "..."
  },
  "summary": {
    "total_issues": 12,
    "severity_breakdown": {
      "critical": 1, "high": 3, "medium": 4, "low": 3, "info": 1
    }
  }
}
```

---

## 🧪 Testing Your Reporter

### Plugin Validation

```bash
njordscan plugins validate ./plugins/community/my_reporter
```

### Output Testing

```bash
njordscan --target ./test_project --report my_format --output report.myext
```

Test in different scenarios:

```bash
# With multiple modules
njordscan --target ./app --report my_format

# With custom configuration
njordscan --config custom_config.yml --report my_format
```

---

## 📚 Advanced Examples

### 🧬 Multi-Format Reporter

```python
class MultiReporter(ReporterPlugin):
    def get_format_name(self): return "multi"
    async def generate_report(self, results, output_path):
        self._save_json(results, output_path.replace(".multi", ".json"))
        self._save_pdf(results, output_path.replace(".multi", ".pdf"))
        return True
```

### 🌐 API Integration Reporter

```python
class APIReporter(ReporterPlugin):
    async def generate_report(self, results, output_path):
        import aiohttp
        async with aiohttp.ClientSession() as session:
            await session.post(self._get_config_value("api_url"), json=results)
        return True
```

---

## 📦 Distribution Tips

- Test thoroughly across formats and scan types
- Include documentation and config guidance
- Share via the NjordScan plugin registry

---

Let your reports speak your security language — whether it's Slack, CSV, HTML, PDF, or raw JSON. Build the output you need with the power NjordScan provides.