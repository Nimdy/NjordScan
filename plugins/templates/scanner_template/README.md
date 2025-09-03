# 🛠️ NjordScan Scanner Plugin Template

Welcome to the official **Scanner Plugin Template** for NjordScan — your starting point for building custom security scanning logic with ease, power, and extensibility.

## 📁 File Structure

```
scanner_template/
├── config.yaml           # Plugin metadata & default config values
├── __init__.py           # Plugin registration and setup
├── template_scanner.py   # Your plugin implementation (rename this)
└── README.md             # You're reading it!
```

---

## ⚡ Quick Start

### 1. Clone and Rename

```bash
cp -r plugins/templates/scanner_template plugins/community/my_scanner
cd plugins/community/my_scanner
```

Then:

- Edit `config.yaml` with your plugin’s name, description, version.
- Rename `template_scanner.py` → `my_scanner.py`
- Update `__init__.py` to import your new class.
- Rename class `TemplateScanner` → `MyScanner`.

---

### 2. Implement Your Logic

In your `scan()` method:

- Traverse files
- Identify patterns
- Use `create_vulnerability()` to report findings

Example:

```python
vulnerabilities.append(self.create_vulnerability(
    title="Sensitive Token Found",
    description="API key detected in public source file",
    severity="high",
    vuln_type="api_key_leak",
    file_path=str(file_path),
    line_number=42,
    code_snippet="API_KEY=sk-***",
    fix="Move secrets to environment variables"
))
```

---

## 🧪 Testing Your Plugin

### Validate Plugin

```bash
njordscan plugins validate ./plugins/community/my_scanner
```

### Run a Scan

```bash
njordscan --target ./test_project --modules my_scanner --verbose
```

### Try Framework-Specific Tests

```bash
njordscan --target ./nextjs_app --framework nextjs --modules my_scanner
```

You can also test in combination with existing modules:

```bash
njordscan --target ./my_app --mode full --modules configs,my_scanner
```

---

## 🔍 Core Plugin API

### `scan(target: str) -> List[Vulnerability]`
Your main scanning method.

### `should_run(mode: str) -> bool`
Indicate when your plugin is applicable:
- `static`: file-based only
- `dynamic`: runtime testing only
- `full`: both

### Utility Methods

- `get_file_content(path)` — Safely read file contents
- `find_files_by_pattern(directory, ["*.js", "*.ts"])`
- `_get_config_value(key, default)` — Pull from `config.yaml`

---

## 🎯 Common Use Cases

### Pattern Matching Example

```python
patterns = [
    {
        "pattern": r"eval\(",
        "title": "Use of eval() Detected",
        "severity": "high",
        "description": "Use of eval is discouraged for security reasons."
    }
]
```

### Framework Specific Functions

- `_scan_nextjs_specific()`
- `_scan_react_specific()`
- `_scan_vite_specific()`

Use them to focus on framework-contextual logic.

---

## ✅ Best Practices

- Skip large/unnecessary files like `node_modules`
- Mask or redact secrets in reports
- Avoid executing or importing scanned code
- Document each vulnerability and fix

---

## 📦 Distributing Your Plugin

Once complete:

- Add usage examples and a clear README
- Push to `plugins/community/`
- Submit a pull request to NjordScan to get it included in the official distribution!

---

Start scanning smarter. Build with purpose. Contribute to secure-by-design JavaScript ecosystems — one plugin at a time.