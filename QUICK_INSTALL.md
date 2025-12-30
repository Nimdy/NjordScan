# ⚡ Quick Install Guide

**Complete beginner? Just copy and paste these commands:**

## 1️⃣ One-Time Setup (First Time Only)

```bash
# Navigate to NjordScan folder
cd /path/to/NjordScan

# Create virtual environment
python3 -m venv venv

# Activate it
source venv/bin/activate  # Linux/Mac
# OR
venv\Scripts\activate     # Windows

# Install NjordScan
pip install --upgrade pip
pip install -e .

# Update vulnerability database (important!)
python -m njordscan update
```

**This downloads the latest CVE and exploit data.** Takes 1-2 minutes.

---

## 2️⃣ Every Time You Use NjordScan

```bash
# Activate virtual environment
source venv/bin/activate  # Linux/Mac
# OR
venv\Scripts\activate     # Windows

# You'll see (venv) appear in your terminal
```

---

## 3️⃣ Run Your First Scan

```bash
# Accept legal terms (one-time)
python -m njordscan legal --accept

# Test it works
python -m njordscan version

# Scan current directory
python -m njordscan scan

# Scan a specific project
python -m njordscan scan /path/to/your/project

# Interactive mode (easiest for beginners)
python -m njordscan --interactive
```

---

## ✅ Success Indicators

**Installation worked if you see:**
- `(venv)` at the start of your terminal prompt
- No errors when running `python -m njordscan version`
- A beautiful table showing version 1.0.0

**Common issue: "ModuleNotFoundError"**
- **Fix:** Activate your virtual environment first!
  ```bash
  source venv/bin/activate
  ```

---

## 🎯 Next Steps

Read the full **[BEGINNER_GUIDE.md](BEGINNER_GUIDE.md)** for detailed explanations and advanced usage.

---

**Pro Tip:** Bookmark these commands! You'll use them every time. 🔖
