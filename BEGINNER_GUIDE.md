# 🚀 NjordScan - Complete Beginner's Guide

**Never used a security scanner before? No problem!** This guide will walk you through everything step-by-step.

---

## 📋 What You Need

- A computer with **Python 3.8 or newer** installed
- Basic ability to use a terminal/command prompt
- A web project to scan (Next.js, React, or Vite)

---

## 🎯 Step 1: Check Python Installation

Open your terminal and type:

```bash
python3 --version
```

You should see something like `Python 3.10.x` or higher. If you get an error, [install Python first](https://www.python.org/downloads/).

---

## 🎯 Step 2: Set Up Virtual Environment

**Why?** A virtual environment keeps NjordScan's dependencies separate from your system, preventing conflicts.

```bash
# Navigate to the NjordScan directory
cd /path/to/NjordScan

# Create a virtual environment (do this once)
python3 -m venv venv

# Activate the virtual environment
# On Linux/Mac:
source venv/bin/activate

# On Windows:
venv\Scripts\activate
```

**You'll know it worked** when you see `(venv)` at the start of your terminal prompt:
```
(venv) user@computer:~/NjordScan$
```

---

## 🎯 Step 3: Install NjordScan

With your virtual environment activated:

```bash
# Install core dependencies first
pip install --upgrade pip

# Install NjordScan (this may take 2-3 minutes)
pip install -e .
```

**That's it!** NjordScan is now installed. ✅

### 🎁 Optional Features

If you want advanced features, you can install extras:

```bash
# For advanced XML parsing (may require system libraries)
pip install -e ".[advanced-parsing]"

# For AI/ML features
pip install -e ".[ai-features]"

# For everything
pip install -e ".[all]"
```

**Note:** The advanced features are optional and may require system libraries. The core scanner works perfectly without them!

---

## 🎯 Step 4: Update Vulnerability Database

**Important!** Before your first scan, update the CVE and exploit database:

```bash
# Download the latest vulnerability data
python -m njordscan update
```

This will:
- ✅ Download CVE data from NIST
- ✅ Get NPM security advisories
- ✅ Fetch GitHub security advisories
- ✅ Update MITRE ATT&CK patterns
- ✅ Get framework-specific vulnerabilities (Next.js, React, Vite)

**Takes 1-2 minutes** on first run. Subsequent updates are faster (cached).

### **Check for Updates Anytime:**

```bash
# Check if updates are available
python -m njordscan update --check

# Force update all sources
python -m njordscan update --force

# Update only official sources
python -m njordscan update --source official
```

**How often to update?** Weekly is good, daily if you're actively developing.

**Note:** Some sources may fail (HTTP 404, 401 errors). This is normal - NjordScan will use the data it successfully downloaded. The scanner works with partial data!

---

## 🎯 Step 5: Your First Scan
Now that the database is updated, let's scan!

### **Accept Legal Terms (One-Time)**

On first use, accept the terms:

```bash
python -m njordscan legal --accept
# Type 'y' and press Enter
```

This is a one-time step. You won't see it again.

### **Quick Test Scan**

Let's scan the current directory to make sure everything works:

```bash
# Make sure you're still in the virtual environment (you should see (venv))
python -m njordscan --help
```

If you see help text, **congratulations!** NjordScan is installed correctly! 🎉

### **Scan a Real Project**

```bash
# Navigate to your web project
cd /path/to/your/nextjs-project

# Run a quick scan
python -m njordscan

# Or specify the path
python -m njordscan /path/to/your/project
```

---

## 🎨 Understanding the Output

NjordScan will show you:

1. **Framework Detection** - What type of project you have
2. **Vulnerabilities Found** - Security issues discovered
3. **Severity Levels:**
   - 🔴 **CRITICAL** - Fix immediately!
   - 🟠 **HIGH** - Fix soon
   - 🟡 **MEDIUM** - Should fix
   - 🔵 **LOW** - Nice to fix
   - ⚪ **INFO** - Good to know

---

## 🎯 Common Scan Commands

### **Different Scan Modes:**

```bash
# Quick scan (fast, basic checks) - good for testing
python -m njordscan --mode quick

# Standard scan (default, recommended)
python -m njordscan --mode standard

# Deep scan (thorough, includes AI analysis)
python -m njordscan --mode deep
```

### **Save Results to File:**

```bash
# Save as JSON
python -m njordscan --output results.json --format json

# Save as HTML report
python -m njordscan --output report.html --format html
```

### **Scan Only High/Critical Issues:**

```bash
python -m njordscan --min-severity high
```

---

## 🎯 Interactive Mode (Easiest for Beginners)

For a guided experience with a visual interface:

```bash
python -m njordscan --interactive
```

This will:
- ✅ Walk you through setup
- ✅ Let you choose options with arrow keys
- ✅ Show results in an easy-to-navigate interface
- ✅ Explain what each vulnerability means

---

## 🆘 Troubleshooting

### **Problem: "ModuleNotFoundError: No module named 'rich'"**

**Solution:** Your virtual environment isn't activated.

```bash
# Activate it:
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows
```

### **Problem: "Permission denied" or "Access denied"**

**Solution:** Don't use `sudo`. Always use the virtual environment instead.

### **Problem: Installation takes forever**

**Solution:** This is normal! Installing all dependencies can take 3-5 minutes.

### **Problem: lxml won't install**

**Solution:** This is fine! NjordScan works without it. For a fix, see Step 3 above.

---

## 🎯 Quick Reference Card

```bash
# Activate virtual environment (do this every time)
source venv/bin/activate

# Basic scan
python -m njordscan

# Scan specific directory
python -m njordscan /path/to/project

# Quick scan (fast)
python -m njordscan --mode quick

# Deep scan with AI (thorough)
python -m njordscan --mode deep

# Interactive mode (beginner-friendly)
python -m njordscan --interactive

# Get help
python -m njordscan --help

# Deactivate virtual environment when done
deactivate
```

---

## 🎯 What's Next?

Once you're comfortable with basic scans:

1. **Read the full documentation** - Check out `docs/getting-started/quick-start.md`
2. **Try different modes** - Experiment with `--mode deep` for AI analysis
3. **Integrate with CI/CD** - Automate scans in your workflow
4. **Customize settings** - Create a config file for your preferences

---

## 💡 Tips for Beginners

1. **Start with `--mode quick`** to get familiar with the output
2. **Use `--interactive`** mode for the best experience
3. **Focus on CRITICAL and HIGH** severity issues first
4. **Read the "Fix" recommendations** - they tell you exactly what to do
5. **Don't panic!** Finding vulnerabilities is good - it means you can fix them!

---

## 🆘 Still Stuck?

If you're having trouble:

1. **Check the full documentation** in the `docs/` folder
2. **Look at KALI_USER_QUICK_FIX.md** if you're on Kali Linux
3. **Check TROUBLESHOOTING.md** in `docs/advanced/`
4. **Open a GitHub issue** with your error message

---

## 📚 Learning Resources

Want to understand security better?

```bash
# Learn about a specific vulnerability type
python -m njordscan explain xss
python -m njordscan explain headers
python -m njordscan explain authentication
```

---

**Remember:** Always keep your virtual environment activated when using NjordScan!

Look for `(venv)` in your terminal prompt. If it's not there, run:
```bash
source venv/bin/activate
```

Happy scanning! 🛡️
