# 🐉 Quick Fix for Kali Linux User

## Your Specific Error
```
error: failed building wheel for lxml
running setup.py clean for lxml
failed to build installable wheels for some pyproject.toml based project lxml
```

## 🚀 **IMMEDIATE SOLUTION**

Run this command in your NjordScan directory:

```bash
./fix-lxml-kali.sh
```

This script will:
1. Install all required system dependencies
2. Try multiple lxml installation methods
3. Provide fallback options if lxml fails

## 🔧 **Alternative Quick Fix**

If the script doesn't work, try this manual approach:

```bash
# 1. Install system dependencies
sudo apt update
sudo apt install -y python3-dev libxml2-dev libxslt1-dev build-essential gcc g++ make

# 2. Try installing lxml
pip3 install lxml --no-cache-dir

# 3. If that fails, try pre-compiled wheels
pip3 install lxml --only-binary=all --no-cache-dir

# 4. If that fails, install NjordScan anyway (it will work without lxml)
pip3 install njordscan
```

## 🎯 **What This Fixes**

- ✅ Resolves the "failed building wheel for lxml" error
- ✅ Installs all required system dependencies
- ✅ Provides multiple fallback installation methods
- ✅ Ensures NjordScan works even if lxml fails

## 📚 **Additional Resources**

- **Detailed Guide**: `KALI_LINUX_GUIDE.md`
- **lxml Troubleshooting**: `LXML_TROUBLESHOOTING.md`
- **Complete Installation**: `install-kali.sh`

## 🆘 **If Nothing Works**

NjordScan will still function without lxml - it will just use alternative XML parsing. The core security scanning features will work perfectly.

---

**The lxml issue is very common on Kali Linux and these solutions should resolve it completely!** 🎉
