# 🛡️ NjordScan Security Report

**Generated:** 2025-09-05 07:16:45  
**Target:** `.`  
**Framework:** `unknown`  
**Scan Mode:** `standard`  
**Duration:** 0.01 seconds

---

## 📊 Executive Summary


**Security Score:** 0/100 (F)

**Total Issues Found:** 152

**Severity Breakdown:**
- 🔴 Critical: 3
- 🟠 High: 44
- 🟡 Medium: 23
- 🔵 Low: 82
- ℹ️ Info: 0

**Recommendation:** Critical security issues found. Immediate action required.


---

## 🔍 Vulnerability Details


### Codestatic Module


**🔵 LOW** - Potentially Dangerous Import: os

- **File:** `setup.py:9`
- **Type:** dangerous_import
- **Description:** Import of os module requires careful handling


**🔵 LOW** - Potentially Dangerous Import: subprocess

- **File:** `setup.py:11`
- **Type:** dangerous_import
- **Description:** Import of subprocess module requires careful handling


**🔵 LOW** - Potentially Dangerous Import: subprocess

- **File:** `install.py:8`
- **Type:** dangerous_import
- **Description:** Import of subprocess module requires careful handling


**🔵 LOW** - Potentially Dangerous Import: os

- **File:** `install.py:9`
- **Type:** dangerous_import
- **Description:** Import of os module requires careful handling


**🔵 LOW** - Potentially Dangerous Import: subprocess

- **File:** `tests/validate_all.py:14`
- **Type:** dangerous_import
- **Description:** Import of subprocess module requires careful handling


**🔵 LOW** - Potentially Dangerous Import: os

- **File:** `tests/validate_all.py:153`
- **Type:** dangerous_import
- **Description:** Import of os module requires careful handling


**🔵 LOW** - Potentially Dangerous Import: os

- **File:** `tests/validation/deep_validation.py:16`
- **Type:** dangerous_import
- **Description:** Import of os module requires careful handling


**🔵 LOW** - Potentially Dangerous Import: subprocess

- **File:** `tests/validation/deep_validation.py:19`
- **Type:** dangerous_import
- **Description:** Import of subprocess module requires careful handling


**🔵 LOW** - Potentially Dangerous Import: os

- **File:** `tests/validation/installation_validator.py:16`
- **Type:** dangerous_import
- **Description:** Import of os module requires careful handling


**🔵 LOW** - Potentially Dangerous Import: subprocess

- **File:** `tests/validation/installation_validator.py:17`
- **Type:** dangerous_import
- **Description:** Import of subprocess module requires careful handling


**🔵 LOW** - Potentially Dangerous Import: os

- **File:** `plugins/core/base_plugin.py:7`
- **Type:** dangerous_import
- **Description:** Import of os module requires careful handling


**🟡 MEDIUM** - Potential Xss Reflected Vulnerability

- **File:** `plugins/templates/scanner_template/template_scanner.py:74`
- **Type:** xss_reflected
- **Description:** Use of document.write() which can lead to XSS


**🟡 MEDIUM** - Potential Xss Reflected Vulnerability

- **File:** `plugins/templates/scanner_template/template_scanner.py:75`
- **Type:** xss_reflected
- **Description:** Use of document.write() which can lead to XSS


**🟠 HIGH** - Potential Xss Reflected Vulnerability

- **File:** `plugins/templates/scanner_template/template_scanner.py:68`
- **Type:** xss_reflected
- **Description:** Use of eval() function - can execute arbitrary code


**🟠 HIGH** - Potential Xss Reflected Vulnerability

- **File:** `plugins/templates/scanner_template/template_scanner.py:69`
- **Type:** xss_reflected
- **Description:** Use of eval() function - can execute arbitrary code


**🔵 LOW** - Potentially Dangerous Import: os

- **File:** `plugins/templates/scanner_template/template_scanner.py:12`
- **Type:** dangerous_import
- **Description:** Import of os module requires careful handling


**🔵 LOW** - Potentially Dangerous Import: os

- **File:** `plugins/templates/reporter_template/template_reporter.py:14`
- **Type:** dangerous_import
- **Description:** Import of os module requires careful handling


**🔵 LOW** - Potentially Dangerous Import: os

- **File:** `njordscan/cache.py:12`
- **Type:** dangerous_import
- **Description:** Import of os module requires careful handling


**🔵 LOW** - Potentially Dangerous Import: os

- **File:** `njordscan/main.py:9`
- **Type:** dangerous_import
- **Description:** Import of os module requires careful handling


**🔵 LOW** - Potentially Dangerous Import: os

- **File:** `njordscan/config.py:8`
- **Type:** dangerous_import
- **Description:** Import of os module requires careful handling


**🔵 LOW** - Potentially Dangerous Import: os

- **File:** `njordscan/plugin_creator.py:8`
- **Type:** dangerous_import
- **Description:** Import of os module requires careful handling


**🔵 LOW** - Potentially Dangerous Import: os

- **File:** `njordscan/plugins.py:8`
- **Type:** dangerous_import
- **Description:** Import of os module requires careful handling


**🔵 LOW** - Potentially Dangerous Import: os

- **File:** `njordscan/scanner.py:483`
- **Type:** dangerous_import
- **Description:** Import of os module requires careful handling


**🔵 LOW** - Potentially Dangerous Import: os

- **File:** `njordscan/cli.py:10`
- **Type:** dangerous_import
- **Description:** Import of os module requires careful handling


**🔵 LOW** - Unsafe Input Function

- **File:** `njordscan/cli.py:64`
- **Type:** unsafe_input
- **Description:** Use of input() without prompt may be confusing


**🔵 LOW** - Potentially Dangerous Import: os

- **File:** `njordscan/utils.py:8`
- **Type:** dangerous_import
- **Description:** Import of os module requires careful handling


**🟡 MEDIUM** - Potential Path Traversal Vulnerability

- **File:** `njordscan/runtime/fuzzing_engine.py:390`
- **Type:** path_traversal
- **Description:** Potential path traversal sequence


**🟡 MEDIUM** - Potential Path Traversal Vulnerability

- **File:** `njordscan/runtime/fuzzing_engine.py:390`
- **Type:** path_traversal
- **Description:** Potential path traversal sequence


**🟡 MEDIUM** - Potential Path Traversal Vulnerability

- **File:** `njordscan/runtime/fuzzing_engine.py:390`
- **Type:** path_traversal
- **Description:** Potential path traversal sequence


**🟡 MEDIUM** - Potential Path Traversal Vulnerability

- **File:** `njordscan/runtime/dast_engine.py:310`
- **Type:** path_traversal
- **Description:** Potential path traversal sequence


**🟡 MEDIUM** - Potential Path Traversal Vulnerability

- **File:** `njordscan/runtime/dast_engine.py:310`
- **Type:** path_traversal
- **Description:** Potential path traversal sequence


**🟡 MEDIUM** - Potential Path Traversal Vulnerability

- **File:** `njordscan/runtime/dast_engine.py:310`
- **Type:** path_traversal
- **Description:** Potential path traversal sequence


**🟡 MEDIUM** - Potential Path Traversal Vulnerability

- **File:** `njordscan/runtime/dast_engine.py:319`
- **Type:** path_traversal
- **Description:** Potential path traversal sequence


**🟡 MEDIUM** - Potential Path Traversal Vulnerability

- **File:** `njordscan/runtime/dast_engine.py:319`
- **Type:** path_traversal
- **Description:** Potential path traversal sequence


**🟡 MEDIUM** - Potential Path Traversal Vulnerability

- **File:** `njordscan/runtime/dast_engine.py:319`
- **Type:** path_traversal
- **Description:** Potential path traversal sequence


**🟡 MEDIUM** - Potential Path Traversal Vulnerability

- **File:** `njordscan/runtime/dast_engine.py:321`
- **Type:** path_traversal
- **Description:** Potential path traversal sequence


**🟡 MEDIUM** - Potential Path Traversal Vulnerability

- **File:** `njordscan/runtime/dast_engine.py:321`
- **Type:** path_traversal
- **Description:** Potential path traversal sequence


**🟡 MEDIUM** - Potential Path Traversal Vulnerability

- **File:** `njordscan/runtime/dast_engine.py:321`
- **Type:** path_traversal
- **Description:** Potential path traversal sequence


**🟡 MEDIUM** - Potential Path Traversal Vulnerability

- **File:** `njordscan/runtime/dast_engine.py:884`
- **Type:** path_traversal
- **Description:** Potential path traversal sequence


**🟠 HIGH** - Potential Xss Reflected Vulnerability

- **File:** `njordscan/developer_experience/ide_integration.py:532`
- **Type:** xss_reflected
- **Description:** Use of eval() function - can execute arbitrary code


**🟠 HIGH** - Potential Xss Reflected Vulnerability

- **File:** `njordscan/developer_experience/ide_integration.py:534`
- **Type:** xss_reflected
- **Description:** Use of eval() function - can execute arbitrary code


**🟠 HIGH** - Potential Xss Reflected Vulnerability

- **File:** `njordscan/developer_experience/ide_integration.py:535`
- **Type:** xss_reflected
- **Description:** Use of eval() function - can execute arbitrary code


**🟠 HIGH** - Potential Xss Reflected Vulnerability

- **File:** `njordscan/developer_experience/ide_integration.py:538`
- **Type:** xss_reflected
- **Description:** Use of eval() function - can execute arbitrary code


**🟠 HIGH** - Potential Xss Reflected Vulnerability

- **File:** `njordscan/developer_experience/ide_integration.py:540`
- **Type:** xss_reflected
- **Description:** Use of eval() function - can execute arbitrary code


**🟠 HIGH** - Potential Xss Reflected Vulnerability

- **File:** `njordscan/developer_experience/ide_integration.py:542`
- **Type:** xss_reflected
- **Description:** Use of eval() function - can execute arbitrary code


**🟠 HIGH** - Potential Xss Reflected Vulnerability

- **File:** `njordscan/developer_experience/ide_integration.py:674`
- **Type:** xss_reflected
- **Description:** Use of eval() function - can execute arbitrary code


**🟠 HIGH** - Potential Xss Reflected Vulnerability

- **File:** `njordscan/developer_experience/ide_integration.py:678`
- **Type:** xss_reflected
- **Description:** Use of eval() function - can execute arbitrary code


**🟠 HIGH** - Potential Xss Reflected Vulnerability

- **File:** `njordscan/developer_experience/ide_integration.py:679`
- **Type:** xss_reflected
- **Description:** Use of eval() function - can execute arbitrary code


**🟠 HIGH** - Potential Xss Reflected Vulnerability

- **File:** `njordscan/developer_experience/ide_integration.py:733`
- **Type:** xss_reflected
- **Description:** Use of eval() function - can execute arbitrary code


**🟠 HIGH** - Potential Xss Reflected Vulnerability

- **File:** `njordscan/developer_experience/ide_integration.py:683`
- **Type:** xss_reflected
- **Description:** Dynamic function creation - can lead to code injection


**🔵 LOW** - Potential Weak Random Vulnerability

- **File:** `njordscan/developer_experience/ide_integration.py:688`
- **Type:** weak_random
- **Description:** Use of cryptographically insecure Math.random()


**🔵 LOW** - Potential Weak Random Vulnerability

- **File:** `njordscan/developer_experience/ide_integration.py:692`
- **Type:** weak_random
- **Description:** Use of cryptographically insecure Math.random()


**🔵 LOW** - Potential Weak Random Vulnerability

- **File:** `njordscan/developer_experience/ide_integration.py:693`
- **Type:** weak_random
- **Description:** Use of cryptographically insecure Math.random()


**🔵 LOW** - Potentially Dangerous Import: subprocess

- **File:** `njordscan/developer_experience/ide_integration.py:23`
- **Type:** dangerous_import
- **Description:** Import of subprocess module requires careful handling


**🔵 LOW** - Potentially Dangerous Import: os

- **File:** `njordscan/developer_experience/ide_integration.py:25`
- **Type:** dangerous_import
- **Description:** Import of os module requires careful handling


**🔵 LOW** - Potentially Dangerous Import: os

- **File:** `njordscan/developer_experience/dx_orchestrator.py:21`
- **Type:** dangerous_import
- **Description:** Import of os module requires careful handling


**🟠 HIGH** - Potential Xss Reflected Vulnerability

- **File:** `njordscan/developer_experience/dev_tools.py:949`
- **Type:** xss_reflected
- **Description:** Use of eval() function - can execute arbitrary code


**🔵 LOW** - Potentially Dangerous Import: os

- **File:** `njordscan/developer_experience/dev_tools.py:15`
- **Type:** dangerous_import
- **Description:** Import of os module requires careful handling


**🔵 LOW** - Potentially Dangerous Import: subprocess

- **File:** `njordscan/developer_experience/dev_tools.py:25`
- **Type:** dangerous_import
- **Description:** Import of subprocess module requires careful handling


**🔵 LOW** - Potentially Dangerous Import: os

- **File:** `njordscan/developer_experience/interactive_cli.py:33`
- **Type:** dangerous_import
- **Description:** Import of os module requires careful handling


**🔵 LOW** - Potentially Dangerous Import: subprocess

- **File:** `njordscan/developer_experience/interactive_cli.py:34`
- **Type:** dangerous_import
- **Description:** Import of subprocess module requires careful handling


**🔵 LOW** - Unsafe Input Function

- **File:** `njordscan/developer_experience/interactive_cli.py:211`
- **Type:** unsafe_input
- **Description:** Use of input() without prompt may be confusing


**🔴 CRITICAL** - Potential Secrets Exposure Vulnerability

- **File:** `njordscan/configuration/secrets_detector.py:24`
- **Type:** secrets_exposure
- **Description:** Hardcoded API key found


**🔴 CRITICAL** - Potential Secrets Exposure Vulnerability

- **File:** `njordscan/configuration/secrets_detector.py:32`
- **Type:** secrets_exposure
- **Description:** Hardcoded password found


**🔴 CRITICAL** - Potential Secrets Exposure Vulnerability

- **File:** `njordscan/configuration/secrets_detector.py:38`
- **Type:** secrets_exposure
- **Description:** Hardcoded secret found


**🟠 HIGH** - Potential Secrets Exposure Vulnerability

- **File:** `njordscan/configuration/secrets_detector.py:27`
- **Type:** secrets_exposure
- **Description:** Hardcoded token found


**🟠 HIGH** - Potential Secrets Exposure Vulnerability

- **File:** `njordscan/configuration/secrets_detector.py:28`
- **Type:** secrets_exposure
- **Description:** Hardcoded token found


**🟠 HIGH** - Potential Secrets Exposure Vulnerability

- **File:** `njordscan/configuration/secrets_detector.py:30`
- **Type:** secrets_exposure
- **Description:** Hardcoded token found


**🟠 HIGH** - Potential Secrets Exposure Vulnerability

- **File:** `njordscan/configuration/secrets_detector.py:34`
- **Type:** secrets_exposure
- **Description:** Hardcoded token found


**🟠 HIGH** - Potential Xss Reflected Vulnerability

- **File:** `njordscan/plugins_v2/plugin_marketplace.py:743`
- **Type:** xss_reflected
- **Description:** Use of eval() function - can execute arbitrary code


**🟠 HIGH** - Potential Xss Reflected Vulnerability

- **File:** `njordscan/plugins_v2/plugin_manager.py:178`
- **Type:** xss_reflected
- **Description:** Dynamic function creation - can lead to code injection


**🟠 HIGH** - Potential Xss Reflected Vulnerability

- **File:** `njordscan/plugins_v2/plugin_manager.py:575`
- **Type:** xss_reflected
- **Description:** Dynamic function creation - can lead to code injection


**🔵 LOW** - Potentially Dangerous Import: os

- **File:** `njordscan/plugins_v2/plugin_manager.py:12`
- **Type:** dangerous_import
- **Description:** Import of os module requires careful handling


**🟠 HIGH** - Potential Xss Reflected Vulnerability

- **File:** `njordscan/intelligence/rules_engine.py:758`
- **Type:** xss_reflected
- **Description:** Use of eval() function - can execute arbitrary code


**🟠 HIGH** - Potential Xss Reflected Vulnerability

- **File:** `njordscan/intelligence/rules_engine.py:759`
- **Type:** xss_reflected
- **Description:** Use of eval() function - can execute arbitrary code


**🔵 LOW** - Potentially Dangerous Import: pickle

- **File:** `njordscan/intelligence/rules_engine.py:27`
- **Type:** dangerous_import
- **Description:** Import of pickle module requires careful handling


**🟠 HIGH** - Potential Xss Reflected Vulnerability

- **File:** `njordscan/report/formatter.py:896`
- **Type:** xss_reflected
- **Description:** Dynamic function creation - can lead to code injection


**🔵 LOW** - Potentially Dangerous Import: os

- **File:** `njordscan/report/formatter.py:9`
- **Type:** dangerous_import
- **Description:** Import of os module requires careful handling


**🔵 LOW** - Potentially Dangerous Import: pickle

- **File:** `njordscan/performance/cache_manager.py:17`
- **Type:** dangerous_import
- **Description:** Import of pickle module requires careful handling


**🟠 HIGH** - Potential Xss Reflected Vulnerability

- **File:** `njordscan/performance/resource_manager.py:890`
- **Type:** xss_reflected
- **Description:** Dynamic function creation - can lead to code injection


**🟠 HIGH** - Potential Xss Reflected Vulnerability

- **File:** `njordscan/performance/resource_manager.py:1034`
- **Type:** xss_reflected
- **Description:** Dynamic function creation - can lead to code injection


**🔵 LOW** - Potentially Dangerous Import: os

- **File:** `njordscan/performance/resource_manager.py:18`
- **Type:** dangerous_import
- **Description:** Import of os module requires careful handling


**🟠 HIGH** - Potential Xss Reflected Vulnerability

- **File:** `njordscan/performance/parallel_coordinator.py:608`
- **Type:** xss_reflected
- **Description:** Dynamic function creation - can lead to code injection


**🔵 LOW** - Potentially Dangerous Import: os

- **File:** `njordscan/performance/parallel_coordinator.py:19`
- **Type:** dangerous_import
- **Description:** Import of os module requires careful handling


**🔵 LOW** - Potentially Dangerous Import: pickle

- **File:** `njordscan/performance/parallel_coordinator.py:26`
- **Type:** dangerous_import
- **Description:** Import of pickle module requires careful handling


**🟠 HIGH** - Potential Xss Reflected Vulnerability

- **File:** `njordscan/performance/performance_orchestrator.py:1016`
- **Type:** xss_reflected
- **Description:** Dynamic function creation - can lead to code injection


**🟠 HIGH** - Potential Xss Reflected Vulnerability

- **File:** `njordscan/performance/performance_orchestrator.py:1158`
- **Type:** xss_reflected
- **Description:** Dynamic function creation - can lead to code injection


**🟠 HIGH** - Potential Xss Reflected Vulnerability

- **File:** `njordscan/reporting/visualization_engine.py:792`
- **Type:** xss_reflected
- **Description:** Dynamic function creation - can lead to code injection


**🟡 MEDIUM** - Potential Xss Reflected Vulnerability

- **File:** `njordscan/modules/code_static.py:45`
- **Type:** xss_reflected
- **Description:** Use of document.write() which can lead to XSS


**🟠 HIGH** - Potential Xss Reflected Vulnerability

- **File:** `njordscan/modules/code_static.py:50`
- **Type:** xss_reflected
- **Description:** Use of eval() function - can execute arbitrary code


**🟠 HIGH** - Potential Xss Reflected Vulnerability

- **File:** `njordscan/modules/code_static.py:398`
- **Type:** xss_reflected
- **Description:** Use of eval() function - can execute arbitrary code


**🟠 HIGH** - Potential Xss Reflected Vulnerability

- **File:** `njordscan/modules/code_static.py:399`
- **Type:** xss_reflected
- **Description:** Use of eval() function - can execute arbitrary code


**🟠 HIGH** - Potential Xss Reflected Vulnerability

- **File:** `njordscan/modules/code_static.py:595`
- **Type:** xss_reflected
- **Description:** Use of eval() function - can execute arbitrary code


**🟡 MEDIUM** - Potential Path Traversal Vulnerability

- **File:** `njordscan/modules/code_static.py:950`
- **Type:** path_traversal
- **Description:** Potential path traversal sequence


**🔵 LOW** - Potential Weak Random Vulnerability

- **File:** `njordscan/modules/code_static.py:166`
- **Type:** weak_random
- **Description:** Use of cryptographically insecure Math.random()


**🔵 LOW** - Potentially Dangerous Import: os

- **File:** `njordscan/modules/code_static.py:9`
- **Type:** dangerous_import
- **Description:** Import of os module requires careful handling


**🟡 MEDIUM** - Potential Path Traversal Vulnerability

- **File:** `njordscan/modules/runtime.py:53`
- **Type:** path_traversal
- **Description:** Potential path traversal sequence


**🟡 MEDIUM** - Potential Path Traversal Vulnerability

- **File:** `njordscan/modules/runtime.py:53`
- **Type:** path_traversal
- **Description:** Potential path traversal sequence


**🟡 MEDIUM** - Potential Path Traversal Vulnerability

- **File:** `njordscan/modules/runtime.py:53`
- **Type:** path_traversal
- **Description:** Potential path traversal sequence


**🟡 MEDIUM** - Potential Path Traversal Vulnerability

- **File:** `njordscan/modules/configs.py:591`
- **Type:** path_traversal
- **Description:** Potential path traversal sequence


**🟡 MEDIUM** - Potential Path Traversal Vulnerability

- **File:** `njordscan/modules/dependencies.py:905`
- **Type:** path_traversal
- **Description:** Potential path traversal sequence


**🔵 LOW** - Potentially Dangerous Import: subprocess

- **File:** `njordscan/modules/dependencies.py:8`
- **Type:** dangerous_import
- **Description:** Import of subprocess module requires careful handling


**🟠 HIGH** - Potential Xss Reflected Vulnerability

- **File:** `njordscan/modules/vulnerability_detector.py:587`
- **Type:** xss_reflected
- **Description:** Use of eval() function - can execute arbitrary code


**🟠 HIGH** - Potential Xss Reflected Vulnerability

- **File:** `njordscan/modules/vulnerability_detector.py:589`
- **Type:** xss_reflected
- **Description:** Use of eval() function - can execute arbitrary code


**🟠 HIGH** - Potential Xss Reflected Vulnerability

- **File:** `njordscan/modules/vulnerability_detector.py:590`
- **Type:** xss_reflected
- **Description:** Use of eval() function - can execute arbitrary code


**🟠 HIGH** - Potential Xss Reflected Vulnerability

- **File:** `njordscan/modules/vulnerability_detector.py:594`
- **Type:** xss_reflected
- **Description:** Use of eval() function - can execute arbitrary code


**🟠 HIGH** - Potential Xss Reflected Vulnerability

- **File:** `njordscan/modules/vulnerability_detector.py:595`
- **Type:** xss_reflected
- **Description:** Use of eval() function - can execute arbitrary code


**🟠 HIGH** - Potential Xss Reflected Vulnerability

- **File:** `njordscan/modules/vulnerability_detector.py:643`
- **Type:** xss_reflected
- **Description:** Use of eval() function - can execute arbitrary code


**🟠 HIGH** - Potential Xss Reflected Vulnerability

- **File:** `njordscan/modules/ai_endpoints.py:447`
- **Type:** xss_reflected
- **Description:** Use of eval() function - can execute arbitrary code


**🟠 HIGH** - Potential Xss Reflected Vulnerability

- **File:** `njordscan/modules/headers.py:169`
- **Type:** xss_reflected
- **Description:** Use of eval() function - can execute arbitrary code


**🟠 HIGH** - Potential Xss Reflected Vulnerability

- **File:** `njordscan/modules/code_static_enhanced.py:733`
- **Type:** xss_reflected
- **Description:** Use of eval() function - can execute arbitrary code


**🟡 MEDIUM** - Potential Path Traversal Vulnerability

- **File:** `njordscan/modules/code_static_enhanced.py:1319`
- **Type:** path_traversal
- **Description:** Potential path traversal sequence


**🟠 HIGH** - Potential Xss Reflected Vulnerability

- **File:** `njordscan/analysis/ast_analyzer.py:372`
- **Type:** xss_reflected
- **Description:** Use of eval() function - can execute arbitrary code


**🔵 LOW** - Potential Weak Random Vulnerability

- **File:** `njordscan/analysis/ast_analyzer.py:276`
- **Type:** weak_random
- **Description:** Use of cryptographically insecure Math.random()


**🔵 LOW** - Potentially Dangerous Import: subprocess

- **File:** `njordscan/analysis/ast_analyzer.py:9`
- **Type:** dangerous_import
- **Description:** Import of subprocess module requires careful handling


**🔵 LOW** - Potentially Dangerous Import: os

- **File:** `njordscan/analysis/ast_analyzer.py:577`
- **Type:** dangerous_import
- **Description:** Import of os module requires careful handling


**🔵 LOW** - Potentially Dangerous Import: os

- **File:** `njordscan/analysis/ast_analyzer.py:635`
- **Type:** dangerous_import
- **Description:** Import of os module requires careful handling


**🔵 LOW** - Potential Weak Random Vulnerability

- **File:** `njordscan/frameworks/react_analyzer.py:382`
- **Type:** weak_random
- **Description:** Use of cryptographically insecure Math.random()


**🔵 LOW** - Potential Weak Random Vulnerability

- **File:** `njordscan/frameworks/react_analyzer.py:382`
- **Type:** weak_random
- **Description:** Use of timestamp for random values


### Dependencies Module


**🔵 LOW** - Unpinned Python Dependency: click

- **File:** `requirements.txt:7`
- **Type:** outdated_dependency
- **Description:** Package click version is not pinned, which may lead to instability


**🔵 LOW** - Unpinned Python Dependency: rich

- **File:** `requirements.txt:8`
- **Type:** outdated_dependency
- **Description:** Package rich version is not pinned, which may lead to instability


**🔵 LOW** - Unpinned Python Dependency: colorama

- **File:** `requirements.txt:9`
- **Type:** outdated_dependency
- **Description:** Package colorama version is not pinned, which may lead to instability


**🔵 LOW** - Unpinned Python Dependency: aiohttp

- **File:** `requirements.txt:12`
- **Type:** outdated_dependency
- **Description:** Package aiohttp version is not pinned, which may lead to instability


**🔵 LOW** - Unpinned Python Dependency: requests

- **File:** `requirements.txt:13`
- **Type:** outdated_dependency
- **Description:** Package requests version is not pinned, which may lead to instability


**🔵 LOW** - Unpinned Python Dependency: httpx

- **File:** `requirements.txt:14`
- **Type:** outdated_dependency
- **Description:** Package httpx version is not pinned, which may lead to instability


**🔵 LOW** - Unpinned Python Dependency: pyyaml

- **File:** `requirements.txt:17`
- **Type:** outdated_dependency
- **Description:** Package pyyaml version is not pinned, which may lead to instability


**🔵 LOW** - Unpinned Python Dependency: toml

- **File:** `requirements.txt:18`
- **Type:** outdated_dependency
- **Description:** Package toml version is not pinned, which may lead to instability


**🔵 LOW** - Unpinned Python Dependency: python-dotenv

- **File:** `requirements.txt:19`
- **Type:** outdated_dependency
- **Description:** Package python-dotenv version is not pinned, which may lead to instability


**🔵 LOW** - Unpinned Python Dependency: beautifulsoup4

- **File:** `requirements.txt:24`
- **Type:** outdated_dependency
- **Description:** Package beautifulsoup4 version is not pinned, which may lead to instability


**🔵 LOW** - Unpinned Python Dependency: lxml

- **File:** `requirements.txt:25`
- **Type:** outdated_dependency
- **Description:** Package lxml version is not pinned, which may lead to instability


**🔵 LOW** - Unpinned Python Dependency: html5lib

- **File:** `requirements.txt:26`
- **Type:** outdated_dependency
- **Description:** Package html5lib version is not pinned, which may lead to instability


**🔵 LOW** - Unpinned Python Dependency: jinja2

- **File:** `requirements.txt:29`
- **Type:** outdated_dependency
- **Description:** Package jinja2 version is not pinned, which may lead to instability


**🔵 LOW** - Unpinned Python Dependency: markdown

- **File:** `requirements.txt:30`
- **Type:** outdated_dependency
- **Description:** Package markdown version is not pinned, which may lead to instability


**🔵 LOW** - Unpinned Python Dependency: cryptography

- **File:** `requirements.txt:33`
- **Type:** outdated_dependency
- **Description:** Package cryptography version is not pinned, which may lead to instability


**🔵 LOW** - Unpinned Python Dependency: pyjwt

- **File:** `requirements.txt:34`
- **Type:** outdated_dependency
- **Description:** Package pyjwt version is not pinned, which may lead to instability


**🔵 LOW** - Unpinned Python Dependency: aiofiles

- **File:** `requirements.txt:37`
- **Type:** outdated_dependency
- **Description:** Package aiofiles version is not pinned, which may lead to instability


**🔵 LOW** - Unpinned Python Dependency: asyncio-throttle

- **File:** `requirements.txt:38`
- **Type:** outdated_dependency
- **Description:** Package asyncio-throttle version is not pinned, which may lead to instability


**🔵 LOW** - Unpinned Python Dependency: typing-extensions

- **File:** `requirements.txt:41`
- **Type:** outdated_dependency
- **Description:** Package typing-extensions version is not pinned, which may lead to instability


**🔵 LOW** - Unpinned Python Dependency: pydantic

- **File:** `requirements.txt:42`
- **Type:** outdated_dependency
- **Description:** Package pydantic version is not pinned, which may lead to instability


**🔵 LOW** - Unpinned Python Dependency: safety

- **File:** `requirements.txt:45`
- **Type:** outdated_dependency
- **Description:** Package safety version is not pinned, which may lead to instability


**🔵 LOW** - Unpinned Python Dependency: packaging

- **File:** `requirements.txt:46`
- **Type:** outdated_dependency
- **Description:** Package packaging version is not pinned, which may lead to instability


**🔵 LOW** - Unpinned Python Dependency: tqdm

- **File:** `requirements.txt:49`
- **Type:** outdated_dependency
- **Description:** Package tqdm version is not pinned, which may lead to instability


**🔵 LOW** - Unpinned Python Dependency: tabulate

- **File:** `requirements.txt:50`
- **Type:** outdated_dependency
- **Description:** Package tabulate version is not pinned, which may lead to instability


**🔵 LOW** - Unpinned Python Dependency: psutil

- **File:** `requirements.txt:51`
- **Type:** outdated_dependency
- **Description:** Package psutil version is not pinned, which may lead to instability


**🔵 LOW** - Unpinned Python Dependency: watchdog

- **File:** `requirements.txt:52`
- **Type:** outdated_dependency
- **Description:** Package watchdog version is not pinned, which may lead to instability


**🔵 LOW** - Unpinned Python Dependency: importlib-metadata

- **File:** `requirements.txt:55`
- **Type:** outdated_dependency
- **Description:** Package importlib-metadata version is not pinned, which may lead to instability


**🔵 LOW** - Unpinned Python Dependency: stevedore

- **File:** `requirements.txt:56`
- **Type:** outdated_dependency
- **Description:** Package stevedore version is not pinned, which may lead to instability


**🔵 LOW** - Unpinned Python Dependency: pluggy

- **File:** `requirements.txt:57`
- **Type:** outdated_dependency
- **Description:** Package pluggy version is not pinned, which may lead to instability


**🔵 LOW** - Unpinned Python Dependency: diskcache

- **File:** `requirements.txt:60`
- **Type:** outdated_dependency
- **Description:** Package diskcache version is not pinned, which may lead to instability


**🔵 LOW** - Unpinned Python Dependency: dnspython

- **File:** `requirements.txt:63`
- **Type:** outdated_dependency
- **Description:** Package dnspython version is not pinned, which may lead to instability


**🔵 LOW** - Unpinned Python Dependency: lz4

- **File:** `requirements.txt:66`
- **Type:** outdated_dependency
- **Description:** Package lz4 version is not pinned, which may lead to instability


**🔵 LOW** - Unpinned Python Dependency: bandit

- **File:** `requirements.txt:69`
- **Type:** outdated_dependency
- **Description:** Package bandit version is not pinned, which may lead to instability



---

## 📈 Statistics


**Modules Executed:** configs, static, dependencies, ai_endpoints

**Plugins Executed:** None

**Scan Duration:** 0.01 seconds

**AI Enhanced:** Yes


---

## 🛠️ Recommendations

**Next Steps:**

1. URGENT: Fix 3 critical vulnerabilities immediately
2. Fix 44 high-severity vulnerabilities within 24 hours
3. Review all security findings in detail
4. Implement recommended fixes
5. Re-scan after fixes to verify resolution
6. Consider security training for the development team


---

## 📋 Scan Information


**Target:** `.`

**Framework:** `unknown`

**Scan Mode:** `standard`

**Timestamp:** 0.01 seconds

**Tool Version:** NjordScan v1.0.0


---

*Report generated by [NjordScan](https://njordscan.dev) - The Ultimate Security Scanner*
