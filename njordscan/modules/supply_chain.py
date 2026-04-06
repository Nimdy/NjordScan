"""
Supply Chain Security Module

Detects supply chain attack vectors in npm/Node.js projects:
- Malicious or suspicious install scripts in package.json
- Lockfile integrity issues (missing checksums, non-standard registries, git deps)
- Lockfile tampering indicators
"""

import json
import re
import hashlib
from pathlib import Path
from typing import List, Dict, Any, Optional

from .base import BaseModule
from ..vulnerability import Vulnerability

try:
    from ..analysis.dep_graph import DepGraphAnalyzer
    DEP_GRAPH_AVAILABLE = True
except ImportError:
    DEP_GRAPH_AVAILABLE = False

# Patterns that are strong indicators of malicious install scripts
DANGEROUS_SCRIPT_PATTERNS = [
    # Network exfiltration during install
    (r'\bcurl\b.*\|.*\bsh\b', 'Pipes remote content into shell'),
    (r'\bwget\b.*\|.*\bsh\b', 'Pipes remote content into shell'),
    (r'\bcurl\b.*-[a-zA-Z]*o\b', 'Downloads file via curl'),
    (r'\bwget\b', 'Downloads file via wget'),

    # Encoded/obfuscated payloads
    (r'\bbase64\b.*-d', 'Decodes base64 payload'),
    (r'\beval\b\s*[\(\$]', 'Evaluates dynamic code'),
    (r'\\x[0-9a-fA-F]{2}', 'Contains hex-encoded characters'),
    (r'node\s+-e\s+["\']', 'Runs inline Node.js code'),
    (r'python[23]?\s+-c\s+["\']', 'Runs inline Python code'),

    # Environment variable harvesting
    (r'\bprocess\.env\b', 'Accesses environment variables'),
    (r'\$\{?\bHOME\b', 'Accesses HOME directory'),
    (r'\$\{?\bUSER\b', 'Accesses USER variable'),
    (r'\/etc\/passwd', 'Reads /etc/passwd'),
    (r'\.ssh\/', 'Accesses SSH directory'),
    (r'\.npmrc', 'Accesses npmrc (may contain auth tokens)'),
    (r'\.aws\/', 'Accesses AWS credentials'),

    # Data exfiltration via DNS or HTTP
    (r'\bdig\b\s+.*\$', 'Potential DNS-based data exfiltration'),
    (r'\bnslookup\b.*\$', 'Potential DNS-based data exfiltration'),

    # Reverse shells
    (r'/dev/tcp/', 'Potential reverse shell via /dev/tcp'),
    (r'\bnc\b\s+-[a-z]*e\b', 'Potential reverse shell via netcat'),
    (r'\bsocat\b', 'Potential reverse shell via socat'),

    # File system tampering
    (r'\bchmod\b\s+[0-7]*[7][0-7]*', 'Sets overly permissive file permissions'),
    (r'\brm\b\s+-rf\s+/', 'Destructive recursive delete from root'),
]

# Patterns that are suspicious but may have legitimate uses
SUSPICIOUS_SCRIPT_PATTERNS = [
    (r'\bcurl\b', 'Uses curl (review target URL)'),
    (r'\bhttp[s]?://', 'Contains URL (verify destination)'),
    (r'\bchild_process\b', 'Spawns child processes'),
    (r'\bexec\b\s*\(', 'Executes shell command'),
    (r'\bspawn\b\s*\(', 'Spawns process'),
    (r'\brequire\s*\(\s*["\']child_process', 'Imports child_process'),
    (r'\bfs\b\.\s*write', 'Writes to filesystem'),
    (r'&&\s*node\b', 'Chains node execution'),
]

# Lifecycle scripts that run automatically (highest risk)
AUTO_RUN_SCRIPTS = [
    'preinstall', 'install', 'postinstall',
    'preuninstall', 'uninstall', 'postuninstall',
    'prepublish', 'preprepare', 'prepare', 'postprepare',
]

# Standard registries considered safe
TRUSTED_REGISTRIES = [
    'registry.npmjs.org',
    'registry.yarnpkg.com',
    'registry.npmmirror.com',
]


class SupplyChainModule(BaseModule):
    """Module for detecting supply chain attack vectors."""

    def __init__(self, config, vuln_id_generator):
        super().__init__(config, vuln_id_generator)
        self.name = 'supply_chain'

    def should_run(self, mode: str) -> bool:
        """Supply chain module runs in static and full modes."""
        return mode in ['static', 'full']

    async def scan(self, target: str) -> List[Vulnerability]:
        """Scan for supply chain security issues."""
        vulnerabilities = []

        if target.startswith(('http://', 'https://')):
            return vulnerabilities

        target_path = Path(target)
        if not target_path.exists():
            return vulnerabilities

        # 1. Install script analysis
        script_vulns = self._scan_install_scripts(target_path)
        vulnerabilities.extend(script_vulns)

        # 2. Lockfile integrity checks
        lockfile_vulns = self._scan_lockfile_integrity(target_path)
        vulnerabilities.extend(lockfile_vulns)

        # 3. Dependency graph risk analysis
        if DEP_GRAPH_AVAILABLE:
            dep_vulns = self._scan_dep_graph(target_path)
            vulnerabilities.extend(dep_vulns)

        return vulnerabilities

    # ------------------------------------------------------------------ #
    #  Install Script Analysis
    # ------------------------------------------------------------------ #

    def _scan_install_scripts(self, target_path: Path) -> List[Vulnerability]:
        """Analyze package.json lifecycle scripts for malicious patterns."""
        vulnerabilities = []

        package_json_path = target_path / 'package.json'
        if not package_json_path.exists():
            return vulnerabilities

        try:
            with open(package_json_path, 'r', encoding='utf-8') as f:
                package_data = json.load(f)
        except (json.JSONDecodeError, IOError):
            return vulnerabilities

        scripts = package_data.get('scripts', {})
        if not scripts:
            return vulnerabilities

        for script_name, script_cmd in scripts.items():
            if not isinstance(script_cmd, str):
                continue

            is_auto_run = script_name in AUTO_RUN_SCRIPTS

            # Check dangerous patterns
            for pattern, reason in DANGEROUS_SCRIPT_PATTERNS:
                if re.search(pattern, script_cmd, re.IGNORECASE):
                    severity = 'critical' if is_auto_run else 'high'
                    vulnerabilities.append(self.create_vulnerability(
                        title=f"Dangerous install script: {script_name}",
                        description=(
                            f"Lifecycle script '{script_name}' contains a dangerous pattern: {reason}. "
                            f"Command: {script_cmd[:200]}"
                        ),
                        severity=severity,
                        confidence='high' if is_auto_run else 'medium',
                        vuln_type='malicious_install_script',
                        file_path=str(package_json_path),
                        code_snippet=f'"{script_name}": "{script_cmd}"',
                        fix=(
                            f"Review the '{script_name}' script carefully. "
                            "Use 'npm install --ignore-scripts' for untrusted packages."
                        ),
                        metadata={
                            'script_name': script_name,
                            'script_command': script_cmd,
                            'pattern_matched': reason,
                            'auto_run': is_auto_run,
                        }
                    ))
                    break  # one finding per script for dangerous patterns

            # Check suspicious patterns (only for auto-run scripts)
            if is_auto_run:
                for pattern, reason in SUSPICIOUS_SCRIPT_PATTERNS:
                    if re.search(pattern, script_cmd, re.IGNORECASE):
                        # Don't duplicate if already flagged as dangerous
                        already_flagged = any(
                            v.metadata.get('script_name') == script_name
                            for v in vulnerabilities
                        )
                        if not already_flagged:
                            vulnerabilities.append(self.create_vulnerability(
                                title=f"Suspicious install script: {script_name}",
                                description=(
                                    f"Auto-run lifecycle script '{script_name}' contains a suspicious pattern: "
                                    f"{reason}. Command: {script_cmd[:200]}"
                                ),
                                severity='medium',
                                confidence='medium',
                                vuln_type='suspicious_install_script',
                                file_path=str(package_json_path),
                                code_snippet=f'"{script_name}": "{script_cmd}"',
                                fix=(
                                    f"Audit the '{script_name}' script to confirm it is benign. "
                                    "Consider running 'npm install --ignore-scripts' for untrusted packages."
                                ),
                                metadata={
                                    'script_name': script_name,
                                    'script_command': script_cmd,
                                    'pattern_matched': reason,
                                    'auto_run': True,
                                }
                            ))
                            break

        return vulnerabilities

    # ------------------------------------------------------------------ #
    #  Lockfile Integrity Checks
    # ------------------------------------------------------------------ #

    def _scan_lockfile_integrity(self, target_path: Path) -> List[Vulnerability]:
        """Check lockfile integrity for signs of tampering or risk."""
        vulnerabilities = []

        # package-lock.json
        package_lock_path = target_path / 'package-lock.json'
        if package_lock_path.exists():
            vulns = self._check_package_lock(package_lock_path)
            vulnerabilities.extend(vulns)

        # yarn.lock
        yarn_lock_path = target_path / 'yarn.lock'
        if yarn_lock_path.exists():
            vulns = self._check_yarn_lock(yarn_lock_path)
            vulnerabilities.extend(vulns)

        return vulnerabilities

    def _check_package_lock(self, lock_path: Path) -> List[Vulnerability]:
        """Analyze package-lock.json for integrity issues."""
        vulnerabilities = []

        try:
            with open(lock_path, 'r', encoding='utf-8') as f:
                lock_data = json.load(f)
        except (json.JSONDecodeError, IOError):
            return vulnerabilities

        lockfile_version = lock_data.get('lockfileVersion', 1)

        # Choose the right packages key based on lockfile version
        if lockfile_version >= 2 and 'packages' in lock_data:
            packages = lock_data['packages']
        elif 'dependencies' in lock_data:
            packages = lock_data['dependencies']
        else:
            return vulnerabilities

        missing_integrity_count = 0
        non_standard_registry_packages = []
        git_dependency_packages = []

        for pkg_name, pkg_info in packages.items():
            if not isinstance(pkg_info, dict):
                continue

            # Skip the root entry (empty string key in lockfile v2+)
            if pkg_name == '':
                continue

            resolved_url = pkg_info.get('resolved', '')
            integrity = pkg_info.get('integrity', '')
            version = pkg_info.get('version', '')

            # Clean up package name for display
            display_name = pkg_name.replace('node_modules/', '') if pkg_name.startswith('node_modules/') else pkg_name

            # Check for missing integrity hashes
            if resolved_url and not integrity:
                missing_integrity_count += 1

            # Check for non-standard registries
            if resolved_url and not any(reg in resolved_url for reg in TRUSTED_REGISTRIES):
                if resolved_url.startswith('http'):
                    non_standard_registry_packages.append(
                        (display_name, version, resolved_url)
                    )

            # Check for git dependencies
            if resolved_url and (
                resolved_url.startswith('git+') or
                resolved_url.startswith('git://') or
                'github.com' in resolved_url and '.git' in resolved_url
            ):
                git_dependency_packages.append(
                    (display_name, version, resolved_url)
                )

        # Report missing integrity hashes
        if missing_integrity_count > 0:
            vulnerabilities.append(self.create_vulnerability(
                title=f"Lockfile missing integrity hashes ({missing_integrity_count} packages)",
                description=(
                    f"{missing_integrity_count} package(s) in package-lock.json are missing integrity "
                    "checksums (sha512/sha1 hashes). This prevents verification that downloaded "
                    "packages match what was originally resolved."
                ),
                severity='medium',
                confidence='high',
                vuln_type='lockfile_integrity',
                file_path=str(lock_path),
                fix="Delete node_modules and package-lock.json, then run 'npm install' to regenerate with integrity hashes.",
                metadata={
                    'missing_integrity_count': missing_integrity_count,
                    'lockfile_version': lockfile_version,
                }
            ))

        # Report non-standard registries
        for display_name, version, resolved_url in non_standard_registry_packages:
            vulnerabilities.append(self.create_vulnerability(
                title=f"Non-standard registry: {display_name}",
                description=(
                    f"Package '{display_name}' (v{version}) resolves from a non-standard registry: "
                    f"{resolved_url[:120]}. This could indicate dependency confusion or a compromised source."
                ),
                severity='high',
                confidence='medium',
                vuln_type='lockfile_registry_mismatch',
                file_path=str(lock_path),
                fix=f"Verify that '{display_name}' should be resolved from this registry. Configure .npmrc for trusted registries.",
                metadata={
                    'package_name': display_name,
                    'version': version,
                    'resolved_url': resolved_url,
                }
            ))

        # Report git dependencies
        for display_name, version, resolved_url in git_dependency_packages:
            vulnerabilities.append(self.create_vulnerability(
                title=f"Git dependency: {display_name}",
                description=(
                    f"Package '{display_name}' is resolved from a git URL: {resolved_url[:120]}. "
                    "Git dependencies bypass registry integrity checks and can be silently modified."
                ),
                severity='medium',
                confidence='high',
                vuln_type='lockfile_git_dependency',
                file_path=str(lock_path),
                fix=f"Publish '{display_name}' to a registry or pin to a specific commit hash.",
                metadata={
                    'package_name': display_name,
                    'version': version,
                    'resolved_url': resolved_url,
                }
            ))

        return vulnerabilities

    def _check_yarn_lock(self, lock_path: Path) -> List[Vulnerability]:
        """Analyze yarn.lock for integrity issues."""
        vulnerabilities = []

        try:
            with open(lock_path, 'r', encoding='utf-8') as f:
                content = f.read()
        except IOError:
            return vulnerabilities

        # Parse yarn.lock entries (simplified — yarn.lock is a custom format)
        entries = self._parse_yarn_lock(content)

        missing_integrity_count = 0
        non_standard_registry_entries = []
        git_dependency_entries = []

        for entry_name, entry_data in entries.items():
            resolved = entry_data.get('resolved', '')
            integrity = entry_data.get('integrity', '')

            if resolved and not integrity:
                missing_integrity_count += 1

            if resolved and not any(reg in resolved for reg in TRUSTED_REGISTRIES):
                if resolved.startswith('http'):
                    non_standard_registry_entries.append((entry_name, resolved))

            if resolved and (
                resolved.startswith('git+') or
                resolved.startswith('git://') or
                ('github.com' in resolved and not resolved.startswith('http'))
            ):
                git_dependency_entries.append((entry_name, resolved))

        if missing_integrity_count > 0:
            vulnerabilities.append(self.create_vulnerability(
                title=f"Yarn lockfile missing integrity hashes ({missing_integrity_count} packages)",
                description=(
                    f"{missing_integrity_count} package(s) in yarn.lock are missing integrity checksums."
                ),
                severity='medium',
                confidence='high',
                vuln_type='lockfile_integrity',
                file_path=str(lock_path),
                fix="Run 'yarn install' with a modern Yarn version to regenerate integrity hashes.",
            ))

        for entry_name, resolved in non_standard_registry_entries:
            vulnerabilities.append(self.create_vulnerability(
                title=f"Non-standard registry in yarn.lock: {entry_name}",
                description=(
                    f"Entry '{entry_name}' resolves from a non-standard registry: {resolved[:120]}"
                ),
                severity='high',
                confidence='medium',
                vuln_type='lockfile_registry_mismatch',
                file_path=str(lock_path),
                fix="Verify the registry source is trusted.",
                metadata={'entry_name': entry_name, 'resolved_url': resolved}
            ))

        for entry_name, resolved in git_dependency_entries:
            vulnerabilities.append(self.create_vulnerability(
                title=f"Git dependency in yarn.lock: {entry_name}",
                description=(
                    f"Entry '{entry_name}' resolves from git: {resolved[:120]}"
                ),
                severity='medium',
                confidence='high',
                vuln_type='lockfile_git_dependency',
                file_path=str(lock_path),
                fix="Pin to a specific commit hash or publish to a registry.",
                metadata={'entry_name': entry_name, 'resolved_url': resolved}
            ))

        return vulnerabilities

    def _scan_dep_graph(self, target_path: Path) -> List[Vulnerability]:
        """Analyze the dependency graph for transitive risks."""
        vulnerabilities = []
        try:
            analyzer = DepGraphAnalyzer()
            result = analyzer.analyze(target_path)
        except Exception:
            return vulnerabilities

        if not result:
            return vulnerabilities

        for risk in result.risks:
            if risk.risk_score < 0.2:
                continue  # Skip low-risk noise

            vulnerabilities.append(self.create_vulnerability(
                title=f"Risky dependency: {risk.name}@{risk.version}",
                description=(
                    f"Package '{risk.name}' (v{risk.version}, depth {risk.depth}) "
                    f"has risk factors: {'; '.join(risk.risk_factors)}"
                ),
                severity=risk.severity,
                confidence='high' if risk.risk_score >= 0.7 else 'medium',
                vuln_type='malicious_package' if risk.risk_score >= 0.7 else 'vulnerable_dependency',
                fix=f"Review '{risk.name}' and its risk factors. Consider replacing with a vetted alternative.",
                metadata={
                    'package_name': risk.name,
                    'version': risk.version,
                    'depth': risk.depth,
                    'risk_score': risk.risk_score,
                    'risk_factors': risk.risk_factors,
                    'total_packages': result.total_packages,
                    'max_depth': result.max_depth,
                }
            ))

        return vulnerabilities

    def _parse_yarn_lock(self, content: str) -> Dict[str, Dict[str, str]]:
        """Simple parser for yarn.lock files."""
        entries: Dict[str, Dict[str, str]] = {}
        current_entry = None
        current_data: Dict[str, str] = {}

        for line in content.splitlines():
            stripped = line.strip()

            # Skip comments and empty lines
            if not stripped or stripped.startswith('#'):
                continue

            # Entry header (not indented, ends with colon)
            if not line.startswith(' ') and not line.startswith('\t') and stripped.endswith(':'):
                # Save previous entry
                if current_entry is not None:
                    entries[current_entry] = current_data
                current_entry = stripped.rstrip(':').strip('"')
                current_data = {}
            elif current_entry is not None and (line.startswith('  ') or line.startswith('\t')):
                # Key-value pair inside an entry
                if ' ' in stripped:
                    key, _, value = stripped.partition(' ')
                    current_data[key.strip()] = value.strip().strip('"')

        # Save last entry
        if current_entry is not None:
            entries[current_entry] = current_data

        return entries
