"""
Dependencies Security Module

Scans package dependencies for known vulnerabilities and security issues.
"""

import json
import subprocess
import asyncio
import aiohttp
from pathlib import Path
from typing import List, Dict, Any, Optional
import re

from .base import BaseModule
from ..vulnerability import Vulnerability

class DependenciesModule(BaseModule):
    """Module for scanning package dependencies."""
    
    def __init__(self, config, vuln_id_generator):
        super().__init__(config, vuln_id_generator)
        self.package_files = {
            'nodejs': ['package.json', 'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml'],
            'python': ['requirements.txt', 'Pipfile', 'Pipfile.lock', 'pyproject.toml', 'setup.py'],
            'php': ['composer.json', 'composer.lock'],
            'ruby': ['Gemfile', 'Gemfile.lock']
        }
        
        # Known vulnerable package patterns
        self.vulnerable_patterns = {
            'typosquatting': [
                'react-dom-router',  # should be react-router-dom
                'express-js',        # should be express
                'loadash',          # should be lodash
                'colours',          # should be colors
                'cross-env-shell',  # malicious variant of cross-env
            ],
            'deprecated': [
                'request',          # deprecated HTTP library
                'moment',           # deprecated date library
                'bower',            # deprecated package manager
            ]
        }
    
    def should_run(self, mode: str) -> bool:
        """Dependencies module runs in static and full modes."""
        return mode in ['static', 'full']
    
    async def scan(self, target: str) -> List[Vulnerability]:
        """Scan package dependencies for vulnerabilities."""
        vulnerabilities = []
        
        if target.startswith(('http://', 'https://')):
            return await self.scan_url(target)
        
        target_path = Path(target)
        if not target_path.exists():
            return vulnerabilities
        
        # Scan Node.js dependencies
        nodejs_vulns = await self._scan_nodejs_dependencies(target_path)
        vulnerabilities.extend(nodejs_vulns)
        
        # Scan Python dependencies
        python_vulns = await self._scan_python_dependencies(target_path)
        vulnerabilities.extend(python_vulns)
        
        # Scan for general dependency issues
        general_vulns = await self._scan_general_dependency_issues(target_path)
        vulnerabilities.extend(general_vulns)
        
        return vulnerabilities
    
    async def _scan_nodejs_dependencies(self, target_path: Path) -> List[Vulnerability]:
        """Scan Node.js dependencies for vulnerabilities."""
        vulnerabilities = []
        
        package_json_path = target_path / 'package.json'
        if not package_json_path.exists():
            return vulnerabilities
        
        try:
            with open(package_json_path, 'r', encoding='utf-8') as f:
                package_data = json.load(f)
            
            # Run npm audit if available
            audit_vulns = await self._run_npm_audit(target_path)
            vulnerabilities.extend(audit_vulns)
            
            # Check for outdated packages
            outdated_vulns = await self._check_outdated_nodejs_packages(package_data, package_json_path)
            vulnerabilities.extend(outdated_vulns)
            
            # Check for suspicious packages
            suspicious_vulns = await self._check_suspicious_nodejs_packages(package_data, package_json_path)
            vulnerabilities.extend(suspicious_vulns)
            
            # Check for development dependencies in production
            prod_vulns = await self._check_production_dependencies(package_data, package_json_path)
            vulnerabilities.extend(prod_vulns)
            
            # Check for version pinning issues
            pinning_vulns = await self._check_version_pinning(package_data, package_json_path)
            vulnerabilities.extend(pinning_vulns)
            
        except (json.JSONDecodeError, IOError) as e:
            if self.config.verbose:
                print(f"Error reading package.json: {e}")
        
        return vulnerabilities
    
    async def _run_npm_audit(self, target_path: Path) -> List[Vulnerability]:
        """Run npm audit to check for vulnerabilities."""
        vulnerabilities = []
        
        try:
            # Run npm audit with JSON output
            result = subprocess.run(
                ['npm', 'audit', '--json', '--audit-level=low'],
                cwd=target_path,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.stdout:
                try:
                    audit_data = json.loads(result.stdout)
                    
                    # Handle new npm audit format (npm 7+)
                    if 'vulnerabilities' in audit_data:
                        for pkg_name, vuln_info in audit_data['vulnerabilities'].items():
                            severity = self._map_npm_severity(vuln_info.get('severity', 'unknown'))
                            
                            vulnerabilities.append(self.create_vulnerability(
                                title=f"Vulnerable Package: {pkg_name}",
                                description=f"Package {pkg_name} has {vuln_info.get('severity', 'unknown')} severity vulnerabilities",
                                severity=severity,
                                vuln_type="vulnerable_dependency",
                                fix=f"Update {pkg_name} to a secure version: npm update {pkg_name}",
                                reference="https://npmjs.com/advisories",
                                metadata={
                                    'package_name': pkg_name,
                                    'via': vuln_info.get('via', []),
                                    'effects': vuln_info.get('effects', []),
                                    'range': vuln_info.get('range', 'unknown')
                                }
                            ))
                    
                    # Handle legacy npm audit format (npm 6)
                    elif 'advisories' in audit_data:
                        for advisory_id, advisory in audit_data['advisories'].items():
                            severity = self._map_npm_severity(advisory.get('severity', 'unknown'))
                            
                            vulnerabilities.append(self.create_vulnerability(
                                title=f"Vulnerable Package: {advisory.get('module_name', 'unknown')}",
                                description=advisory.get('title', 'Known security vulnerability'),
                                severity=severity,
                                vuln_type="vulnerable_dependency",
                                fix=f"Update to version {advisory.get('patched_versions', 'latest')}",
                                reference=advisory.get('url', 'https://npmjs.com/advisories'),
                                metadata={
                                    'advisory_id': advisory_id,
                                    'package_name': advisory.get('module_name'),
                                    'vulnerable_versions': advisory.get('vulnerable_versions'),
                                    'patched_versions': advisory.get('patched_versions')
                                }
                            ))
                
                except json.JSONDecodeError:
                    if self.config.verbose:
                        print("Failed to parse npm audit JSON output")
        
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
            if self.config.verbose:
                print("npm audit failed or npm not available")
        
        return vulnerabilities
    
    async def _check_outdated_nodejs_packages(self, package_data: Dict, package_json_path: Path) -> List[Vulnerability]:
        """Check for outdated Node.js packages."""
        vulnerabilities = []
        
        dependencies = {
            **package_data.get('dependencies', {}),
            **package_data.get('devDependencies', {})
        }
        
        for package_name, version_spec in dependencies.items():
            # Skip if version is already flexible
            if any(prefix in version_spec for prefix in ['^', '~', '>=', '*']):
                continue
            
            # Check for very old versions (simplified heuristic)
            if self._is_version_very_old(version_spec):
                vulnerabilities.append(self.create_vulnerability(
                    title=f"Potentially Outdated Package: {package_name}",
                    description=f"Package {package_name} appears to be using an old version ({version_spec})",
                    severity="low",
                    vuln_type="outdated_dependency",
                    file_path=str(package_json_path),
                    fix=f"Update {package_name} to the latest version: npm update {package_name}",
                    metadata={
                        'package_name': package_name,
                        'current_version': version_spec
                    }
                ))
        
        return vulnerabilities
    
    async def _check_suspicious_nodejs_packages(self, package_data: Dict, package_json_path: Path) -> List[Vulnerability]:
        """Check for suspicious or typosquatted packages."""
        vulnerabilities = []
        
        dependencies = {
            **package_data.get('dependencies', {}),
            **package_data.get('devDependencies', {})
        }
        
        for package_name in dependencies:
            # Check against known typosquatted packages
            if package_name in self.vulnerable_patterns['typosquatting']:
                vulnerabilities.append(self.create_vulnerability(
                    title=f"Suspicious Package: {package_name}",
                    description=f"Package {package_name} may be a typosquatted version of a legitimate package",
                    severity="high",
                    vuln_type="typosquatting",
                    file_path=str(package_json_path),
                    fix=f"Verify {package_name} is the correct package and replace if necessary",
                    metadata={'package_name': package_name}
                ))
            
            # Check against deprecated packages
            if package_name in self.vulnerable_patterns['deprecated']:
                vulnerabilities.append(self.create_vulnerability(
                    title=f"Deprecated Package: {package_name}",
                    description=f"Package {package_name} is deprecated and should be replaced",
                    severity="medium",
                    vuln_type="outdated_dependency",
                    file_path=str(package_json_path),
                    fix=f"Replace {package_name} with a maintained alternative",
                    metadata={'package_name': package_name}
                ))
            
            # Check for packages with suspicious names
            if self._is_package_name_suspicious(package_name):
                vulnerabilities.append(self.create_vulnerability(
                    title=f"Potentially Suspicious Package Name: {package_name}",
                    description=f"Package {package_name} has a name that may indicate malicious intent",
                    severity="medium",
                    vuln_type="suspicious_name",
                    file_path=str(package_json_path),
                    fix=f"Verify the legitimacy of {package_name} package",
                    metadata={'package_name': package_name}
                ))
        
        return vulnerabilities
    
    async def _check_production_dependencies(self, package_data: Dict, package_json_path: Path) -> List[Vulnerability]:
        """Check for development dependencies in production."""
        vulnerabilities = []
        
        if 'dependencies' not in package_data:
            return vulnerabilities
        
        dev_only_packages = [
            'nodemon', 'webpack-dev-server', 'webpack-dev-middleware',
            'hot-reload', 'live-reload', 'browser-sync', 'concurrently',
            '@types/', 'eslint', 'prettier', 'jest', 'cypress', 'mocha',
            'chai', 'sinon', 'nyc', 'babel', '@babel/', 'typescript'
        ]
        
        for dep_name in package_data['dependencies']:
            if any(dev_pkg in dep_name for dev_pkg in dev_only_packages):
                vulnerabilities.append(self.create_vulnerability(
                    title="Development Dependency in Production",
                    description=f"Development package '{dep_name}' found in production dependencies",
                    severity="medium",
                    vuln_type="dev_in_prod",
                    file_path=str(package_json_path),
                    fix=f"Move {dep_name} to devDependencies",
                    metadata={
                        'package_name': dep_name,
                        'version': package_data['dependencies'][dep_name]
                    }
                ))
        
        return vulnerabilities
    
    async def _check_version_pinning(self, package_data: Dict, package_json_path: Path) -> List[Vulnerability]:
        """Check for version pinning issues."""
        vulnerabilities = []
        
        dependencies = package_data.get('dependencies', {})
        
        # Count unpinned versions
        unpinned_count = 0
        total_count = len(dependencies)
        
        for package_name, version_spec in dependencies.items():
            if version_spec.startswith('*') or version_spec == 'latest':
                vulnerabilities.append(self.create_vulnerability(
                    title=f"Unpinned Dependency Version: {package_name}",
                    description=f"Package {package_name} uses wildcard or 'latest' version which may cause instability",
                    severity="low",
                    vuln_type="outdated_dependency",
                    file_path=str(package_json_path),
                    fix=f"Pin {package_name} to a specific version range",
                    metadata={
                        'package_name': package_name,
                        'version_spec': version_spec
                    }
                ))
                unpinned_count += 1
        
        # Warn if too many dependencies are unpinned
        if total_count > 0 and (unpinned_count / total_count) > 0.3:
            vulnerabilities.append(self.create_vulnerability(
                title="Too Many Unpinned Dependencies",
                description=f"{unpinned_count} out of {total_count} dependencies are not properly pinned",
                severity="medium",
                vuln_type="outdated_dependency",
                file_path=str(package_json_path),
                fix="Review and pin dependency versions for better stability"
            ))
        
        return vulnerabilities
    
    async def _scan_python_dependencies(self, target_path: Path) -> List[Vulnerability]:
        """Scan Python dependencies for vulnerabilities."""
        vulnerabilities = []
        
        # Check requirements.txt
        requirements_path = target_path / 'requirements.txt'
        if requirements_path.exists():
            req_vulns = await self._scan_requirements_txt(requirements_path)
            vulnerabilities.extend(req_vulns)
        
        # Check Pipfile
        pipfile_path = target_path / 'Pipfile'
        if pipfile_path.exists():
            pipfile_vulns = await self._scan_pipfile(pipfile_path)
            vulnerabilities.extend(pipfile_vulns)
        
        # Check pyproject.toml
        pyproject_path = target_path / 'pyproject.toml'
        if pyproject_path.exists():
            pyproject_vulns = await self._scan_pyproject_toml(pyproject_path)
            vulnerabilities.extend(pyproject_vulns)
        
        # Run safety check if available
        safety_vulns = await self._run_safety_check(target_path)
        vulnerabilities.extend(safety_vulns)
        
        return vulnerabilities
    
    async def _scan_requirements_txt(self, requirements_path: Path) -> List[Vulnerability]:
        """Scan requirements.txt for issues."""
        vulnerabilities = []
        
        try:
            with open(requirements_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            for line_num, line in enumerate(lines, 1):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                # Parse package specification
                package_spec = self._parse_python_package_spec(line)
                if not package_spec:
                    continue
                
                package_name, version_spec, operators = package_spec
                
                # Check for unpinned versions
                if not operators or all(op in ['>=', '>'] for op in operators):
                    vulnerabilities.append(self.create_vulnerability(
                        title=f"Unpinned Python Dependency: {package_name}",
                        description=f"Package {package_name} version is not pinned, which may lead to instability",
                        severity="low",
                        vuln_type="outdated_dependency",
                        file_path=str(requirements_path),
                        line_number=line_num,
                        code_snippet=line,
                        fix=f"Pin {package_name} to a specific version using == operator",
                        metadata={
                            'package_name': package_name,
                            'version_spec': version_spec
                        }
                    ))
                
                # Check for insecure package sources
                if line.startswith('-i ') and 'http://' in line:
                    vulnerabilities.append(self.create_vulnerability(
                        title="Insecure Package Index",
                        description="Using HTTP instead of HTTPS for package index",
                        severity="medium",
                        vuln_type="insecure_configuration",
                        file_path=str(requirements_path),
                        line_number=line_num,
                        code_snippet=line,
                        fix="Use HTTPS URLs for package indexes"
                    ))
        
        except IOError as e:
            if self.config.verbose:
                print(f"Error reading requirements.txt: {e}")
        
        return vulnerabilities
    
    async def _scan_pipfile(self, pipfile_path: Path) -> List[Vulnerability]:
        """Scan Pipfile for issues."""
        vulnerabilities = []
        
        try:
            with open(pipfile_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Check for allow_prereleases
            if 'allow_prereleases = true' in content:
                vulnerabilities.append(self.create_vulnerability(
                    title="Prerelease Packages Allowed",
                    description="Pipfile allows prerelease packages which may be unstable",
                    severity="low",
                    vuln_type="allow_prereleases",
                    file_path=str(pipfile_path),
                    fix="Consider disabling prereleases for production: allow_prereleases = false"
                ))
            
            # Check for insecure package sources
            if re.search(r'url\s*=\s*[\'"]http://', content):
                vulnerabilities.append(self.create_vulnerability(
                    title="Insecure Package Source in Pipfile",
                    description="Pipfile contains HTTP URLs for package sources",
                    severity="medium",
                    vuln_type="insecure_source",
                    file_path=str(pipfile_path),
                    fix="Use HTTPS URLs for all package sources"
                ))
        
        except IOError as e:
            if self.config.verbose:
                print(f"Error reading Pipfile: {e}")
        
        return vulnerabilities
    
    async def _scan_pyproject_toml(self, pyproject_path: Path) -> List[Vulnerability]:
        """Scan pyproject.toml for issues."""
        vulnerabilities = []
        
        try:
            import tomli
            
            with open(pyproject_path, 'rb') as f:
                data = tomli.load(f)
            
            # Check for development dependencies in main dependencies
            if 'project' in data and 'dependencies' in data['project']:
                dev_indicators = ['test', 'dev', 'debug', 'mock']
                
                for dep in data['project']['dependencies']:
                    if any(indicator in dep.lower() for indicator in dev_indicators):
                        vulnerabilities.append(self.create_vulnerability(
                            title="Potential Development Dependency in Production",
                            description=f"Dependency '{dep}' may be a development-only package",
                            severity="low",
                            vuln_type="dev_in_prod_python",
                            file_path=str(pyproject_path),
                            fix="Move development dependencies to optional-dependencies or dev group"
                        ))
        
        except ImportError:
            if self.config.verbose:
                print("tomli not available, skipping pyproject.toml analysis")
        except Exception as e:
            if self.config.verbose:
                print(f"Error reading pyproject.toml: {e}")
        
        return vulnerabilities
    
    async def _run_safety_check(self, target_path: Path) -> List[Vulnerability]:
        """Run safety check for Python vulnerabilities."""
        vulnerabilities = []
        
        try:
            result = subprocess.run(
                ['safety', 'check', '--json'],
                cwd=target_path,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.stdout:
                try:
                    safety_data = json.loads(result.stdout)
                    
                    for vuln in safety_data:
                        vulnerabilities.append(self.create_vulnerability(
                            title=f"Vulnerable Python Package: {vuln.get('package', 'Unknown')}",
                            description=vuln.get('vulnerability', 'Known security vulnerability'),
                            severity=self._map_safety_severity(vuln.get('severity', 'unknown')),
                            vuln_type="vulnerable_dependency",
                            fix=f"Update to version {vuln.get('fixed_version', 'latest')} or higher",
                            reference="https://pyup.io/safety/",
                            metadata={
                                'package_name': vuln.get('package'),
                                'installed_version': vuln.get('installed_version'),
                                'vulnerability_id': vuln.get('id')
                            }
                        ))
                
                except json.JSONDecodeError:
                    if self.config.verbose:
                        print("Failed to parse safety check JSON output")
        
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
            if self.config.verbose:
                print("safety check failed or safety not available")
        
        return vulnerabilities
    
    async def _scan_general_dependency_issues(self, target_path: Path) -> List[Vulnerability]:
        """Scan for general dependency management issues."""
        vulnerabilities = []
        
        # Check for multiple package managers
        package_manager_files = {
            'npm': ['package-lock.json'],
            'yarn': ['yarn.lock'],
            'pnpm': ['pnpm-lock.yaml'],
            'pip': ['requirements.txt'],
            'pipenv': ['Pipfile.lock'],
            'poetry': ['poetry.lock']
        }
        
        found_managers = []
        for manager, files in package_manager_files.items():
            if any((target_path / file).exists() for file in files):
                found_managers.append(manager)
        
        # Warn about multiple Node.js package managers
        node_managers = [m for m in found_managers if m in ['npm', 'yarn', 'pnpm']]
        if len(node_managers) > 1:
            vulnerabilities.append(self.create_vulnerability(
                title="Multiple Package Managers Detected",
                description=f"Multiple Node.js package managers detected: {', '.join(node_managers)}",
                severity="medium",
                vuln_type="multiple_package_managers",
                fix="Use a single package manager consistently across the project"
            ))
        
        # Check for missing lock files
        if (target_path / 'package.json').exists():
            lock_files = ['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml']
            if not any((target_path / lock_file).exists() for lock_file in lock_files):
                vulnerabilities.append(self.create_vulnerability(
                    title="Missing Package Lock File",
                    description="No package lock file found (package-lock.json, yarn.lock, or pnpm-lock.yaml)",
                    severity="medium",
                    vuln_type="insecure_configuration",
                    fix="Commit the appropriate lock file to ensure reproducible builds"
                ))
        
        return vulnerabilities
    
    def _map_npm_severity(self, severity: str) -> str:
        """Map npm audit severity to our severity levels."""
        severity_map = {
            'critical': 'critical',
            'high': 'high',
            'moderate': 'medium',
            'low': 'low',
            'info': 'info'
        }
        return severity_map.get(severity.lower(), 'medium')
    
    def _map_safety_severity(self, severity: str) -> str:
        """Map safety severity to our severity levels."""
        # Safety doesn't provide severity levels consistently
        return 'high'
    
    def _is_version_very_old(self, version_spec: str) -> bool:
        """Check if a version appears to be very old."""
        # Remove common prefixes
        version = version_spec.lstrip('^~>=<')
        
        # Simple heuristic: major version 0 or 1 might be old
        if version.startswith(('0.', '1.')):
            return True
        
        return False
    
    def _is_package_name_suspicious(self, package_name: str) -> bool:
        """Check if package name appears suspicious."""
        suspicious_patterns = [
            r'.*-js$',  # Many typosquats end with -js
            r'.*\.js$',  # Or .js
            r'[0-9]+$',  # Ending with numbers
            r'^[a-z]{1,3}$',  # Very short names
        ]
        
        for pattern in suspicious_patterns:
            if re.match(pattern, package_name):
                return True
        
        return False
    
    def _parse_python_package_spec(self, line: str) -> Optional[tuple]:
        """Parse a Python package specification line."""
        # Simple parser for package specifications
        line = line.strip()
        
        # Skip URLs and complex specifications
        if any(prefix in line for prefix in ['http://', 'https://', 'git+', '-e ']):
            return None
        
        # Extract package name and version specification
        operators = ['==', '>=', '<=', '>', '<', '~=', '!=']
        
        for op in operators:
            if op in line:
                parts = line.split(op, 1)
                if len(parts) == 2:
                    package_name = parts[0].strip()
                    version_spec = parts[1].strip()
                    return package_name, version_spec, [op]
        
        # No version specification found
        return line.strip(), None, []
    
    async def scan_url(self, url: str) -> List[Vulnerability]:
        """Scan a URL for dependency-related security issues."""
        vulnerabilities = []
        
        try:
            import aiohttp
            
            # Create session with timeout
            timeout = aiohttp.ClientTimeout(total=10)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                # Test for exposed dependency files
                dependency_endpoints = [
                    '/package.json',
                    '/package-lock.json',
                    '/yarn.lock',
                    '/pnpm-lock.yaml',
                    '/requirements.txt',
                    '/Pipfile',
                    '/Pipfile.lock',
                    '/pyproject.toml',
                    '/composer.json',
                    '/composer.lock',
                    '/Gemfile',
                    '/Gemfile.lock',
                    '/go.mod',
                    '/go.sum',
                    '/pom.xml',
                    '/build.gradle',
                    '/Cargo.toml',
                    '/Cargo.lock'
                ]
                
                for endpoint in dependency_endpoints:
                    test_url = url.rstrip('/') + endpoint
                    try:
                        async with session.get(test_url) as response:
                            if response.status == 200:
                                content = await response.text()
                                
                                # Check if it's actually a dependency file
                                if self._is_dependency_content(content, endpoint):
                                    vulnerabilities.append(self.create_vulnerability(
                                        title=f"Exposed Dependency File: {endpoint}",
                                        description=f"Dependency file {endpoint} is accessible via HTTP",
                                        severity="medium",
                                        vuln_type="information_disclosure",
                                        fix=f"Remove or secure access to {endpoint}",
                                        metadata={
                                            'url': test_url,
                                            'endpoint': endpoint,
                                            'status_code': response.status,
                                            'content_length': len(content)
                                        }
                                    ))
                                    
                                    # Analyze the dependency file for vulnerabilities
                                    dep_vulns = await self._analyze_exposed_dependency_file(content, endpoint, test_url)
                                    vulnerabilities.extend(dep_vulns)
                    except Exception as e:
                        if self.config.verbose:
                            print(f"Error testing {test_url}: {e}")
                        continue
                
                # Test for exposed node_modules directory
                node_modules_vulns = await self._test_node_modules_exposure(session, url)
                vulnerabilities.extend(node_modules_vulns)
                
        except Exception as e:
            if self.config.verbose:
                print(f"Error scanning URL {url}: {e}")
        
        return vulnerabilities
    
    def _is_dependency_content(self, content: str, endpoint: str) -> bool:
        """Check if content appears to be a dependency file."""
        # Skip if content is too short or looks like an error page
        if len(content) < 10:
            return False
        
        # Check for common error page indicators
        error_indicators = ['404', 'not found', 'error', 'page not found', '<html>', '<!doctype']
        if any(indicator in content.lower() for indicator in error_indicators):
            return False
        
        # Check for specific file type indicators
        if endpoint.endswith('.json'):
            try:
                import json
                data = json.loads(content)
                # Check for package.json structure
                if endpoint == '/package.json':
                    return 'name' in data and ('dependencies' in data or 'devDependencies' in data)
                # Check for package-lock.json structure
                elif endpoint == '/package-lock.json':
                    return 'name' in data and 'lockfileVersion' in data
                # Check for composer.json structure
                elif endpoint == '/composer.json':
                    return 'name' in data and ('require' in data or 'require-dev' in data)
                return True
            except:
                return False
        elif endpoint.endswith('.lock'):
            return 'version' in content and ('resolved' in content or 'integrity' in content)
        elif endpoint.endswith('.txt'):
            return '==' in content or '>=' in content or '~=' in content
        elif endpoint.endswith('.toml'):
            return '[' in content and ']' in content and ('dependencies' in content or 'version' in content)
        elif endpoint.endswith('.yaml') or endpoint.endswith('.yml'):
            return ':' in content and ('version' in content or 'dependencies' in content)
        elif endpoint.endswith('.xml'):
            return '<project' in content and ('<dependencies>' in content or '<dependency>' in content)
        elif endpoint.endswith('.gradle'):
            return 'dependencies' in content and '{' in content
        elif endpoint.endswith('.mod'):
            return 'module' in content and 'go' in content
        
        return False
    
    async def _analyze_exposed_dependency_file(self, content: str, endpoint: str, url: str) -> List[Vulnerability]:
        """Analyze an exposed dependency file for security issues."""
        vulnerabilities = []
        
        try:
            if endpoint == '/package.json':
                import json
                package_data = json.loads(content)
                
                # Check for known vulnerable packages
                all_deps = {
                    **package_data.get('dependencies', {}),
                    **package_data.get('devDependencies', {})
                }
                
                # Known malicious/vulnerable packages
                vulnerable_packages = {
                    'event-stream': 'Known malicious package that was compromised',
                    'eslint-scope': 'Package was compromised and contained malicious code',
                    'flatmap-stream': 'Malicious dependency that was part of event-stream attack',
                    'getcookies': 'Malicious package with typosquatting',
                    'crossenv': 'Malicious package (typosquat of cross-env)',
                    'cross-env.js': 'Malicious package (typosquat of cross-env)'
                }
                
                for pkg_name, reason in vulnerable_packages.items():
                    if pkg_name in all_deps:
                        vulnerabilities.append(self.create_vulnerability(
                            title=f"Known Malicious Package: {pkg_name}",
                            description=f"Package {pkg_name} is known to be malicious: {reason}",
                            severity="critical",
                            vuln_type="malicious_dependency",
                            fix=f"Remove {pkg_name} immediately and audit your system",
                            metadata={
                                'package_name': pkg_name,
                                'reason': reason,
                                'url': url
                            }
                        ))
                
                # Check for typosquatted packages
                typosquat_vulns = await self._check_typosquatting(all_deps, url)
                vulnerabilities.extend(typosquat_vulns)
                
        except Exception as e:
            if self.config.verbose:
                print(f"Error analyzing dependency file {endpoint}: {e}")
        
        return vulnerabilities
    
    async def _check_typosquatting(self, dependencies: Dict[str, str], url: str) -> List[Vulnerability]:
        """Check for typosquatted packages."""
        vulnerabilities = []
        
        # Common typosquatting patterns
        typosquat_patterns = {
            'react-dom-router': 'react-router-dom',
            'express-js': 'express',
            'loadash': 'lodash',
            'colours': 'colors',
            'cross-env-shell': 'cross-env',
            'crossenv': 'cross-env',
            'cross-env.js': 'cross-env',
            'getcookies': 'js-cookie',
            'momentjs': 'moment',
            'jquery-ui': 'jquery-ui-dist'
        }
        
        for pkg_name in dependencies:
            if pkg_name in typosquat_patterns:
                correct_package = typosquat_patterns[pkg_name]
                vulnerabilities.append(self.create_vulnerability(
                    title=f"Potential Typosquatting: {pkg_name}",
                    description=f"Package {pkg_name} may be a typosquatted version of {correct_package}",
                    severity="high",
                    vuln_type="typosquatting",
                    fix=f"Verify {pkg_name} is legitimate or replace with {correct_package}",
                    metadata={
                        'package_name': pkg_name,
                        'suggested_package': correct_package,
                        'url': url
                    }
                ))
        
        return vulnerabilities
    
    async def _test_node_modules_exposure(self, session, url: str) -> List[Vulnerability]:
        """Test for exposed node_modules directory."""
        vulnerabilities = []
        
        # Test for node_modules directory listing
        test_url = url.rstrip('/') + '/node_modules/'
        try:
            async with session.get(test_url) as response:
                if response.status == 200:
                    content = await response.text()
                    
                    # Check if it's a directory listing
                    if self._is_directory_listing(content):
                        vulnerabilities.append(self.create_vulnerability(
                            title="Exposed node_modules Directory",
                            description="node_modules directory is accessible via HTTP",
                            severity="high",
                            vuln_type="information_disclosure",
                            fix="Disable directory listing and secure access to node_modules",
                            metadata={
                                'url': test_url,
                                'status_code': response.status
                            }
                        ))
                    
                    # Test for specific vulnerable packages in node_modules
                    vulnerable_package_tests = [
                        '/node_modules/event-stream/',
                        '/node_modules/eslint-scope/',
                        '/node_modules/flatmap-stream/',
                        '/node_modules/getcookies/',
                        '/node_modules/crossenv/'
                    ]
                    
                    for test_pkg in vulnerable_package_tests:
                        pkg_url = url.rstrip('/') + test_pkg
                        try:
                            async with session.get(pkg_url) as pkg_response:
                                if pkg_response.status == 200:
                                    pkg_name = test_pkg.split('/')[-2]
                                    vulnerabilities.append(self.create_vulnerability(
                                        title=f"Exposed Vulnerable Package: {pkg_name}",
                                        description=f"Known vulnerable package {pkg_name} is accessible via HTTP",
                                        severity="critical",
                                        vuln_type="malicious_dependency",
                                        fix=f"Remove {pkg_name} and audit your dependencies",
                                        metadata={
                                            'url': pkg_url,
                                            'package_name': pkg_name,
                                            'status_code': pkg_response.status
                                        }
                                    ))
                        except Exception:
                            continue
        except Exception:
            pass
        
        return vulnerabilities
    
    def _is_directory_listing(self, content: str) -> bool:
        """Check if content appears to be a directory listing."""
        # Common directory listing indicators
        listing_indicators = [
            'Index of',
            'Directory listing',
            'Parent Directory',
            '<a href="../">',
            'Last modified',
            'Size</th>',
            'Name</th>',
            'Apache/',
            'nginx/',
            'Microsoft-IIS/'
        ]
        
        return any(indicator in content for indicator in listing_indicators)