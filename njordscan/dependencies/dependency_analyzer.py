"""
Advanced Dependency Analyzer

Comprehensive dependency analysis including dependency graph construction,
transitive dependency resolution, and security risk assessment.
"""

import re
import json
import hashlib
import time
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

class DependencyType(Enum):
    """Types of dependencies."""
    DIRECT = "direct"
    TRANSITIVE = "transitive"
    DEV = "dev"
    PEER = "peer"
    OPTIONAL = "optional"
    BUNDLED = "bundled"

class PackageManager(Enum):
    """Supported package managers."""
    NPM = "npm"
    YARN = "yarn"
    PIP = "pip"
    PIPENV = "pipenv"
    POETRY = "poetry"
    MAVEN = "maven"
    GRADLE = "gradle"
    COMPOSER = "composer"
    NUGET = "nuget"
    CARGO = "cargo"
    GO_MOD = "go_mod"
    BUNDLER = "bundler"

@dataclass
class DependencyInfo:
    """Comprehensive dependency information."""
    name: str
    version: str
    package_manager: PackageManager
    dependency_type: DependencyType
    
    # Package metadata
    description: str = ""
    homepage: str = ""
    repository: str = ""
    license: str = ""
    author: str = ""
    
    # Version information
    latest_version: str = ""
    is_outdated: bool = False
    version_behind: int = 0
    
    # Security information
    known_vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    security_score: float = 0.0
    risk_level: str = "unknown"
    
    # Supply chain information
    maintainers: List[str] = field(default_factory=list)
    download_count: int = 0
    age_days: int = 0
    last_updated: str = ""
    
    # Dependency relationships
    parent_dependencies: List[str] = field(default_factory=list)
    child_dependencies: List[str] = field(default_factory=list)
    
    # File information
    file_path: str = ""
    file_hash: str = ""
    file_size: int = 0
    
    # Analysis metadata
    analyzed_time: float = field(default_factory=time.time)

@dataclass
class DependencyGraph:
    """Dependency graph representation."""
    root_dependencies: List[DependencyInfo]
    all_dependencies: Dict[str, DependencyInfo]
    dependency_tree: Dict[str, List[str]]
    reverse_tree: Dict[str, List[str]]
    
    # Graph statistics
    total_dependencies: int = 0
    direct_dependencies: int = 0
    transitive_dependencies: int = 0
    max_depth: int = 0
    
    # Risk metrics
    high_risk_dependencies: int = 0
    outdated_dependencies: int = 0
    vulnerable_dependencies: int = 0

class DependencyAnalyzer:
    """Advanced dependency analyzer for comprehensive security assessment."""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        
        # Analysis configuration
        self.analysis_config = {
            'max_depth': self.config.get('max_depth', 10),
            'include_dev_dependencies': self.config.get('include_dev_dependencies', True),
            'enable_transitive_analysis': self.config.get('enable_transitive_analysis', True),
            'vulnerability_check': self.config.get('vulnerability_check', True),
            'license_check': self.config.get('license_check', True),
            'outdated_check': self.config.get('outdated_check', True),
            'supply_chain_analysis': self.config.get('supply_chain_analysis', True)
        }
        
        # Package manager configurations
        self.package_managers = {
            PackageManager.NPM: {
                'manifest_files': ['package.json'],
                'lock_files': ['package-lock.json'],
                'dependency_dirs': ['node_modules'],
                'parser': self._parse_npm_dependencies
            },
            PackageManager.PIP: {
                'manifest_files': ['requirements.txt', 'setup.py', 'pyproject.toml'],
                'lock_files': ['Pipfile.lock', 'poetry.lock'],
                'dependency_dirs': ['site-packages'],
                'parser': self._parse_pip_dependencies
            },
            PackageManager.MAVEN: {
                'manifest_files': ['pom.xml'],
                'lock_files': [],
                'dependency_dirs': ['target/dependency'],
                'parser': self._parse_maven_dependencies
            },
            PackageManager.CARGO: {
                'manifest_files': ['Cargo.toml'],
                'lock_files': ['Cargo.lock'],
                'dependency_dirs': ['target'],
                'parser': self._parse_cargo_dependencies
            },
            PackageManager.GO_MOD: {
                'manifest_files': ['go.mod'],
                'lock_files': ['go.sum'],
                'dependency_dirs': ['vendor'],
                'parser': self._parse_go_dependencies
            }
        }
        
        # Vulnerability databases (would integrate with real DBs)
        self.vulnerability_sources = [
            'npm_audit',
            'snyk',
            'osv',
            'nvd',
            'github_advisories',
            'sonatype_ossindex'
        ]
        
        # Statistics
        self.stats = {
            'projects_analyzed': 0,
            'dependencies_analyzed': 0,
            'vulnerabilities_found': 0,
            'outdated_packages_found': 0,
            'high_risk_packages': 0
        }
    
    async def analyze_project_dependencies(self, project_path: Path) -> DependencyGraph:
        """Analyze all dependencies in a project."""
        
        logger.info(f"Starting dependency analysis for: {project_path}")
        
        # Detect package managers in project
        detected_managers = await self._detect_package_managers(project_path)
        
        if not detected_managers:
            logger.warning("No supported package managers detected")
            return self._create_empty_graph()
        
        # Analyze dependencies for each package manager
        all_dependencies = {}
        root_dependencies = []
        
        for manager in detected_managers:
            try:
                manager_deps = await self._analyze_package_manager_dependencies(
                    project_path, manager
                )
                
                for dep_key, dep_info in manager_deps.items():
                    if dep_key not in all_dependencies:
                        all_dependencies[dep_key] = dep_info
                        if dep_info.dependency_type == DependencyType.DIRECT:
                            root_dependencies.append(dep_info)
                
            except Exception as e:
                logger.error(f"Failed to analyze {manager.value} dependencies: {str(e)}")
        
        # Build dependency graph
        dependency_graph = await self._build_dependency_graph(all_dependencies, root_dependencies)
        
        # Perform additional analysis
        if self.analysis_config['vulnerability_check']:
            await self._analyze_vulnerabilities(dependency_graph)
        
        if self.analysis_config['outdated_check']:
            await self._analyze_outdated_packages(dependency_graph)
        
        if self.analysis_config['supply_chain_analysis']:
            await self._analyze_supply_chain_risks(dependency_graph)
        
        # Update statistics
        self._update_statistics(dependency_graph)
        
        logger.info(f"Dependency analysis completed: {dependency_graph.total_dependencies} packages analyzed")
        
        return dependency_graph
    
    async def _detect_package_managers(self, project_path: Path) -> List[PackageManager]:
        """Detect package managers used in the project."""
        
        detected_managers = []
        
        for manager, config in self.package_managers.items():
            for manifest_file in config['manifest_files']:
                if (project_path / manifest_file).exists():
                    detected_managers.append(manager)
                    break
        
        logger.info(f"Detected package managers: {[m.value for m in detected_managers]}")
        
        return detected_managers
    
    async def _analyze_package_manager_dependencies(self, project_path: Path, 
                                                   manager: PackageManager) -> Dict[str, DependencyInfo]:
        """Analyze dependencies for a specific package manager."""
        
        config = self.package_managers[manager]
        parser = config['parser']
        
        dependencies = {}
        
        # Parse manifest files
        for manifest_file in config['manifest_files']:
            manifest_path = project_path / manifest_file
            if manifest_path.exists():
                try:
                    parsed_deps = await parser(manifest_path)
                    dependencies.update(parsed_deps)
                except Exception as e:
                    logger.error(f"Failed to parse {manifest_file}: {str(e)}")
        
        # Parse lock files for more accurate versions
        for lock_file in config['lock_files']:
            lock_path = project_path / lock_file
            if lock_path.exists():
                try:
                    lock_deps = await self._parse_lock_file(lock_path, manager)
                    # Merge lock file information
                    for dep_key, lock_info in lock_deps.items():
                        if dep_key in dependencies:
                            dependencies[dep_key].version = lock_info.version
                        else:
                            dependencies[dep_key] = lock_info
                except Exception as e:
                    logger.error(f"Failed to parse {lock_file}: {str(e)}")
        
        return dependencies
    
    async def _parse_npm_dependencies(self, package_json_path: Path) -> Dict[str, DependencyInfo]:
        """Parse NPM package.json dependencies."""
        
        dependencies = {}
        
        try:
            with open(package_json_path, 'r', encoding='utf-8') as f:
                package_data = json.load(f)
            
            # Parse direct dependencies
            for dep_name, version in package_data.get('dependencies', {}).items():
                dep_info = DependencyInfo(
                    name=dep_name,
                    version=self._clean_version(version),
                    package_manager=PackageManager.NPM,
                    dependency_type=DependencyType.DIRECT,
                    file_path=str(package_json_path)
                )
                dependencies[f"npm:{dep_name}"] = dep_info
            
            # Parse dev dependencies
            if self.analysis_config['include_dev_dependencies']:
                for dep_name, version in package_data.get('devDependencies', {}).items():
                    dep_info = DependencyInfo(
                        name=dep_name,
                        version=self._clean_version(version),
                        package_manager=PackageManager.NPM,
                        dependency_type=DependencyType.DEV,
                        file_path=str(package_json_path)
                    )
                    dependencies[f"npm:{dep_name}"] = dep_info
            
            # Parse peer dependencies
            for dep_name, version in package_data.get('peerDependencies', {}).items():
                dep_info = DependencyInfo(
                    name=dep_name,
                    version=self._clean_version(version),
                    package_manager=PackageManager.NPM,
                    dependency_type=DependencyType.PEER,
                    file_path=str(package_json_path)
                )
                dependencies[f"npm:{dep_name}"] = dep_info
                
        except Exception as e:
            logger.error(f"Error parsing package.json: {str(e)}")
        
        return dependencies
    
    async def _parse_pip_dependencies(self, requirements_path: Path) -> Dict[str, DependencyInfo]:
        """Parse Python requirements.txt dependencies."""
        
        dependencies = {}
        
        try:
            if requirements_path.name == 'requirements.txt':
                with open(requirements_path, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                
                for line in lines:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        # Parse requirement line
                        dep_match = re.match(r'^([a-zA-Z0-9\-_.]+)([>=<~!]*)(.*)', line)
                        if dep_match:
                            dep_name = dep_match.group(1)
                            version_spec = dep_match.group(2) + dep_match.group(3) if dep_match.group(2) else ""
                            
                            dep_info = DependencyInfo(
                                name=dep_name,
                                version=version_spec or "latest",
                                package_manager=PackageManager.PIP,
                                dependency_type=DependencyType.DIRECT,
                                file_path=str(requirements_path)
                            )
                            dependencies[f"pip:{dep_name}"] = dep_info
            
            elif requirements_path.name == 'pyproject.toml':
                # Parse TOML format (simplified)
                content = requirements_path.read_text(encoding='utf-8')
                # This would use a proper TOML parser in real implementation
                dep_matches = re.findall(r'"([^"]+)"\s*=\s*"([^"]*)"', content)
                for dep_name, version in dep_matches:
                    if not dep_name.startswith('['):  # Skip sections
                        dep_info = DependencyInfo(
                            name=dep_name,
                            version=version or "latest",
                            package_manager=PackageManager.PIP,
                            dependency_type=DependencyType.DIRECT,
                            file_path=str(requirements_path)
                        )
                        dependencies[f"pip:{dep_name}"] = dep_info
                        
        except Exception as e:
            logger.error(f"Error parsing Python dependencies: {str(e)}")
        
        return dependencies
    
    async def _parse_maven_dependencies(self, pom_path: Path) -> Dict[str, DependencyInfo]:
        """Parse Maven pom.xml dependencies."""
        
        dependencies = {}
        
        try:
            content = pom_path.read_text(encoding='utf-8')
            
            # Simple XML parsing (would use proper XML parser in real implementation)
            dependency_blocks = re.findall(r'<dependency>(.*?)</dependency>', content, re.DOTALL)
            
            for dep_block in dependency_blocks:
                group_match = re.search(r'<groupId>(.*?)</groupId>', dep_block)
                artifact_match = re.search(r'<artifactId>(.*?)</artifactId>', dep_block)
                version_match = re.search(r'<version>(.*?)</version>', dep_block)
                scope_match = re.search(r'<scope>(.*?)</scope>', dep_block)
                
                if group_match and artifact_match:
                    group_id = group_match.group(1)
                    artifact_id = artifact_match.group(1)
                    version = version_match.group(1) if version_match else "latest"
                    scope = scope_match.group(1) if scope_match else "compile"
                    
                    dep_name = f"{group_id}:{artifact_id}"
                    dep_type = DependencyType.DEV if scope == "test" else DependencyType.DIRECT
                    
                    dep_info = DependencyInfo(
                        name=dep_name,
                        version=version,
                        package_manager=PackageManager.MAVEN,
                        dependency_type=dep_type,
                        file_path=str(pom_path)
                    )
                    dependencies[f"maven:{dep_name}"] = dep_info
                    
        except Exception as e:
            logger.error(f"Error parsing Maven dependencies: {str(e)}")
        
        return dependencies
    
    async def _parse_cargo_dependencies(self, cargo_path: Path) -> Dict[str, DependencyInfo]:
        """Parse Rust Cargo.toml dependencies."""
        
        dependencies = {}
        
        try:
            content = cargo_path.read_text(encoding='utf-8')
            
            # Parse [dependencies] section
            deps_section = re.search(r'\[dependencies\](.*?)(?=\[|\Z)', content, re.DOTALL)
            if deps_section:
                deps_content = deps_section.group(1)
                
                # Parse dependency lines
                dep_lines = re.findall(r'(\w+)\s*=\s*"([^"]*)"', deps_content)
                for dep_name, version in dep_lines:
                    dep_info = DependencyInfo(
                        name=dep_name,
                        version=version,
                        package_manager=PackageManager.CARGO,
                        dependency_type=DependencyType.DIRECT,
                        file_path=str(cargo_path)
                    )
                    dependencies[f"cargo:{dep_name}"] = dep_info
            
            # Parse [dev-dependencies] section
            if self.analysis_config['include_dev_dependencies']:
                dev_deps_section = re.search(r'\[dev-dependencies\](.*?)(?=\[|\Z)', content, re.DOTALL)
                if dev_deps_section:
                    dev_deps_content = dev_deps_section.group(1)
                    
                    dev_dep_lines = re.findall(r'(\w+)\s*=\s*"([^"]*)"', dev_deps_content)
                    for dep_name, version in dev_dep_lines:
                        dep_info = DependencyInfo(
                            name=dep_name,
                            version=version,
                            package_manager=PackageManager.CARGO,
                            dependency_type=DependencyType.DEV,
                            file_path=str(cargo_path)
                        )
                        dependencies[f"cargo:{dep_name}"] = dep_info
                        
        except Exception as e:
            logger.error(f"Error parsing Cargo dependencies: {str(e)}")
        
        return dependencies
    
    async def _parse_go_dependencies(self, go_mod_path: Path) -> Dict[str, DependencyInfo]:
        """Parse Go go.mod dependencies."""
        
        dependencies = {}
        
        try:
            content = go_mod_path.read_text(encoding='utf-8')
            
            # Parse require block
            require_block = re.search(r'require\s*\((.*?)\)', content, re.DOTALL)
            if require_block:
                require_content = require_block.group(1)
                
                # Parse individual requirements
                req_lines = re.findall(r'(\S+)\s+v?([^\s]+)', require_content)
                for module_path, version in req_lines:
                    dep_info = DependencyInfo(
                        name=module_path,
                        version=version,
                        package_manager=PackageManager.GO_MOD,
                        dependency_type=DependencyType.DIRECT,
                        file_path=str(go_mod_path)
                    )
                    dependencies[f"go:{module_path}"] = dep_info
            
            # Parse single-line requires
            single_requires = re.findall(r'require\s+(\S+)\s+v?([^\s]+)', content)
            for module_path, version in single_requires:
                if f"go:{module_path}" not in dependencies:
                    dep_info = DependencyInfo(
                        name=module_path,
                        version=version,
                        package_manager=PackageManager.GO_MOD,
                        dependency_type=DependencyType.DIRECT,
                        file_path=str(go_mod_path)
                    )
                    dependencies[f"go:{module_path}"] = dep_info
                    
        except Exception as e:
            logger.error(f"Error parsing Go dependencies: {str(e)}")
        
        return dependencies
    
    async def _parse_lock_file(self, lock_path: Path, manager: PackageManager) -> Dict[str, DependencyInfo]:
        """Parse lock file for exact dependency versions."""
        
        dependencies = {}
        
        try:
            if manager == PackageManager.NPM and lock_path.name == 'package-lock.json':
                with open(lock_path, 'r', encoding='utf-8') as f:
                    lock_data = json.load(f)
                
                # Parse dependencies from lock file
                for dep_name, dep_info in lock_data.get('dependencies', {}).items():
                    version = dep_info.get('version', 'unknown')
                    
                    dependency = DependencyInfo(
                        name=dep_name,
                        version=version,
                        package_manager=PackageManager.NPM,
                        dependency_type=DependencyType.TRANSITIVE,
                        file_path=str(lock_path)
                    )
                    dependencies[f"npm:{dep_name}"] = dependency
            
            elif manager == PackageManager.CARGO and lock_path.name == 'Cargo.lock':
                content = lock_path.read_text(encoding='utf-8')
                
                # Parse [[package]] blocks
                package_blocks = re.findall(r'\[\[package\]\](.*?)(?=\[\[|\Z)', content, re.DOTALL)
                
                for package_block in package_blocks:
                    name_match = re.search(r'name\s*=\s*"([^"]*)"', package_block)
                    version_match = re.search(r'version\s*=\s*"([^"]*)"', package_block)
                    
                    if name_match and version_match:
                        dep_name = name_match.group(1)
                        version = version_match.group(1)
                        
                        dependency = DependencyInfo(
                            name=dep_name,
                            version=version,
                            package_manager=PackageManager.CARGO,
                            dependency_type=DependencyType.TRANSITIVE,
                            file_path=str(lock_path)
                        )
                        dependencies[f"cargo:{dep_name}"] = dependency
                        
        except Exception as e:
            logger.error(f"Error parsing lock file {lock_path}: {str(e)}")
        
        return dependencies
    
    async def _build_dependency_graph(self, all_dependencies: Dict[str, DependencyInfo], 
                                     root_dependencies: List[DependencyInfo]) -> DependencyGraph:
        """Build dependency graph with relationships."""
        
        # Build dependency tree
        dependency_tree = {}
        reverse_tree = {}
        
        for dep_key, dep_info in all_dependencies.items():
            dependency_tree[dep_key] = []
            reverse_tree[dep_key] = []
        
        # Resolve transitive dependencies (simplified)
        if self.analysis_config['enable_transitive_analysis']:
            await self._resolve_transitive_dependencies(all_dependencies, dependency_tree, reverse_tree)
        
        # Calculate graph statistics
        total_dependencies = len(all_dependencies)
        direct_dependencies = len([d for d in all_dependencies.values() if d.dependency_type == DependencyType.DIRECT])
        transitive_dependencies = total_dependencies - direct_dependencies
        max_depth = self._calculate_max_depth(dependency_tree, root_dependencies)
        
        # Calculate risk metrics
        high_risk_dependencies = len([d for d in all_dependencies.values() if d.risk_level == "high"])
        outdated_dependencies = len([d for d in all_dependencies.values() if d.is_outdated])
        vulnerable_dependencies = len([d for d in all_dependencies.values() if d.known_vulnerabilities])
        
        return DependencyGraph(
            root_dependencies=root_dependencies,
            all_dependencies=all_dependencies,
            dependency_tree=dependency_tree,
            reverse_tree=reverse_tree,
            total_dependencies=total_dependencies,
            direct_dependencies=direct_dependencies,
            transitive_dependencies=transitive_dependencies,
            max_depth=max_depth,
            high_risk_dependencies=high_risk_dependencies,
            outdated_dependencies=outdated_dependencies,
            vulnerable_dependencies=vulnerable_dependencies
        )
    
    async def _resolve_transitive_dependencies(self, all_dependencies: Dict[str, DependencyInfo],
                                              dependency_tree: Dict[str, List[str]],
                                              reverse_tree: Dict[str, List[str]]):
        """Resolve transitive dependency relationships."""
        
        # This would integrate with package manager APIs to resolve transitive deps
        # For now, we'll simulate some relationships
        
        for dep_key, dep_info in all_dependencies.items():
            if dep_info.dependency_type == DependencyType.DIRECT:
                # Simulate finding transitive dependencies
                simulated_children = self._simulate_transitive_deps(dep_info)
                
                for child_key in simulated_children:
                    if child_key in all_dependencies:
                        dependency_tree[dep_key].append(child_key)
                        reverse_tree[child_key].append(dep_key)
                        
                        # Update child dependency info
                        all_dependencies[child_key].parent_dependencies.append(dep_key)
                        dep_info.child_dependencies.append(child_key)
    
    def _simulate_transitive_deps(self, dep_info: DependencyInfo) -> List[str]:
        """Simulate transitive dependency discovery."""
        
        # This would query real package registries
        # For now, return some common transitive dependencies based on package names
        
        common_transitive = {
            'react': ['npm:react-dom', 'npm:prop-types'],
            'express': ['npm:body-parser', 'npm:cookie-parser', 'npm:debug'],
            'lodash': [],
            'axios': ['npm:follow-redirects'],
            'webpack': ['npm:webpack-cli', 'npm:webpack-dev-server']
        }
        
        return common_transitive.get(dep_info.name, [])
    
    async def _analyze_vulnerabilities(self, graph: DependencyGraph):
        """Analyze dependencies for known vulnerabilities."""
        
        logger.info("Analyzing dependencies for vulnerabilities")
        
        for dep_key, dep_info in graph.all_dependencies.items():
            # Simulate vulnerability lookup (would query real databases)
            vulnerabilities = await self._lookup_vulnerabilities(dep_info)
            
            dep_info.known_vulnerabilities = vulnerabilities
            
            if vulnerabilities:
                # Calculate security score based on vulnerabilities
                critical_count = len([v for v in vulnerabilities if v.get('severity') == 'critical'])
                high_count = len([v for v in vulnerabilities if v.get('severity') == 'high'])
                medium_count = len([v for v in vulnerabilities if v.get('severity') == 'medium'])
                
                # Security score (0-100, higher is better)
                dep_info.security_score = max(0, 100 - (critical_count * 30 + high_count * 20 + medium_count * 10))
                
                if critical_count > 0:
                    dep_info.risk_level = "critical"
                elif high_count > 0:
                    dep_info.risk_level = "high"
                elif medium_count > 0:
                    dep_info.risk_level = "medium"
                else:
                    dep_info.risk_level = "low"
            else:
                dep_info.security_score = 85.0  # Good score for no known vulnerabilities
                dep_info.risk_level = "low"
    
    async def _lookup_vulnerabilities(self, dep_info: DependencyInfo) -> List[Dict[str, Any]]:
        """Lookup vulnerabilities for a dependency."""
        
        # Simulate vulnerability database lookup
        # In reality, this would query OSV, NVD, Snyk, etc.
        
        vulnerable_packages = {
            'lodash': [
                {
                    'id': 'CVE-2021-23337',
                    'severity': 'high',
                    'title': 'Command Injection in lodash',
                    'description': 'lodash versions prior to 4.17.21 are vulnerable to Command Injection',
                    'affected_versions': '< 4.17.21',
                    'fixed_version': '4.17.21'
                }
            ],
            'axios': [
                {
                    'id': 'CVE-2021-3749',
                    'severity': 'medium',
                    'title': 'Regular Expression Denial of Service in axios',
                    'description': 'axios is vulnerable to ReDoS when parsing URLs',
                    'affected_versions': '< 0.21.2',
                    'fixed_version': '0.21.2'
                }
            ],
            'express': [
                {
                    'id': 'CVE-2022-24999',
                    'severity': 'medium',
                    'title': 'qs prototype pollution',
                    'description': 'qs before 6.10.3 allows prototype pollution',
                    'affected_versions': '< 4.18.2',
                    'fixed_version': '4.18.2'
                }
            ]
        }
        
        return vulnerable_packages.get(dep_info.name, [])
    
    async def _analyze_outdated_packages(self, graph: DependencyGraph):
        """Analyze dependencies for outdated versions."""
        
        logger.info("Analyzing dependencies for outdated versions")
        
        for dep_key, dep_info in graph.all_dependencies.items():
            # Simulate version checking (would query package registries)
            latest_version = await self._get_latest_version(dep_info)
            
            dep_info.latest_version = latest_version
            dep_info.is_outdated = self._is_version_outdated(dep_info.version, latest_version)
            
            if dep_info.is_outdated:
                dep_info.version_behind = self._calculate_versions_behind(dep_info.version, latest_version)
    
    async def _get_latest_version(self, dep_info: DependencyInfo) -> str:
        """Get latest version for a dependency."""
        
        # Simulate latest version lookup
        latest_versions = {
            'react': '18.2.0',
            'lodash': '4.17.21',
            'axios': '1.6.0',
            'express': '4.18.2',
            'webpack': '5.89.0'
        }
        
        return latest_versions.get(dep_info.name, dep_info.version)
    
    async def _analyze_supply_chain_risks(self, graph: DependencyGraph):
        """Analyze supply chain risks for dependencies."""
        
        logger.info("Analyzing supply chain risks")
        
        for dep_key, dep_info in graph.all_dependencies.items():
            # Simulate supply chain analysis
            supply_chain_info = await self._get_supply_chain_info(dep_info)
            
            dep_info.maintainers = supply_chain_info.get('maintainers', [])
            dep_info.download_count = supply_chain_info.get('download_count', 0)
            dep_info.age_days = supply_chain_info.get('age_days', 0)
            dep_info.last_updated = supply_chain_info.get('last_updated', '')
            
            # Assess supply chain risk
            risk_factors = []
            
            if len(dep_info.maintainers) < 2:
                risk_factors.append('few_maintainers')
            
            if dep_info.download_count < 1000:
                risk_factors.append('low_adoption')
            
            if dep_info.age_days < 30:
                risk_factors.append('very_new')
            
            # Adjust risk level based on supply chain factors
            if risk_factors and dep_info.risk_level == "low":
                dep_info.risk_level = "medium"
    
    async def _get_supply_chain_info(self, dep_info: DependencyInfo) -> Dict[str, Any]:
        """Get supply chain information for a dependency."""
        
        # Simulate supply chain data
        supply_chain_data = {
            'react': {
                'maintainers': ['facebook', 'react-team'],
                'download_count': 20000000,
                'age_days': 2800,
                'last_updated': '2023-10-15'
            },
            'lodash': {
                'maintainers': ['jdalton', 'mathias'],
                'download_count': 50000000,
                'age_days': 3000,
                'last_updated': '2023-09-20'
            },
            'some-unknown-package': {
                'maintainers': ['unknown-dev'],
                'download_count': 500,
                'age_days': 15,
                'last_updated': '2023-11-01'
            }
        }
        
        return supply_chain_data.get(dep_info.name, {
            'maintainers': ['unknown'],
            'download_count': 1000,
            'age_days': 365,
            'last_updated': '2023-01-01'
        })
    
    # Helper methods
    def _clean_version(self, version: str) -> str:
        """Clean and normalize version string."""
        
        # Remove version prefixes and suffixes
        version = re.sub(r'^[\^~>=<]*', '', version)
        version = re.sub(r'\s.*$', '', version)  # Remove everything after first space
        
        return version.strip()
    
    def _is_version_outdated(self, current: str, latest: str) -> bool:
        """Check if current version is outdated compared to latest."""
        
        # Simplified version comparison (would use proper semantic versioning)
        try:
            current_parts = [int(x) for x in current.split('.')]
            latest_parts = [int(x) for x in latest.split('.')]
            
            # Pad with zeros if needed
            max_len = max(len(current_parts), len(latest_parts))
            current_parts.extend([0] * (max_len - len(current_parts)))
            latest_parts.extend([0] * (max_len - len(latest_parts)))
            
            return current_parts < latest_parts
            
        except (ValueError, AttributeError):
            return current != latest
    
    def _calculate_versions_behind(self, current: str, latest: str) -> int:
        """Calculate how many versions behind current is from latest."""
        
        # Simplified calculation
        try:
            current_parts = [int(x) for x in current.split('.')]
            latest_parts = [int(x) for x in latest.split('.')]
            
            if len(current_parts) >= 2 and len(latest_parts) >= 2:
                # Compare minor versions
                return latest_parts[1] - current_parts[1] if latest_parts[0] == current_parts[0] else 999
            
        except (ValueError, AttributeError):
            pass
        
        return 1 if current != latest else 0
    
    def _calculate_max_depth(self, dependency_tree: Dict[str, List[str]], 
                           root_dependencies: List[DependencyInfo]) -> int:
        """Calculate maximum depth of dependency tree."""
        
        max_depth = 0
        
        for root_dep in root_dependencies:
            depth = self._calculate_depth_recursive(f"{root_dep.package_manager.value}:{root_dep.name}", 
                                                   dependency_tree, set(), 0)
            max_depth = max(max_depth, depth)
        
        return max_depth
    
    def _calculate_depth_recursive(self, dep_key: str, dependency_tree: Dict[str, List[str]], 
                                  visited: Set[str], current_depth: int) -> int:
        """Recursively calculate dependency depth."""
        
        if dep_key in visited or current_depth > self.analysis_config['max_depth']:
            return current_depth
        
        visited.add(dep_key)
        max_child_depth = current_depth
        
        for child_key in dependency_tree.get(dep_key, []):
            child_depth = self._calculate_depth_recursive(child_key, dependency_tree, visited, current_depth + 1)
            max_child_depth = max(max_child_depth, child_depth)
        
        visited.remove(dep_key)
        return max_child_depth
    
    def _create_empty_graph(self) -> DependencyGraph:
        """Create empty dependency graph."""
        
        return DependencyGraph(
            root_dependencies=[],
            all_dependencies={},
            dependency_tree={},
            reverse_tree={}
        )
    
    def _update_statistics(self, graph: DependencyGraph):
        """Update analyzer statistics."""
        
        self.stats['projects_analyzed'] += 1
        self.stats['dependencies_analyzed'] += graph.total_dependencies
        self.stats['vulnerabilities_found'] += graph.vulnerable_dependencies
        self.stats['outdated_packages_found'] += graph.outdated_dependencies
        self.stats['high_risk_packages'] += graph.high_risk_dependencies
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get analyzer statistics."""
        
        return dict(self.stats)
