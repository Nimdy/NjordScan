"""
Dependency graph analysis with transitive risk scoring.

Parses lockfiles into a dependency graph and scores each package
based on depth, known-malicious lists, and metadata heuristics.
"""

import json
import logging
from pathlib import Path
from typing import Dict, List, Set, Optional, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# Known-malicious packages (confirmed supply chain attacks)
KNOWN_MALICIOUS: Set[str] = {
    'event-stream', 'flatmap-stream', 'eslint-scope',
    'getcookies', 'crossenv', 'cross-env.js',
    'mongose', 'mariadb', 'mysqljs',
    'nodesass', 'nodefabric', 'discordi.js',
    'discord.jss', 'colors-2', 'ua-parser-js-hijacked',
    'coa-hijacked', 'rc-hijacked',
}

# Packages with documented past compromises (may have been fixed)
PREVIOUSLY_COMPROMISED: Set[str] = {
    'ua-parser-js', 'coa', 'rc', 'colors', 'faker',
}


@dataclass
class DepNode:
    """A node in the dependency graph."""
    name: str
    version: str
    depth: int  # 0 = direct, 1+ = transitive
    resolved_url: str = ""
    integrity: str = ""
    dependents: List[str] = field(default_factory=list)  # who depends on this
    dependencies: List[str] = field(default_factory=list)  # what this depends on


@dataclass
class DepRisk:
    """Risk assessment for a single dependency."""
    name: str
    version: str
    depth: int
    risk_score: float  # 0.0 (safe) - 1.0 (critical)
    risk_factors: List[str] = field(default_factory=list)
    severity: str = "low"


@dataclass
class DepGraphResult:
    """Result of dependency graph analysis."""
    total_packages: int
    direct_count: int
    transitive_count: int
    max_depth: int
    risks: List[DepRisk]
    graph: Dict[str, DepNode]


class DepGraphAnalyzer:
    """Builds and analyzes a dependency graph from lockfiles."""

    def analyze(self, target_path: Path) -> Optional[DepGraphResult]:
        """Analyze dependency graph for a project."""
        graph: Dict[str, DepNode] = {}

        # Try package-lock.json first
        lock_path = target_path / 'package-lock.json'
        if lock_path.exists():
            graph = self._parse_package_lock(lock_path)
        else:
            # Try yarn.lock (basic parsing)
            yarn_path = target_path / 'yarn.lock'
            if yarn_path.exists():
                graph = self._parse_yarn_lock_basic(yarn_path)

        if not graph:
            return None

        # Score risks
        risks = self._score_risks(graph)

        direct = sum(1 for n in graph.values() if n.depth == 0)
        transitive = sum(1 for n in graph.values() if n.depth > 0)
        max_depth = max((n.depth for n in graph.values()), default=0)

        return DepGraphResult(
            total_packages=len(graph),
            direct_count=direct,
            transitive_count=transitive,
            max_depth=max_depth,
            risks=sorted(risks, key=lambda r: r.risk_score, reverse=True),
            graph=graph,
        )

    # ----------------------------------------------------------------- #
    #  Lockfile parsers
    # ----------------------------------------------------------------- #

    def _parse_package_lock(self, lock_path: Path) -> Dict[str, DepNode]:
        """Parse package-lock.json into a dependency graph."""
        try:
            with open(lock_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except (json.JSONDecodeError, IOError):
            return {}

        graph: Dict[str, DepNode] = {}
        lockfile_version = data.get('lockfileVersion', 1)

        # Read direct dependencies from top-level package.json ref
        direct_deps: Set[str] = set()
        pkg_json = lock_path.parent / 'package.json'
        if pkg_json.exists():
            try:
                with open(pkg_json, 'r') as f:
                    pkg = json.load(f)
                direct_deps = set(pkg.get('dependencies', {}).keys()) | set(pkg.get('devDependencies', {}).keys())
            except (json.JSONDecodeError, IOError):
                pass

        if lockfile_version >= 2 and 'packages' in data:
            packages = data['packages']
            for key, info in packages.items():
                if key == '' or not isinstance(info, dict):
                    continue
                # Extract name from key: node_modules/foo or node_modules/@scope/foo
                name = key.replace('node_modules/', '').split('node_modules/')[-1]
                depth = 0 if name in direct_deps else key.count('node_modules/') - 1
                if depth < 0:
                    depth = 1

                node = DepNode(
                    name=name,
                    version=info.get('version', ''),
                    depth=depth,
                    resolved_url=info.get('resolved', ''),
                    integrity=info.get('integrity', ''),
                    dependencies=list(info.get('dependencies', {}).keys()),
                )
                graph[name] = node

        elif 'dependencies' in data:
            # v1 format
            self._parse_v1_deps(data['dependencies'], graph, direct_deps, depth=0)

        # Build reverse dependency links
        for name, node in graph.items():
            for dep_name in node.dependencies:
                if dep_name in graph:
                    graph[dep_name].dependents.append(name)

        return graph

    def _parse_v1_deps(self, deps: dict, graph: Dict[str, DepNode],
                        direct_deps: Set[str], depth: int):
        """Recursively parse v1 lockfile dependencies."""
        for name, info in deps.items():
            if not isinstance(info, dict):
                continue
            d = 0 if name in direct_deps else max(depth, 1)
            graph[name] = DepNode(
                name=name,
                version=info.get('version', ''),
                depth=d,
                resolved_url=info.get('resolved', ''),
                integrity=info.get('integrity', ''),
                dependencies=list(info.get('requires', {}).keys()),
            )
            # Recurse into nested deps
            if 'dependencies' in info:
                self._parse_v1_deps(info['dependencies'], graph, set(), depth + 1)

    def _parse_yarn_lock_basic(self, yarn_path: Path) -> Dict[str, DepNode]:
        """Basic yarn.lock parsing — extracts names and versions."""
        graph: Dict[str, DepNode] = {}
        try:
            content = yarn_path.read_text(encoding='utf-8')
        except IOError:
            return graph

        current_name = None
        current_data: Dict[str, str] = {}

        for line in content.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith('#'):
                continue

            if not line.startswith(' ') and not line.startswith('\t') and stripped.endswith(':'):
                if current_name and current_data:
                    graph[current_name] = DepNode(
                        name=current_name,
                        version=current_data.get('version', ''),
                        depth=1,  # Yarn lock doesn't easily give us depth
                        resolved_url=current_data.get('resolved', ''),
                        integrity=current_data.get('integrity', ''),
                    )
                # Parse entry name: "foo@^1.0.0" or foo@^1.0.0:
                raw = stripped.rstrip(':').strip('"')
                current_name = raw.split('@')[0] if '@' in raw and not raw.startswith('@') else raw.rsplit('@', 1)[0]
                current_data = {}
            elif current_name and (line.startswith('  ') or line.startswith('\t')):
                if ' ' in stripped:
                    key, _, val = stripped.partition(' ')
                    current_data[key.strip()] = val.strip().strip('"')

        if current_name and current_data:
            graph[current_name] = DepNode(
                name=current_name,
                version=current_data.get('version', ''),
                depth=1,
                resolved_url=current_data.get('resolved', ''),
                integrity=current_data.get('integrity', ''),
            )

        return graph

    # ----------------------------------------------------------------- #
    #  Risk scoring
    # ----------------------------------------------------------------- #

    def _score_risks(self, graph: Dict[str, DepNode]) -> List[DepRisk]:
        """Score each package for risk."""
        risks: List[DepRisk] = []

        for name, node in graph.items():
            score = 0.0
            factors: List[str] = []

            # Known malicious
            if name.lower() in KNOWN_MALICIOUS:
                score += 0.9
                factors.append("Known malicious package")

            # Previously compromised
            if name.lower() in PREVIOUSLY_COMPROMISED:
                score += 0.3
                factors.append("Previously compromised package")

            # Deep transitive dependency (harder to audit)
            if node.depth >= 4:
                score += 0.15
                factors.append(f"Deep transitive dependency (depth {node.depth})")
            elif node.depth >= 2:
                score += 0.05
                factors.append(f"Transitive dependency (depth {node.depth})")

            # Missing integrity hash
            if node.resolved_url and not node.integrity:
                score += 0.2
                factors.append("Missing integrity hash")

            # Non-standard registry
            trusted = ('registry.npmjs.org', 'registry.yarnpkg.com')
            if node.resolved_url and node.resolved_url.startswith('http'):
                if not any(r in node.resolved_url for r in trusted):
                    score += 0.4
                    factors.append(f"Non-standard registry: {node.resolved_url[:80]}")

            # Git dependency
            if node.resolved_url and (
                node.resolved_url.startswith('git+') or
                node.resolved_url.startswith('git://') or
                ('github.com' in node.resolved_url and '.git' in node.resolved_url)
            ):
                score += 0.25
                factors.append("Git dependency (bypasses registry integrity)")

            # Many dependents = high blast radius
            if len(node.dependents) >= 10:
                score += 0.1
                factors.append(f"High blast radius ({len(node.dependents)} dependents)")

            if factors:
                score = min(score, 1.0)
                severity = 'critical' if score >= 0.7 else 'high' if score >= 0.4 else 'medium' if score >= 0.2 else 'low'
                risks.append(DepRisk(
                    name=name,
                    version=node.version,
                    depth=node.depth,
                    risk_score=round(score, 2),
                    risk_factors=factors,
                    severity=severity,
                ))

        return risks
