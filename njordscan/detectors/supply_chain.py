"""Supply-chain detector.

Catches the attacks that happen before you even run your code:
  - dangerous npm lifecycle scripts (preinstall/postinstall running curl|sh, etc.)
  - a missing lockfile (non-reproducible, lets bad versions slip in)
  - lockfile integrity gaps (dependencies pulled from non-standard registries / git URLs)
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Dict, List

from ..core.finding import Finding
from ..core.project import Project
from .base import Detector

_LIFECYCLE_SCRIPTS = (
    "preinstall", "install", "postinstall",
    "preuninstall", "postuninstall", "prepare", "prepublish",
)

_MAX_DEP_PKGS = 8000   # cap how many node_modules package.json files we read, for perf

# (regex, human reason). Ordered most-to-least specific.
_DANGEROUS_PATTERNS: List[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(curl|wget|fetch)\b[^|&;]*\|\s*(sh|bash|zsh|node|python)", re.I),
     "Pipes remote content directly into a shell/interpreter"),
    (re.compile(r"\b(bash|sh)\s+-c\s+.*(curl|wget)", re.I),
     "Downloads and executes a remote script"),
    (re.compile(r"/dev/tcp/|nc\s+-e|ncat\s+-e|bash\s+-i\b", re.I),
     "Looks like a reverse shell"),
    (re.compile(r"(base64\s+-d|atob\()", re.I),
     "Decodes an obfuscated/encoded payload"),
    (re.compile(r"(process\.env|~/\.(aws|ssh|npmrc)|id_rsa|\.env)\b.*(curl|wget|fetch|http)", re.I),
     "Reads credentials/secrets and may exfiltrate them"),
    (re.compile(r"\b(curl|wget)\b.*\b(POST|--data|-d)\b", re.I),
     "Sends data to a remote server during install"),
    (re.compile(r"eval\s*\(|child_process", re.I),
     "Executes dynamic code during install"),
]

_LOCKFILES = ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb", "npm-shrinkwrap.json")


class SupplyChainDetector(Detector):
    id = "supply-chain"
    name = "Supply-chain integrity"
    kind = "static"

    def applies(self, project: Project) -> bool:
        return (project.root / "package.json").exists()

    async def scan(self, project: Project) -> List[Finding]:
        findings: List[Finding] = []
        findings.extend(self._check_install_scripts(project))
        findings.extend(self._check_lockfile(project))
        findings.extend(self._audit_installed_deps(project))
        return findings

    # -- installed dependency audit (node_modules) ---------------------------

    def _audit_installed_deps(self, project: Project) -> List[Finding]:
        """Scan installed dependencies for dangerous install scripts, and flag any
        install script that is NEW or CHANGED since the last scan — the signature of
        a freshly-compromised package picked up on a redeploy."""
        nm = project.root / "node_modules"
        if not nm.is_dir():
            return []
        findings: List[Finding] = []
        current: Dict[str, Dict[str, str]] = {}   # dep -> {script_name: sha1}
        count = 0
        try:
            paths = nm.rglob("package.json")
        except OSError:
            return []
        for pj in paths:
            if count >= _MAX_DEP_PKGS:
                break
            count += 1
            try:
                if pj.stat().st_size > 1_000_000:
                    continue
                data = json.loads(pj.read_text(encoding="utf-8", errors="replace"))
            except (OSError, ValueError):
                continue
            scripts = data.get("scripts")
            if not isinstance(scripts, dict):
                continue
            name = str(data.get("name") or pj.parent.name)
            version = str(data.get("version") or "")
            current.setdefault(name, {})   # record EVERY dep, so "gained a script" is detectable
            for sname, cmd in scripts.items():
                if sname not in _LIFECYCLE_SCRIPTS or not isinstance(cmd, str):
                    continue
                current[name][sname] = hashlib.sha1(cmd.encode("utf-8")).hexdigest()
                for pattern, reason in _DANGEROUS_PATTERNS:
                    if pattern.search(cmd):
                        findings.append(Finding(
                            rule_id="supply-chain.dependency-install-script",
                            file=f"node_modules/{name}/package.json", line=1,
                            code_snippet=f'"{sname}": "{cmd[:160]}"', detector=self.id, confidence="high",
                            reachable=True,
                            message=(f"Installed dependency '{name}@{version}' has a dangerous '{sname}' "
                                     f"script: {reason}."),
                        ))
                        break

        # change detection vs the previous scan's baseline
        baseline = self._load_dep_baseline(project)
        if baseline:   # skip on the very first scan (no baseline yet)
            for name, scripts in current.items():
                old = baseline.get(name)
                if old is None:
                    continue   # a dependency you newly added is not a "change"
                for sname, digest in scripts.items():
                    if sname not in old or old[sname] != digest:
                        kind = "added a new" if sname not in old else "changed its"
                        findings.append(Finding(
                            rule_id="supply-chain.dependency-script-changed",
                            file=f"node_modules/{name}/package.json", line=1,
                            detector=self.id, confidence="high", reachable=True,
                            message=(f"Dependency '{name}' {kind} '{sname}' install script since your "
                                     "last scan — investigate before deploying (possible compromised update)."),
                        ))
        self._save_dep_baseline(project, current)
        return findings

    @staticmethod
    def _dep_baseline_path(project: Project) -> Path:
        return project.root / ".njordscan" / "dep-scripts.json"

    def _load_dep_baseline(self, project: Project) -> Dict[str, Dict[str, str]]:
        try:
            return json.loads(self._dep_baseline_path(project).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}

    def _save_dep_baseline(self, project: Project, current: Dict[str, Dict[str, str]]) -> None:
        try:
            path = self._dep_baseline_path(project)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(current, sort_keys=True), encoding="utf-8")
        except OSError:
            pass

    def _check_install_scripts(self, project: Project) -> List[Finding]:
        pkg = project.package_json
        if not pkg:
            return []
        scripts = pkg.get("scripts")
        if not isinstance(scripts, dict):
            return []

        pkg_path = project.root / "package.json"
        raw = project.read_text(pkg_path)
        out: List[Finding] = []
        for name, command in scripts.items():
            if name not in _LIFECYCLE_SCRIPTS or not isinstance(command, str):
                continue
            for pattern, reason in _DANGEROUS_PATTERNS:
                if pattern.search(command):
                    out.append(Finding(
                        rule_id="supply-chain.dangerous-install-script",
                        file="package.json",
                        line=_find_line(raw, f'"{name}"'),
                        code_snippet=f'"{name}": "{command}"',
                        detector=self.id,
                        confidence="high",
                        message=f"Lifecycle script '{name}': {reason}.",
                    ))
                    break  # one finding per script is enough
        return out

    def _check_lockfile(self, project: Project) -> List[Finding]:
        lockfile = project.find_file(*_LOCKFILES)
        if lockfile is None:
            return [Finding(
                rule_id="supply-chain.missing-lockfile",
                file="package.json",
                line=1,
                detector=self.id,
                confidence="high",
                message="No package-lock.json / yarn.lock / pnpm-lock.yaml found.",
            )]
        return self._check_lockfile_integrity(project, lockfile)

    def _check_lockfile_integrity(self, project: Project, lockfile: Path) -> List[Finding]:
        # Only npm's JSON lockfile is structured enough to check cheaply here.
        if lockfile.name not in ("package-lock.json", "npm-shrinkwrap.json"):
            return []
        try:
            data = json.loads(project.read_text(lockfile))
        except (json.JSONDecodeError, ValueError):
            return []

        packages = data.get("packages") or {}
        out: List[Finding] = []
        flagged_git = 0
        flagged_registry = 0
        for name, meta in packages.items():
            if not name or not isinstance(meta, dict):
                continue
            resolved = str(meta.get("resolved", ""))
            if resolved.startswith(("git+", "git:")) or "github.com" in resolved and resolved.endswith(".git"):
                flagged_git += 1
            elif resolved.startswith("http") and "registry.npmjs.org" not in resolved and "registry.yarnpkg.com" not in resolved:
                flagged_registry += 1

        if flagged_registry:
            out.append(Finding(
                rule_id="deps.typosquat",
                file=lockfile.name,
                line=1,
                detector=self.id,
                confidence="low",
                message=(
                    f"{flagged_registry} dependencies resolve from a non-standard registry. "
                    "Confirm this is intentional (dependency-confusion risk)."
                ),
            ))
        return out


def _find_line(text: str, needle: str) -> int:
    idx = text.find(needle)
    if idx < 0:
        return 1
    return text.count("\n", 0, idx) + 1
