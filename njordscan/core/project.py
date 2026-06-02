"""Project model: framework detection and source-file discovery.

Wraps the target directory so detectors don't each re-implement file walking,
ignore handling, framework detection, or package.json parsing.
"""

from __future__ import annotations

import fnmatch
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from .config import CODE_EXTENSIONS, Config


@dataclass
class Project:
    """A scannable project rooted at ``root``."""

    root: Path
    config: Config
    framework: str = "unknown"          # "nextjs" | "react" | "vite" | "unknown"
    package_json: Optional[Dict] = None
    _source_files: List[Path] = field(default_factory=list, repr=False)
    _text_cache: Dict[Path, str] = field(default_factory=dict, repr=False)

    @classmethod
    def load(cls, config: Config) -> "Project":
        root = config.target
        if not root.exists():
            raise FileNotFoundError(f"Target path does not exist: {root}")
        if not root.is_dir():
            raise NotADirectoryError(f"Target is not a directory: {root}")

        pkg = _read_package_json(root)
        project = cls(root=root, config=config, package_json=pkg)
        project.framework = project._detect_framework()
        project._source_files = project._discover_source_files()
        return project

    # -- framework detection -------------------------------------------------

    def _detect_framework(self) -> str:
        deps = self._all_dependencies()
        if "next" in deps or (self.root / "next.config.js").exists() or (
            self.root / "next.config.mjs"
        ).exists() or (self.root / "next.config.ts").exists():
            return "nextjs"
        if "vite" in deps or (self.root / "vite.config.js").exists() or (
            self.root / "vite.config.ts"
        ).exists():
            return "vite"
        if "react" in deps or "react-dom" in deps:
            return "react"
        return "unknown"

    def _all_dependencies(self) -> Dict[str, str]:
        if not self.package_json:
            return {}
        out: Dict[str, str] = {}
        for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
            section = self.package_json.get(key)
            if isinstance(section, dict):
                out.update({str(k): str(v) for k, v in section.items()})
        return out

    @property
    def dependencies(self) -> Dict[str, str]:
        return self._all_dependencies()

    # -- file discovery ------------------------------------------------------

    def _discover_source_files(self) -> List[Path]:
        files: List[Path] = []
        for path in self.root.rglob("*"):
            if not path.is_file():
                continue
            if path.suffix.lower() not in CODE_EXTENSIONS:
                continue
            if self.is_ignored(path):
                continue
            try:
                if path.stat().st_size > self.config.max_file_bytes:
                    continue
            except OSError:
                continue
            files.append(path)
        return files

    @property
    def source_files(self) -> List[Path]:
        return list(self._source_files)

    def is_ignored(self, path: Path) -> bool:
        try:
            rel = path.relative_to(self.root).as_posix()
        except ValueError:
            rel = path.as_posix()
        for pattern in self.config.all_ignores:
            if fnmatch.fnmatch(rel, pattern) or fnmatch.fnmatch(rel, pattern.lstrip("*/")):
                return True
        return False

    def rel(self, path: Path) -> str:
        try:
            return path.relative_to(self.root).as_posix()
        except ValueError:
            return str(path)

    def read_text(self, path: Path) -> str:
        """Read a file as UTF-8, tolerating undecodable bytes. Cached per path."""
        cached = self._text_cache.get(path)
        if cached is not None:
            return cached
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            text = ""
        self._text_cache[path] = text
        return text

    def find_file(self, *names: str) -> Optional[Path]:
        """Return the first existing file at the project root matching any name."""
        for name in names:
            candidate = self.root / name
            if candidate.exists():
                return candidate
        return None


def _read_package_json(root: Path) -> Optional[Dict]:
    pkg_path = root / "package.json"
    if not pkg_path.exists():
        return None
    try:
        return json.loads(pkg_path.read_text(encoding="utf-8", errors="replace"))
    except (json.JSONDecodeError, OSError):
        return None
