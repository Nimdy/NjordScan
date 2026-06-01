"""Reachability analysis — is a finding's code actually reachable by an attacker?

A long list of issues is noise; what matters is which vulnerable code is reachable
from an **exposed entrypoint** — an HTTP route, API handler, Server Action,
middleware, or the client bundle. NjordScan builds an import graph rooted at the
framework's entrypoints and marks each finding reachable / not-reachable, with the
import path and whether it runs **server-side** (higher risk) or **client-side**.

This is the reachability/ASPM technique commercial tools charge for — used here to
prioritize, never to silently hide. Static import analysis is a strong *signal*, not
a proof: dynamic ``require()``/``import()`` can create paths we don't see, so
"not reachable" means *lower priority*, not *safe*.
"""

from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Dict, List, Optional, Set, Tuple

from .project import Project

# import x from 'spec' | import 'spec' | export ... from 'spec' | require('spec') | import('spec')
_IMPORT_RE = re.compile(
    r"""(?:import|export)\s+(?:[^'"`;]*?\sfrom\s+)?['"]([^'"]+)['"]"""
    r"""|require\(\s*['"]([^'"]+)['"]\s*\)"""
    r"""|import\(\s*['"]([^'"]+)['"]\s*\)""",
)
_EXT_ORDER = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs")
_INDEX = tuple(f"index{e}" for e in _EXT_ORDER)

# basenames (without extension) that Next.js app-router treats as live files
_APP_ROUTE_FILES = {"route"}
_APP_RENDER_FILES = {"page", "layout", "template", "default", "loading", "error",
                     "not-found", "global-error", "head", "opengraph-image", "icon"}


@dataclass
class Reach:
    reachable: bool
    kind: str = ""                       # "server" | "client" | ""
    entrypoint: Optional[str] = None     # the entry file that reaches this one
    path: List[str] = field(default_factory=list)   # entrypoint -> ... -> file


class ReachabilityGraph:
    """Import graph + entrypoint reachability for a project's source files."""

    def __init__(self, project: Project) -> None:
        self.project = project
        self._files: Dict[str, "PurePosixPath"] = {}     # rel -> posix path
        self._imports: Dict[str, Set[str]] = {}          # rel -> resolved local imports (rel)
        self._entry_kind: Dict[str, str] = {}            # entry rel -> "server"|"client"
        self._reach: Dict[str, Reach] = {}
        self._build()

    # -- public ------------------------------------------------------------

    def lookup(self, rel: str) -> Reach:
        return self._reach.get(rel, Reach(reachable=False))

    @property
    def entrypoint_count(self) -> int:
        return len(self._entry_kind)

    # -- build -------------------------------------------------------------

    def _build(self) -> None:
        rels = []
        for path in self.project.source_files:
            rel = self.project.rel(path)
            self._files[rel] = PurePosixPath(rel)
            rels.append(rel)

        alias_roots = self._alias_roots()
        for rel in rels:
            text = self.project.read_text(self.project.root / rel)
            self._imports[rel] = self._parse_imports(rel, text, alias_roots)
            kind = self._entry_kind_for(rel, text)
            if kind:
                self._entry_kind[rel] = kind

        self._reach = self._bfs()

    def _parse_imports(self, importer: str, text: str, alias_roots: List[str]) -> Set[str]:
        out: Set[str] = set()
        for m in _IMPORT_RE.finditer(text):
            spec = m.group(1) or m.group(2) or m.group(3)
            if not spec:
                continue
            target = self._resolve(importer, spec, alias_roots)
            if target:
                out.add(target)
        return out

    def _resolve(self, importer: str, spec: str, alias_roots: List[str]) -> Optional[str]:
        base: Optional[PurePosixPath] = None
        if spec.startswith("."):
            base = (PurePosixPath(importer).parent / spec)
        elif spec.startswith("@/") or spec.startswith("~/"):
            for root in alias_roots:
                cand = self._match(PurePosixPath(root) / spec[2:])
                if cand:
                    return cand
            return None
        else:
            return None  # bare import = node_modules (external leaf)
        return self._match(base)

    def _match(self, p: PurePosixPath) -> Optional[str]:
        p = PurePosixPath(*_norm(p.parts))
        s = p.as_posix()
        if s in self._files:
            return s
        for ext in _EXT_ORDER:
            if (s + ext) in self._files:
                return s + ext
        for idx in _INDEX:
            cand = (p / idx).as_posix()
            if cand in self._files:
                return cand
        return None

    def _alias_roots(self) -> List[str]:
        roots = [""]
        if (self.project.root / "src").is_dir():
            roots.append("src")
        # honor a tsconfig "@/*" -> baseUrl mapping when obvious
        ts = self.project.find_file("tsconfig.json", "jsconfig.json")
        if ts:
            txt = self.project.read_text(ts)
            if '"baseUrl": "./src"' in txt or '"baseUrl":"./src"' in txt:
                roots = ["src", ""]
        return roots

    def _entry_kind_for(self, rel: str, text: str) -> str:
        parts = PurePosixPath(rel).parts
        stem = PurePosixPath(rel).stem
        name = PurePosixPath(rel).name
        segs = set(parts)

        # root middleware
        if rel in {f"middleware{e}" for e in _EXT_ORDER} or rel in {f"src/middleware{e}" for e in _EXT_ORDER}:
            return "server"
        # app router
        if "app" in segs or "src/app" in rel:
            if stem in _APP_ROUTE_FILES:
                return "server"
            if stem in _APP_RENDER_FILES:
                return "client"
        # pages router
        if "pages" in segs:
            if "api" in parts[parts.index("pages") + 1:] if "pages" in parts else False:
                return "server"
            return "server" if "/api/" in "/" + rel else "client"
        # Server Action module (directive in the first ~3 lines)
        head = "\n".join(text.splitlines()[:3])
        if re.search(r"""^\s*['"]use server['"]""", head, re.M):
            return "server"
        # Vite / React SPA entry
        if stem in ("main", "index") and ("src" in segs or len(parts) == 1):
            if self.project.framework in ("vite", "react") or name.startswith("main."):
                return "client"
        return ""

    def _bfs(self) -> Dict[str, Reach]:
        reach: Dict[str, Reach] = {}
        # server entrypoints first so server reachability wins on ties
        queue: deque[Tuple[str, str, List[str]]] = deque()
        for entry, kind in sorted(self._entry_kind.items(), key=lambda kv: 0 if kv[1] == "server" else 1):
            queue.append((entry, kind, [entry]))
        while queue:
            rel, kind, path = queue.popleft()
            existing = reach.get(rel)
            if existing and not (kind == "server" and existing.kind != "server"):
                continue
            reach[rel] = Reach(reachable=True, kind=kind,
                               entrypoint=path[0], path=path)
            for imp in self._imports.get(rel, ()):  # noqa: B007
                if imp not in reach or (kind == "server" and reach[imp].kind != "server"):
                    queue.append((imp, kind, path + [imp]))
        return reach


def _norm(parts: tuple) -> List[str]:
    out: List[str] = []
    for part in parts:
        if part == "..":
            if out:
                out.pop()
        elif part not in (".", ""):
            out.append(part)
    return out
