"""Dependency usage analysis — which npm packages and symbols the code actually uses.

This is what turns "you have a vulnerable package installed" into "you actually call
the vulnerable function" — the real VEX (Vulnerability Exploitability eXchange) signal.

For each npm package it records: which files import it, and which symbols are used
(named imports, members accessed on a default/namespace binding, subpath imports,
and `require()` forms). Given an advisory that names its vulnerable symbol(s), we can
then say: *affected* (you call it), *not affected — vulnerable code not used* (you
import the package but never the vulnerable function), or *not affected — not imported*.

Static analysis is conservative: when a package is imported in a way we can't fully
resolve, we err toward "potentially affected" rather than give false assurance.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, Optional, Set

from .project import Project

_IMPORT = re.compile(r"""import\s+(?P<clause>[^'";]+?)\s+from\s+['"](?P<spec>[^'"]+)['"]""")
_IMPORT_BARE = re.compile(r"""(?:^|\n)\s*import\s+['"](?P<spec>[^'"]+)['"]""")
_REQUIRE = re.compile(
    r"""(?:const|let|var)\s+(?P<bind>\{[^}]*\}|[A-Za-z0-9_$]+)\s*=\s*"""
    r"""require\(\s*['"](?P<spec>[^'"]+)['"]\s*\)""",
)


def _pkg_root(spec: str):
    """'lodash/template' -> ('lodash','template'); '@scope/p/sub' -> ('@scope/p','sub')."""
    if spec.startswith(".") or not spec:
        return None, None
    parts = spec.split("/")
    if spec.startswith("@"):
        if len(parts) < 2:
            return None, None
        return "/".join(parts[:2]), "/".join(parts[2:]) or None
    return parts[0], "/".join(parts[1:]) or None


@dataclass
class PkgUsage:
    package: str
    symbols: Set[str] = field(default_factory=set)   # symbols used from the package
    files: Set[str] = field(default_factory=set)      # files importing it
    unresolved: bool = False                          # default/namespace import we couldn't fully resolve


class UsageIndex:
    def __init__(self, project: Project) -> None:
        self.project = project
        self._pkgs: Dict[str, PkgUsage] = {}
        self._build()

    def _u(self, name: str) -> PkgUsage:
        return self._pkgs.setdefault(name, PkgUsage(name))

    def _build(self) -> None:
        for path in self.project.source_files:
            text = self.project.read_text(path)
            if text:
                try:
                    self._scan_file(text, self.project.rel(path))
                except Exception:  # noqa: BLE001 — one weird file must not break the index
                    continue

    def _scan_file(self, text: str, rel: str) -> None:
        bindings: Dict[str, str] = {}   # local name -> package (default/namespace imports)

        for m in _IMPORT.finditer(text):
            root, sub = _pkg_root(m.group("spec"))
            if not root:
                continue
            u = self._u(root)
            u.files.add(rel)
            if sub:                      # subpath import: the leaf is effectively the symbol
                u.symbols.add(sub.split("/")[-1])
            else:                        # root import: track named symbols + default/ns bindings
                self._parse_clause(m.group("clause"), root, u, bindings)

        for m in _IMPORT_BARE.finditer(text):
            root, sub = _pkg_root(m.group("spec"))
            if root:
                self._u(root).files.add(rel)

        for m in _REQUIRE.finditer(text):
            root, sub = _pkg_root(m.group("spec"))
            if not root:
                continue
            u = self._u(root)
            u.files.add(rel)
            bind = m.group("bind").strip()
            if sub:
                u.symbols.add(sub.split("/")[-1])
            elif bind.startswith("{"):
                u.symbols.update(_names(bind.strip("{}")))
            else:
                bindings[bind] = root

        # member accesses on default/namespace/require bindings: binding.symbol
        for local, pkg in bindings.items():
            u = self._u(pkg)
            members = set(re.findall(rf"\b{re.escape(local)}\.([A-Za-z0-9_$]+)", text))
            if members:
                u.symbols.update(members)
            else:
                u.unresolved = True      # imported whole, but no member access we can see

    def _parse_clause(self, clause: str, pkg: str, u: PkgUsage, bindings: Dict[str, str]) -> None:
        clause = clause.strip()
        # split top-level: a default/namespace part and an optional { ... } part
        named = re.search(r"\{([^}]*)\}", clause)
        if named:
            u.symbols.update(_names(named.group(1)))
            clause = clause[:named.start()] + clause[named.end():]
        for piece in clause.split(","):
            piece = piece.strip().rstrip(",").strip()
            if not piece:
                continue
            ns = re.match(r"\*\s+as\s+([A-Za-z0-9_$]+)", piece)
            if ns:
                bindings[ns.group(1)] = pkg
            elif re.match(r"^[A-Za-z0-9_$]+$", piece):  # default import
                bindings[piece] = pkg

    def for_package(self, name: str) -> Optional[PkgUsage]:
        return self._pkgs.get(name)

    def uses_symbol(self, name: str, vuln_symbols: Set[str]) -> Optional[bool]:
        """True = vulnerable symbol used; False = imported but not; None = not imported."""
        u = self._pkgs.get(name)
        if not u:
            return None
        if not vuln_symbols:
            return True                       # no symbol info -> any use is potentially relevant
        if u.symbols & {s.lower() for s in vuln_symbols} or u.symbols & set(vuln_symbols):
            return True
        # imported, vulnerable symbol not seen — but if we couldn't resolve the binding, be safe.
        if u.unresolved:
            return True
        return False


def _names(block: str) -> Set[str]:
    """Parse a `{ a, b as c, type D }` import block into original symbol names {a, b}."""
    out: Set[str] = set()
    for part in block.split(","):
        part = part.strip()
        if not part or part == "type":
            continue
        part = re.sub(r"^type\s+", "", part)
        name = re.split(r"\s+as\s+", part)[0].strip()
        if re.match(r"^[A-Za-z0-9_$]+$", name):
            out.add(name)
    return out
