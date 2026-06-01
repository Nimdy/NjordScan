"""Software Bill of Materials (SBOM) generation.

Produces a CycloneDX 1.5 or SPDX 2.3 inventory of a project's npm dependencies —
and, for CycloneDX, **correlates each component against the advisory database** so
the SBOM also tells you which components are vulnerable (a lightweight VEX).

Dependency versions are resolved from the lockfile (`package-lock.json`) when
present, otherwise from the declared range in `package.json`.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from . import __version__
from .core.project import Project
from .detectors.dependencies import _coerce_version, _in_range, _load_advisories


class _Component:
    __slots__ = ("name", "version", "dev")

    def __init__(self, name: str, version: str, dev: bool) -> None:
        self.name = name
        self.version = version
        self.dev = dev

    @property
    def purl(self) -> str:
        n = self.name.replace("@", "%40", 1) if self.name.startswith("@") else self.name
        return f"pkg:npm/{n}@{self.version}" if self.version else f"pkg:npm/{n}"


def _resolved_versions(project: Project) -> Dict[str, str]:
    """name -> resolved version from package-lock.json (best effort)."""
    lock = project.find_file("package-lock.json", "npm-shrinkwrap.json")
    if not lock:
        return {}
    try:
        data = json.loads(project.read_text(lock))
    except (json.JSONDecodeError, ValueError):
        return {}
    out: Dict[str, str] = {}
    for path, meta in (data.get("packages") or {}).items():
        if not path or not isinstance(meta, dict):
            continue
        name = path.split("node_modules/")[-1]
        ver = meta.get("version")
        if name and ver:
            out[name] = str(ver)
    # legacy v1 lockfile
    for name, meta in (data.get("dependencies") or {}).items():
        if isinstance(meta, dict) and meta.get("version") and name not in out:
            out[name] = str(meta["version"])
    return out


def _components(project: Project) -> List[_Component]:
    pkg = project.package_json or {}
    resolved = _resolved_versions(project)
    dev_names = set((pkg.get("devDependencies") or {}).keys())
    comps: List[_Component] = []
    seen = set()
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        for name, declared in (pkg.get(section) or {}).items():
            if name in seen:
                continue
            seen.add(name)
            version = resolved.get(name) or _clean(str(declared))
            comps.append(_Component(name, version, dev=name in dev_names))
    return sorted(comps, key=lambda c: c.name.lower())


def _clean(declared: str) -> str:
    v = _coerce_version(declared)
    return str(v) if v else declared.lstrip("^~>=<v ").split(" ")[0]


def _vulns_for(comp: _Component, advisories: Dict[str, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    entries = advisories.get(comp.name)
    if not entries:
        return []
    version = _coerce_version(comp.version)
    hits = []
    for adv in entries:
        rng = adv.get("vulnerable_range", "")
        if version is not None and rng and _in_range(version, rng):
            hits.append(adv)
    return hits


# --- CycloneDX 1.5 -----------------------------------------------------------

def to_cyclonedx(project: Project) -> Dict[str, Any]:
    comps = _components(project)
    advisories = _load_advisories()
    pkg = project.package_json or {}
    now = datetime.now(timezone.utc).isoformat()

    components = [{
        "type": "library",
        "name": c.name,
        "version": c.version,
        "purl": c.purl,
        "bom-ref": c.purl,
        "scope": "optional" if c.dev else "required",
    } for c in comps]

    vulnerabilities = []
    for c in comps:
        for adv in _vulns_for(c, advisories):
            vid = adv.get("id") or adv.get("ghsa") or "advisory"
            vulnerabilities.append({
                "bom-ref": str(uuid.uuid4()),
                "id": vid,
                "source": {"name": "OSV/GHSA", "url": "https://osv.dev"},
                "ratings": [{"severity": str(adv.get("severity", "unknown")).lower()}],
                "cwes": _cwe_nums(adv.get("cwe")),
                "description": adv.get("summary", ""),
                "recommendation": f"Upgrade to {adv.get('patched', 'a patched version')} or later.",
                "affects": [{"ref": c.purl}],
            })

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": now,
            "tools": [{"vendor": "NjordScan", "name": "njordscan", "version": __version__}],
            "component": {
                "type": "application",
                "name": str(pkg.get("name") or project.root.name),
                "version": str(pkg.get("version") or "0.0.0"),
                "bom-ref": "root-application",
            },
        },
        "components": components,
        "vulnerabilities": vulnerabilities,
    }


def _cwe_nums(cwe: Optional[str]) -> List[int]:
    if not cwe:
        return []
    try:
        return [int(cwe.split("-")[1])]
    except (IndexError, ValueError):
        return []


# --- SPDX 2.3 ----------------------------------------------------------------

def to_spdx(project: Project) -> Dict[str, Any]:
    comps = _components(project)
    pkg = project.package_json or {}
    now = datetime.now(timezone.utc).isoformat()
    root_name = str(pkg.get("name") or project.root.name)

    packages = []
    relationships = []
    for i, c in enumerate(comps):
        spdx_id = f"SPDXRef-Package-{i}"
        packages.append({
            "name": c.name,
            "SPDXID": spdx_id,
            "versionInfo": c.version,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "externalRefs": [{
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": c.purl,
            }],
        })
        relationships.append({
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relatedSpdxElement": spdx_id,
            "relationshipType": "DESCRIBES",
        })

    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": root_name,
        "documentNamespace": f"https://njordscan/spdx/{root_name}-{uuid.uuid4()}",
        "creationInfo": {
            "created": now,
            "creators": [f"Tool: njordscan-{__version__}"],
        },
        "packages": packages,
        "relationships": relationships,
    }


def generate(project: Project, fmt: str = "cyclonedx") -> str:
    if fmt == "spdx":
        doc = to_spdx(project)
    else:
        doc = to_cyclonedx(project)
    return json.dumps(doc, indent=2, ensure_ascii=False)


def summary(project: Project) -> Dict[str, int]:
    comps = _components(project)
    advisories = _load_advisories()
    vulnerable = sum(1 for c in comps if _vulns_for(c, advisories))
    return {"components": len(comps), "vulnerable": vulnerable}
