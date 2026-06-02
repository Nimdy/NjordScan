"""Keystone Commit — the change that ARMED a pre-existing kill chain.

Every PR scanner is diff-local: it flags findings whose lines you touched. None can
answer the more dangerous question — *given everything already in the repo, did THIS
change complete a kill chain whose other links were planted months ago by other
people?* — because none own a whole-repo attack-chain model.

NjordScan does. ``synthesize()`` is a pure function of findings, and any historical
tree can be re-scanned. So Keystone reconstructs the tree BEFORE the change, re-runs
the exact same deterministic attack-path synthesis, and compares:

  a kill chain that exists AFTER but not BEFORE, with at least one step the change
  introduced AND at least one step that pre-existed, is a chain the change *armed*.

Each pre-existing link is dated by ``git blame`` (who planted it, when). There is **no
model in the verdict** — it is a set-difference over two real ASTs, reproducible by
anyone who checks out the two refs and re-scans. Never raises; returns ``[]`` when git
is unavailable or nothing was armed.
"""

from __future__ import annotations

import asyncio
import logging
import subprocess
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..core import gitblame
from ..core.gitdiff import changed_lines, in_diff
from .attack_paths import AttackPath, AttackStep

logger = logging.getLogger(__name__)


@dataclass
class KeystoneStep:
    step: AttackStep
    provenance: str                       # "newly-introduced" | "pre-existing"
    born_commit: Optional[str] = None
    born_author: Optional[str] = None
    born_date: Optional[str] = None       # ISO date (UTC)

    def to_dict(self) -> Dict[str, Any]:
        d = self.step.to_dict()
        d.update({"provenance": self.provenance, "born_commit": self.born_commit,
                  "born_author": self.born_author, "born_date": self.born_date})
        return d


@dataclass
class KeystonePath:
    path: AttackPath
    steps: List[KeystoneStep]
    new_kind: bool = True                 # the whole chain kind is new (vs band raised)
    assemblers: List[str] = field(default_factory=list)  # distinct authors of pre-existing links

    @property
    def supplied_orders(self) -> List[int]:
        return [s.step.order for s in self.steps if s.provenance == "newly-introduced"]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": self.path.title,
            "kind": self.path.kind,
            "score": self.path.score,
            "band": self.path.band.value,
            "new_kind": self.new_kind,
            "supplied_steps": self.supplied_orders,
            "assemblers": list(self.assemblers),
            "steps": [s.to_dict() for s in self.steps],
        }


def _scan_now(cfg) -> Any:
    """Run an Orchestrator scan synchronously, inside or outside an event loop."""
    from ..core.orchestrator import Orchestrator

    def runner():
        return asyncio.run(Orchestrator(cfg).run())
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return runner()
    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        return ex.submit(runner).result()


def _reconstruct_tree(root: Path, ref: str, dest: Path) -> bool:
    """Materialize the tracked tree at ``ref`` into ``dest`` via ``git archive | tar``."""
    try:
        archive = subprocess.run(
            ["git", "-C", str(root), "archive", ref],
            capture_output=True, timeout=60, check=False)
        if archive.returncode != 0 or not archive.stdout:
            return False
        dest.mkdir(parents=True, exist_ok=True)
        tar = subprocess.run(["tar", "-x", "-C", str(dest)], input=archive.stdout,
                             capture_output=True, timeout=60, check=False)
        return tar.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _scan_paths(treeroot: Path) -> List[AttackPath]:
    from ..core.config import Config
    cfg = Config(target=treeroot, reachability=True, skip_detectors=["runtime"])
    result = _scan_now(cfg)
    return [p for p in result.attack_paths if not getattr(p, "ai_verified", False)]


def _before_index(paths_before: List[AttackPath]) -> Dict[str, int]:
    """kind -> highest band rank present before the change."""
    idx: Dict[str, int] = {}
    for p in paths_before:
        idx[p.kind] = max(idx.get(p.kind, -1), p.band.rank)
    return idx


def keystone(root: Path, diff_ref: str, paths_after: List[AttackPath]) -> List[KeystonePath]:
    """Return the kill chains the change at ``diff_ref`` armed (pre-existing + new links)."""
    after = [p for p in (paths_after or []) if not getattr(p, "ai_verified", False)]
    if not after or not diff_ref:
        return []
    try:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / "base"
            if not _reconstruct_tree(root, diff_ref, base):
                return []
            before_idx = _before_index(_scan_paths(base))

        changed = changed_lines(root, diff_ref)
        if changed is None:
            return []
        in_range = gitblame.commits_in_range(root, diff_ref)

        out: List[KeystonePath] = []
        for p in after:
            prev = before_idx.get(p.kind, -1)
            if p.kind in before_idx and p.band.rank <= prev:
                continue  # this kind already existed at >= this severity → not newly armed
            ks = _classify(root, p, changed, in_range)
            if ks is not None:
                out.append(ks)
        out.sort(key=lambda k: -k.path.score)
        return out
    except Exception as exc:  # noqa: BLE001 — temporal analysis is best-effort
        logger.debug("keystone analysis failed: %s", exc)
        return []


def _classify(root: Path, path: AttackPath, changed, in_range) -> Optional[KeystonePath]:
    """Split a path's steps into newly-introduced vs pre-existing; keystone iff both."""
    steps: List[KeystoneStep] = []
    has_new = has_old = False
    assemblers: List[str] = []
    for step in path.steps:
        if in_diff(changed, step.file, step.line):
            steps.append(KeystoneStep(step, "newly-introduced"))
            has_new = True
            continue
        blamed = gitblame.blame_line(root, step.file, step.line)
        # a line last touched by a commit IN the change range is part of the change
        if blamed is None or blamed[0] in in_range:
            steps.append(KeystoneStep(step, "newly-introduced"))
            has_new = True
            continue
        sha, author, epoch = blamed
        date = datetime.fromtimestamp(epoch, tz=timezone.utc).date().isoformat() if epoch else None
        steps.append(KeystoneStep(step, "pre-existing", born_commit=sha,
                                  born_author=author, born_date=date))
        has_old = True
        if author not in assemblers:
            assemblers.append(author)
    if not (has_new and has_old):
        return None
    return KeystonePath(path=path, steps=steps, new_kind=True, assemblers=assemblers)
