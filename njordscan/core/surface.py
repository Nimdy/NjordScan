"""Deployment-surface classification.

A finding in a local setup script, build tool, CI config, or a test file is real,
but it is *not* part of the application you ship — so it should be de-prioritized
(never hidden). Paths here are relative to the scanned project root, so a real
top-level ``scripts/`` matches while an in-app route like ``app/tools/page.tsx``
does not.
"""

from __future__ import annotations

# Conventionally TOP-LEVEL, non-deployed directories. Matched only at the project
# root so an in-app folder (e.g. app/tools/, app/test/) is NOT mistaken for tooling.
_ROOT_DIR_MARKERS = (
    "scripts", "tools", "bin", ".github", ".storybook",
    "cypress", "playwright", "e2e", "test", "tests",
)
# Test/mock directories legitimately colocated anywhere in the tree.
_ANY_DIR_MARKERS = ("__tests__", "__mocks__", "__fixtures__")
# Filename markers (a test/story file colocated next to the code it covers).
_SUFFIX_MARKERS = (".test.", ".spec.", ".stories.", ".cy.", ".e2e.")


def is_dev_only_path(path: str) -> bool:
    """True if ``path`` (project-relative) is dev/test/build tooling, not shipped
    application code. Conservative: top-level tooling dirs, colocated test dirs, and
    test/story filename suffixes only."""
    if not path:
        return False
    low = path.replace("\\", "/").strip("/").lower()
    if low.split("/", 1)[0] in _ROOT_DIR_MARKERS:
        return True
    framed = "/" + low + "/"
    if any(("/" + d + "/") in framed for d in _ANY_DIR_MARKERS):
        return True
    return any(s in low for s in _SUFFIX_MARKERS)
