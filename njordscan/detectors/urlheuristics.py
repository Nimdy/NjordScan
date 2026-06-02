"""Shared URL heuristic: does a fetch/axios URL target an attacker-controllable HOST?

SSRF requires the *host/destination* of a request to be attacker-influenced. A
relative URL (``/api/x``, ``./x``) is same-origin, and a URL with a fixed literal
host (``https://api.stripe.com/${id}``) has a fixed destination — in both cases
whatever flows into the *path or query* is not SSRF. Only when the host itself is
dynamic (a bare variable, a leading interpolation, ``https://${h}/``) can it be
SSRF. This keeps the SSRF detectors from screaming on ordinary same-origin
``fetch(`/api/...`)`` calls — the dominant false positive on real apps.
"""

from __future__ import annotations

import re

# A URL string/template that STARTS relative: /x (not //), ./x, ../x, ?x, #x.
_REL_PREFIX = re.compile(r"""^[`'"]?\s*(?:/(?!/)|\./|\.\./|\?|#)""")
# Starts with an absolute URL whose host is a LITERAL (no ${...} in the host part).
_LITERAL_HOST = re.compile(r"""^[`'"]?\s*(?:https?:)?//[^/`$'"\s{]+""")


def fetch_host_is_dynamic(url_text: str) -> bool:
    """True only if the request URL's HOST could be attacker-controlled.

    Returns False for same-origin (relative) and fixed-literal-host URLs — those
    are not SSRF no matter what flows into the path/query. A bare variable or an
    interpolation in the host position still returns True (keep flagging)."""
    if not url_text:
        return True
    a = url_text.strip()
    # 1. relative URL -> same-origin -> never SSRF
    if _REL_PREFIX.match(a):
        return False
    # 2. absolute URL with a literal host -> fixed destination -> not SSRF
    if _LITERAL_HOST.match(a):
        return False
    # 3. template literal starting with literal non-URL text and no scheme
    #    (e.g. `api/v1/${id}`) -> relative path -> same-origin
    if a.startswith("`"):
        body = a[1:]
        i = body.find("${")
        prefix = (body if i < 0 else body[:i]).strip()
        if prefix and "://" not in prefix and not prefix.startswith("//"):
            return False
    # 4. bare var, `${host}/...`, `https://${host}/...`, "http://"+h -> host dynamic
    return True
