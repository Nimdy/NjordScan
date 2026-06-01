"""Higher-order analysis that runs *across* findings rather than on one file.

The detectors answer "is there a bug here?". This package answers the question a
developer actually cares about: **"so how do I get hacked?"** — by correlating
individual findings into the multi-step attack paths an adversary would walk.
"""

from .attack_paths import AttackPath, AttackStep, synthesize

__all__ = ["AttackPath", "AttackStep", "synthesize"]
