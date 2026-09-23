"""One answer to "is this component governed?", for every reader of the graph.

There were three, and they disagreed about half the vocabulary.

=================  =========  =====  =========  =======  =========  =======
predicate          approved   known  unmanaged  unknown  high_risk  retired
=================  =========  =====  =========  =======  =========  =======
``_MANAGED``       governed   gov.   SHADOW     SHADOW   SHADOW     SHADOW
``== UNMANAGED``   governed   gov.   SHADOW     gov.     gov.       gov.
``{UNMANAGED,      governed   gov.   SHADOW     SHADOW   gov.       gov.
  UNKNOWN}``
=================  =========  =====  =========  =======  =========  =======

Measured consequences, on one deployment, through the real derivers:

- A deployment whose entire inventory is one **high-risk** component reported
  posture ``baseline`` -- the best band there is -- because the posture rule
  counted only ``unmanaged``. The capability map on the same deployment reported
  one shadow capability. An executive reading the headline and an engineer
  reading the map were looking at opposite conclusions about one asset.
- Six assets, four of them ungoverned by any reading: the vendor report said
  "4 ungoverned dependencies", the executive summary's headline said "1 shadow
  asset", and ``coverage_ratio`` said 67% of the graph was classified. One
  summary, one set of rows, three numbers.
- A ``retired`` or ``high_risk`` asset could drive EFFECTIVE_ACCESS to
  CONTRADICTED (that claim reads the ``_MANAGED`` predicate) while the AI_BOM
  and DATA_BOUNDARY claims about the *same asset* stayed clean and reported zero
  shadow components (they read ``== UNMANAGED``).

And nothing in the platform ever *writes* ``high_risk`` or ``retired``: every
derived classification is APPROVED, KNOWN or UNMANAGED. Those two arrive only
when a person sets them. So the case the headline could not see was precisely
the case where somebody had looked at a component and said, explicitly, that it
is dangerous.

WHAT THIS MODULE DECIDES

``GOVERNED`` is the narrow reading -- APPROVED or KNOWN -- because that is what
"somebody has accounted for this and stands behind it" means, and it is the
reading the claim layer already used. Everything else is shadow.

``is_governed`` FAILS SAFE. A classification this module does not recognise --
a blank string from an import or a migration, a seventh enum member added later
and not wired in here -- is shadow, not governed. The old ``== UNMANAGED`` sites
did the opposite: an unrecognised value read as governed, under-reporting risk,
and silently. A value we cannot interpret is not evidence that a component is
fine.

WHAT THIS MODULE DOES NOT DECIDE

"Has this component been classified at all" is a different question with a
different answer, and it keeps its own predicate in :mod:`assurance.roi`
(``_COVERAGE_GAP_CLASSIFICATIONS``). Coverage and governance are two axes: an
asset can be classified and ungoverned, which is exactly what ``high_risk``
means. Folding them together is how three predicates became three answers.
"""

from __future__ import annotations

from .models import Asset

# Somebody has accounted for this component and stands behind it. APPROVED is an
# explicit sign-off; KNOWN is "it is in the inventory and nobody has flagged it".
GOVERNED = frozenset({Asset.Classification.APPROVED, Asset.Classification.KNOWN})

# Every other member of the enum, derived rather than listed, so adding a
# classification cannot quietly leave it out of one set and in the other.
SHADOW = frozenset(Asset.Classification.values) - GOVERNED


def is_governed(classification) -> bool:
    """Whether a component counts as under governance.

    Fails safe: anything this module does not recognise is NOT governed. That is
    deliberately the opposite of the ``== UNMANAGED`` checks this replaces,
    where a blank or unexpected value read as governed -- an answer that
    under-reports risk, from the one input that says we do not know.
    """
    return classification in GOVERNED


def is_shadow(classification) -> bool:
    """Whether a component is outside governance -- unmanaged, unknown, flagged
    high-risk, retired-but-reachable, or a value we cannot interpret."""
    return not is_governed(classification)
