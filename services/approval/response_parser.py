from __future__ import annotations

import re


def interpret_human_response(response: str | None) -> str:
    """Classify clear approval/rejection text; keep revisions and ambiguity pending."""

    text = (response or "").strip().lower()
    normalized = re.sub(r"[^a-z0-9' ]+", " ", text)
    normalized = " ".join(normalized.split())
    if not normalized:
        return "unclear"

    revision_markers = (
        "change",
        "modify",
        "revise",
        "update",
        "instead",
        "different",
        "rather than",
        "what if",
        "use version",
        "not this",
    )
    if any(re.search(rf"\b{re.escape(marker)}\b", normalized) for marker in revision_markers):
        return "revision_requested"

    negative = (
        r"^(no|n|reject|rejected|decline|declined|deny|denied)$",
        r"^(do not|don't|dont) (apply|proceed|deploy)$",
        r"^(i )?(do not|don't|dont) (approve|accept|agree|authorize)(\b|$).*",
        r"^(i )?(reject|decline|deny)(\b|$).*",
        r"^(i am|i'm) not in favor(\b|$).*",
        r"^(stop|not approved|leave it unresolved)$",
        r"^(no|reject|decline|deny)[ ,].*",
    )
    if any(re.fullmatch(pattern, normalized) for pattern in negative):
        return "rejected"

    positive = (
        r"^(yes|y|approve|approved|proceed|apply|go ahead|do it|looks good)$",
        r"^(yes|approve|approved|proceed|apply|go ahead)[ ,].*",
        r"^(i )?(approve|accept|agree|authorize)(\b|$).*",
        r"^(i am|i'm) in favor(\b|$).*",
        r"^(that|this) (looks|sounds) good(\b|$).*",
    )
    if any(re.fullmatch(pattern, normalized) for pattern in positive):
        return "approved"

    return "unclear"