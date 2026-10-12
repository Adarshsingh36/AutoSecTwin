"""
Small shared helpers with no business-logic ownership of their own --
kept here so ExploitExecutor (Phase 3) and PatchExecutor (Phase 4) don't
each maintain their own copy of the same parsing logic.
"""

from __future__ import annotations

from typing import Optional


def detect_version_from_image_tag(image: Optional[str]) -> Optional[str]:
    """Best-effort version extraction from a Docker image reference, e.g.
    "apache/activemq-classic:5.17.6" -> "5.17.6".

    Returns None for an untagged image or a tag with no digit in it (e.g.
    "latest"), since that's not something that can honestly be reported as
    a detected version.
    """

    if not image or ":" not in image:
        return None

    tag = image.rsplit(":", 1)[-1]

    return tag if any(ch.isdigit() for ch in tag) else None
