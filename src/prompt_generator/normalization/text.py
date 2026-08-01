"""General text normalization helpers."""

from __future__ import annotations

import re
import unicodedata


def collapse_whitespace(text: str) -> str:
    """Collapse runs of whitespace into a single space and trim."""
    return re.sub(r"\s+", " ", text).strip()


def normalize_unicode(text: str) -> str:
    """Normalize unicode to NFKC to avoid homoglyph issues."""
    return unicodedata.normalize("NFKC", text)


def count_sentences(text: str) -> int:
    """Simple sentence count based on terminal punctuation."""
    return text.count(".") + text.count("?") + text.count("!")
