"""URL, IP, and email normalization.

Cybersecurity track prompts must use literal placeholders [URL], [IP], and
[email] instead of real or mock values.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable


_URL_RE = re.compile(r"https?://[^\s\]\)\"']+", re.IGNORECASE)
_WWW_RE = re.compile(r"www\.[^\s\]\)\"']+", re.IGNORECASE)
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")


@dataclass(frozen=True)
class ReferenceMatch:
    kind: str  # "url", "www", "ip", "email"
    value: str
    start: int
    end: int


def scan_for_unnormalized_references(text: str) -> list[ReferenceMatch]:
    """Find any real URL, IP, or email address in the text."""
    matches: list[ReferenceMatch] = []
    for regex, kind in (
        (_URL_RE, "url"),
        (_WWW_RE, "www"),
        (_IP_RE, "ip"),
        (_EMAIL_RE, "email"),
    ):
        for m in regex.finditer(text):
            matches.append(ReferenceMatch(kind, m.group(), m.start(), m.end()))
    return sorted(matches, key=lambda x: x.start)


def normalize_references(text: str) -> str:
    """Replace real references with the appropriate placeholder.

    Order matters: full URLs before bare www, and specific IPs before emails.
    """
    text = _URL_RE.sub("[URL]", text)
    text = _WWW_RE.sub("[URL]", text)
    text = _IP_RE.sub("[IP]", text)
    text = _EMAIL_RE.sub("[email]", text)
    return text


def validate_placeholders(text: str) -> list[str]:
    """Return warnings if placeholders are malformed or missing when expected."""
    issues: list[str] = []
    # Detect lowercase-only or bracket-typo placeholders.
    for bad in ("url", "ip", "email"):
        if re.search(rf"(?<!\[)\b{bad}\b(?!\])", text, re.IGNORECASE):
            issues.append(f"Possible unbracketed placeholder: {bad!r}")
    return issues
