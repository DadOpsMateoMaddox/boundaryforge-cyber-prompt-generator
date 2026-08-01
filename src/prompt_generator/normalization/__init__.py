"""Normalization utilities for prompt text and placeholders."""

from .urls import normalize_references, scan_for_unnormalized_references
from .text import collapse_whitespace, normalize_unicode

__all__ = [
    "normalize_references",
    "scan_for_unnormalized_references",
    "collapse_whitespace",
    "normalize_unicode",
]
