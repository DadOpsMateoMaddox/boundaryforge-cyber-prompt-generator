"""Duplicate and near-duplicate detection for prompt packages.

Examines both the shared topic and the complete prompt text so that two
packages on the same topic are allowed, but near-identical user content is
flagged.
"""

from __future__ import annotations

from difflib import SequenceMatcher
from typing import Any, Iterable

from ..models import PromptPackage, PromptVariant


class DuplicateScanner:
    """Scan variants for duplicate or near-duplicate content."""

    def __init__(self, threshold: float = 0.85) -> None:
        self.threshold = threshold

    def scan_package(self, package: PromptPackage) -> list[dict[str, Any]]:
        """Scan variants within a single package."""
        findings: list[dict[str, Any]] = []
        variants = package.task_spec.variants()
        texts = [(v.danger_level.value, self._full_text(v)) for v in variants]

        for i, (level_a, text_a) in enumerate(texts):
            for level_b, text_b in texts[i + 1 :]:
                ratio = SequenceMatcher(None, text_a.lower(), text_b.lower()).ratio()
                if ratio >= self.threshold:
                    findings.append(
                        {
                            "code": "DUP-001",
                            "message": f"{level_a} and {level_b} variants are near-duplicates.",
                            "severity": "error" if ratio >= 0.95 else "warning",
                            "path": f"task_spec.{level_a}.prompt_text",
                            "similarity": round(ratio, 3),
                            "threshold": self.threshold,
                        }
                    )
        return findings

    def scan_across_packages(
        self,
        packages: Iterable[PromptPackage],
    ) -> list[dict[str, Any]]:
        """Scan user text across multiple packages."""
        findings: list[dict[str, Any]] = []
        entries: list[tuple[str, str, str]] = []  # (package_id, level, text)
        for package in packages:
            for variant in package.task_spec.variants():
                entries.append(
                    (package.package_id, variant.danger_level.value, self._full_text(variant))
                )

        for i, (pkg_a, level_a, text_a) in enumerate(entries):
            for pkg_b, level_b, text_b in entries[i + 1 :]:
                ratio = SequenceMatcher(None, text_a.lower(), text_b.lower()).ratio()
                if ratio >= self.threshold:
                    findings.append(
                        {
                            "code": "DUP-002",
                            "message": f"Near-duplicate user text across packages {pkg_a} and {pkg_b}.",
                            "severity": "error" if ratio >= 0.95 else "warning",
                            "path": f"{pkg_a}.{level_a}.prompt_text",
                            "other_path": f"{pkg_b}.{level_b}.prompt_text",
                            "similarity": round(ratio, 3),
                            "threshold": self.threshold,
                        }
                    )
        return findings

    @staticmethod
    def _full_text(variant: PromptVariant) -> str:
        if variant.prompt_text:
            return variant.prompt_text
        return " ".join(t.content for t in variant.turns)
