"""Core data models for intentscope.

Kept dependency-free so the rule engine can be tested without androguard
or a real APK.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class IntentFilter:
    actions: list[str] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)
    schemes: list[str] = field(default_factory=list)
    hosts: list[str] = field(default_factory=list)
    # android:autoVerify on the <intent-filter> (App Links verification)
    auto_verify: bool = False

    @property
    def is_browsable(self) -> bool:
        return "android.intent.category.BROWSABLE" in self.categories

    @property
    def web_schemes(self) -> list[str]:
        return [s for s in self.schemes if s in ("http", "https")]

    @property
    def custom_schemes(self) -> list[str]:
        return [s for s in self.schemes if s not in ("http", "https")]


@dataclass
class Component:
    kind: str  # activity | activity-alias | service | receiver | provider
    name: str
    exported: Optional[bool]  # None = not explicitly set
    permission: Optional[str]
    intent_filters: list[IntentFilter] = field(default_factory=list)
    launch_mode: Optional[str] = None

    @property
    def has_intent_filter(self) -> bool:
        return len(self.intent_filters) > 0

    @property
    def is_effectively_exported(self) -> bool:
        """A component is reachable by other apps if exported=true, or if
        exported is unset but it declares an intent-filter (implicitly
        exported on API < 31)."""
        if self.exported is True:
            return True
        if self.exported is False:
            return False
        return self.has_intent_filter


SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}


@dataclass
class Finding:
    rule_id: str
    severity: str  # HIGH | MEDIUM | LOW | INFO
    title: str
    component: str
    detail: str
    recommendation: str

    def as_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "title": self.title,
            "component": self.component,
            "detail": self.detail,
            "recommendation": self.recommendation,
        }
