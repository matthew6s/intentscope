"""Vulnerability rules for Android deep links and exported components.

Each rule is a pure function of the parsed components, so the engine is
fully unit-testable without androguard or an APK.
"""
from __future__ import annotations

from .models import Component, Finding


def _fmt_filters(schemes: list[str], hosts: list[str]) -> str:
    host_part = ", ".join(sorted(set(hosts))) if hosts else "(any host)"
    return f"scheme(s) {', '.join(sorted(set(schemes)))} on {host_part}"


def rule_unverified_app_link(c: Component) -> list[Finding]:
    """HIGH: an http/https BROWSABLE deep link on an exported component whose
    filter does not set android:autoVerify. Without verified App Links, any
    other installed app can register the same host and hijack the link."""
    out: list[Finding] = []
    if not c.is_effectively_exported:
        return out
    for f in c.intent_filters:
        if f.is_browsable and f.web_schemes and not f.auto_verify:
            out.append(Finding(
                rule_id="IS001",
                severity="HIGH",
                title="Unverified web deep link (hijackable App Link)",
                component=c.name,
                detail=(
                    f"Exported {c.kind} handles a browsable web deep link "
                    f"({_fmt_filters(f.web_schemes, f.hosts)}) without "
                    f"android:autoVerify. A competing app can claim the same "
                    f"host and intercept these links."
                ),
                recommendation=(
                    "Set android:autoVerify=\"true\" on the intent-filter and "
                    "host a matching /.well-known/assetlinks.json, or restrict "
                    "the component's exposure."
                ),
            ))
    return out


def rule_custom_scheme_hijack(c: Component) -> list[Finding]:
    """MEDIUM: a custom-scheme BROWSABLE deep link on an exported component.
    Custom schemes cannot be verified, so any app can register the same
    scheme and receive the intent."""
    out: list[Finding] = []
    if not c.is_effectively_exported:
        return out
    for f in c.intent_filters:
        if f.is_browsable and f.custom_schemes:
            out.append(Finding(
                rule_id="IS002",
                severity="MEDIUM",
                title="Custom-scheme deep link (unverifiable, hijackable)",
                component=c.name,
                detail=(
                    f"Exported {c.kind} handles a custom-scheme deep link "
                    f"({_fmt_filters(f.custom_schemes, f.hosts)}). Custom "
                    f"schemes have no ownership verification; any installed "
                    f"app may register the same scheme."
                ),
                recommendation=(
                    "Prefer verified https App Links. If a custom scheme is "
                    "required, treat all incoming data as untrusted and never "
                    "use it for auth callbacks or to load privileged content."
                ),
            ))
    return out


def rule_exported_no_permission(c: Component) -> list[Finding]:
    """LOW: a component that is exported (or implicitly exported via an
    intent-filter) with no permission guard is reachable by any app."""
    out: list[Finding] = []
    if not c.is_effectively_exported or c.permission:
        return out
    implicit = c.exported is None and c.has_intent_filter
    out.append(Finding(
        rule_id="IS003",
        severity="LOW",
        title=("Implicitly exported component with no permission"
               if implicit else "Exported component with no permission"),
        component=c.name,
        detail=(
            f"{c.kind} '{c.name}' is reachable by other apps"
            + (" (implicitly exported via an intent-filter; explicitly set "
               "android:exported to make intent clear)" if implicit else "")
            + " and declares no android:permission."
        ),
        recommendation=(
            "Set android:exported=\"false\" if external access is not needed, "
            "or guard the component with a signature-level permission."
        ),
    ))
    return out


def rule_launchmode_task_hijack(c: Component) -> list[Finding]:
    """INFO: an exported deep-linked activity using singleTask/singleInstance
    increases task-affinity / StrandHogg-style hijack surface."""
    out: list[Finding] = []
    if c.kind not in ("activity", "activity-alias"):
        return out
    if not c.is_effectively_exported or not c.has_intent_filter:
        return out
    if (c.launch_mode or "").lower() in ("singletask", "singleinstance"):
        out.append(Finding(
            rule_id="IS004",
            severity="INFO",
            title="Deep-linked activity uses singleTask/singleInstance",
            component=c.name,
            detail=(
                f"Exported activity '{c.name}' has launchMode="
                f"{c.launch_mode} and an intent-filter, which can widen "
                f"task-affinity / task-hijacking surface."
            ),
            recommendation=(
                "Review task affinity and consider taskAffinity=\"\" plus "
                "FLAG_ACTIVITY_NEW_TASK handling; validate the calling context."
            ),
        ))
    return out


ALL_RULES = [
    rule_unverified_app_link,
    rule_custom_scheme_hijack,
    rule_exported_no_permission,
    rule_launchmode_task_hijack,
]


def scan_components(components: list[Component]) -> list[Finding]:
    findings: list[Finding] = []
    for c in components:
        for rule in ALL_RULES:
            findings.extend(rule(c))
    from .models import SEVERITY_ORDER
    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.rule_id, f.component))
    return findings
