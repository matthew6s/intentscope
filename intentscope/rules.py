"""Vulnerability rules for Android deep links and exported components.

Each rule is a pure function of the parsed manifest, so the engine is fully
unit-testable without androguard or an APK.
"""
from __future__ import annotations

from .models import Application, Component, Finding, SEVERITY_ORDER


def _fmt(schemes: list[str], hosts: list[str]) -> str:
    host_part = ", ".join(sorted(set(hosts))) if hosts else "(any host)"
    return f"scheme(s) {', '.join(sorted(set(schemes)))} on {host_part}"


# --- component rules -------------------------------------------------------

def rule_unverified_app_link(c: Component) -> list[Finding]:
    out: list[Finding] = []
    if not c.is_effectively_exported:
        return out
    for f in c.intent_filters:
        if f.is_browsable and f.web_schemes and not f.auto_verify:
            out.append(Finding(
                rule_id="IS001", severity="HIGH",
                title="Unverified web deep link (hijackable App Link)",
                component=c.name,
                detail=(f"Exported {c.kind} handles a browsable web deep link "
                        f"({_fmt(f.web_schemes, f.hosts)}) without android:autoVerify. "
                        f"A competing app can claim the same host and intercept these links."),
                recommendation=('Set android:autoVerify="true" on the intent-filter and host a '
                                'matching /.well-known/assetlinks.json, or restrict the component.'),
            ))
    return out


def rule_custom_scheme_hijack(c: Component) -> list[Finding]:
    out: list[Finding] = []
    if not c.is_effectively_exported:
        return out
    for f in c.intent_filters:
        if f.is_browsable and f.custom_schemes:
            out.append(Finding(
                rule_id="IS002", severity="MEDIUM",
                title="Custom-scheme deep link (unverifiable, hijackable)",
                component=c.name,
                detail=(f"Exported {c.kind} handles a custom-scheme deep link "
                        f"({_fmt(f.custom_schemes, f.hosts)}). Custom schemes have no ownership "
                        f"verification; any installed app may register the same scheme."),
                recommendation=("Prefer verified https App Links. If a custom scheme is required, "
                                "treat incoming data as untrusted and never use it for auth "
                                "callbacks or to load privileged content."),
            ))
    return out


def rule_exported_no_permission(c: Component) -> list[Finding]:
    out: list[Finding] = []
    if not c.is_effectively_exported or c.permission:
        return out
    implicit = c.exported is None and c.has_intent_filter
    out.append(Finding(
        rule_id="IS003", severity="LOW",
        title=("Implicitly exported component with no permission" if implicit
               else "Exported component with no permission"),
        component=c.name,
        detail=(f"{c.kind} '{c.name}' is reachable by other apps"
                + (" (implicitly exported via an intent-filter; set android:exported explicitly)"
                   if implicit else "") + " and declares no android:permission."),
        recommendation=('Set android:exported="false" if external access is not needed, or guard '
                        'the component with a signature-level permission.'),
    ))
    return out


def rule_launchmode_task_hijack(c: Component) -> list[Finding]:
    out: list[Finding] = []
    if c.kind not in ("activity", "activity-alias"):
        return out
    if not c.is_effectively_exported or not c.has_intent_filter:
        return out
    if (c.launch_mode or "").lower() in ("singletask", "singleinstance"):
        out.append(Finding(
            rule_id="IS004", severity="INFO",
            title="Deep-linked activity uses singleTask/singleInstance",
            component=c.name,
            detail=(f"Exported activity '{c.name}' has launchMode={c.launch_mode} and an "
                    f"intent-filter, which can widen task-affinity / task-hijacking surface."),
            recommendation=('Review task affinity (consider taskAffinity="") and validate the '
                            'calling context.'),
        ))
    return out


def rule_exported_provider_grant_uri(c: Component) -> list[Finding]:
    out: list[Finding] = []
    if c.kind != "provider" or not c.is_effectively_exported or c.permission:
        return out
    if c.grant_uri_permissions:
        out.append(Finding(
            rule_id="IS005", severity="HIGH",
            title="Exported ContentProvider with grantUriPermissions and no permission",
            component=c.name,
            detail=(f"provider '{c.name}' is exported, sets grantUriPermissions, and declares no "
                    f"android:permission. Any app can be granted URI access — a common "
                    f"path-traversal / arbitrary-file-read sink."),
            recommendation=('Set android:exported="false" if not needed, add a signature-level '
                            'android:permission, and constrain <grant-uri-permission> paths.'),
        ))
    return out


ALL_RULES = [
    rule_unverified_app_link,
    rule_custom_scheme_hijack,
    rule_exported_no_permission,
    rule_launchmode_task_hijack,
    rule_exported_provider_grant_uri,
]


# --- application rules -----------------------------------------------------

def scan_application(app: Application) -> list[Finding]:
    out: list[Finding] = []
    if app.debuggable is True:
        out.append(Finding(
            rule_id="IS006", severity="HIGH",
            title="Application is debuggable", component="<application>",
            detail=('android:debuggable="true" ships a debuggable build; anyone with device '
                    'access can attach a debugger, read memory, and run code as the app.'),
            recommendation="Never ship debuggable builds; release builds must set debuggable=false.",
        ))
    if app.allow_backup is not False:
        out.append(Finding(
            rule_id="IS007", severity="MEDIUM",
            title="Application data is backup-enabled", component="<application>",
            detail=("android:allowBackup is not disabled"
                    + ("" if app.allow_backup is True else " (defaults to true)")
                    + ", so app data can be extracted via 'adb backup' on many devices."),
            recommendation=('Set android:allowBackup="false" (or a strict backup-rules XML) for '
                            'apps holding sensitive data.'),
        ))
    if app.uses_cleartext_traffic is True:
        out.append(Finding(
            rule_id="IS008", severity="MEDIUM",
            title="Cleartext (HTTP) traffic is permitted", component="<application>",
            detail=('android:usesCleartextTraffic="true" allows unencrypted HTTP, exposing '
                    'traffic to interception and tampering.'),
            recommendation=('Set usesCleartextTraffic="false" and require TLS via a '
                            'networkSecurityConfig.'),
        ))
    return out


# --- entry points ----------------------------------------------------------

def _scan_components_unsorted(components: list[Component]) -> list[Finding]:
    findings: list[Finding] = []
    for c in components:
        for rule in ALL_RULES:
            findings.extend(rule(c))
    return findings


def scan_components(components: list[Component]) -> list[Finding]:
    findings = _scan_components_unsorted(components)
    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.rule_id, f.component))
    return findings


def scan(application: Application, components: list[Component]) -> list[Finding]:
    findings = scan_application(application) + _scan_components_unsorted(components)
    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.rule_id, f.component))
    return findings
