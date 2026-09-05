"""Render findings as JSON or Markdown."""
from __future__ import annotations

import json
from .models import Finding

_SEV_EMOJI = {"HIGH": "🔴", "MEDIUM": "🟠", "LOW": "🟡", "INFO": "⚪"}


def to_json(findings: list[Finding], target: str) -> str:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return json.dumps(
        {
            "target": target,
            "summary": {"total": len(findings), "by_severity": counts},
            "findings": [f.as_dict() for f in findings],
        },
        indent=2,
    )


def to_markdown(findings: list[Finding], target: str) -> str:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    lines = [f"# intentscope report — `{target}`", ""]
    if not findings:
        lines.append("No deep-link / exported-component issues found. ✅")
        return "\n".join(lines) + "\n"
    summary = " · ".join(
        f"{_SEV_EMOJI.get(s, '')} {counts[s]} {s}"
        for s in ("HIGH", "MEDIUM", "LOW", "INFO") if s in counts
    )
    lines += [f"**{len(findings)} finding(s):** {summary}", ""]
    for f in findings:
        lines += [
            f"## {_SEV_EMOJI.get(f.severity, '')} {f.severity} — {f.title} (`{f.rule_id}`)",
            f"- **Component:** `{f.component}`",
            f"- **Detail:** {f.detail}",
            f"- **Fix:** {f.recommendation}",
            "",
        ]
    return "\n".join(lines) + "\n"
