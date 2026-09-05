"""intentscope command-line interface."""
from __future__ import annotations

import argparse
import sys

from .manifest import load_components
from .report import to_json, to_markdown
from .rules import scan_components

_EXIT_FINDINGS = 1
_EXIT_CLEAN = 0
_EXIT_ERROR = 2


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="intentscope",
        description="Scan an Android app for hijackable deep links and risky "
                    "exported components (intent-redirection surface).",
    )
    parser.add_argument("target", help="path to an .apk or a decoded AndroidManifest.xml")
    parser.add_argument("--json", metavar="FILE", help="write JSON report to FILE")
    parser.add_argument("--md", metavar="FILE", help="write Markdown report to FILE")
    parser.add_argument("--format", choices=("text", "json", "md"), default="text",
                        help="stdout format (default: text)")
    parser.add_argument("--fail-on", choices=("HIGH", "MEDIUM", "LOW", "INFO", "never"),
                        default="HIGH",
                        help="exit non-zero if a finding at or above this severity "
                             "is present (default: HIGH); 'never' always exits 0")
    args = parser.parse_args(argv)

    try:
        components = load_components(args.target)
    except (FileNotFoundError, RuntimeError) as exc:
        print(f"intentscope: {exc}", file=sys.stderr)
        return _EXIT_ERROR

    findings = scan_components(components)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            fh.write(to_json(findings, args.target))
    if args.md:
        with open(args.md, "w", encoding="utf-8") as fh:
            fh.write(to_markdown(findings, args.target))

    if args.format == "json":
        print(to_json(findings, args.target))
    elif args.format == "md":
        print(to_markdown(findings, args.target))
    else:
        if not findings:
            print(f"intentscope: no issues found in {args.target} "
                  f"({len(components)} components scanned).")
        else:
            for f in findings:
                print(f"[{f.severity}] {f.rule_id} {f.component}: {f.title}")
            print(f"\n{len(findings)} finding(s) across {len(components)} components.")

    from .models import SEVERITY_ORDER
    if args.fail_on != "never":
        threshold = SEVERITY_ORDER[args.fail_on]
        if any(SEVERITY_ORDER.get(f.severity, 9) <= threshold for f in findings):
            return _EXIT_FINDINGS
    return _EXIT_CLEAN


if __name__ == "__main__":
    raise SystemExit(main())
