"""Optional deep (bytecode) analysis for true intent-redirection and WebView
deep-link sinks. Requires androguard and a real .apk; slower than the manifest
scan, so it is opt-in via `intentscope <apk> --deep`.

Heuristics (a triage aid, not proof — each hit is a candidate to review):
  IS101 HIGH  intent-redirection: a class both reads an incoming Intent
              (getParcelableExtra/getIntent extras) and calls startActivity/
              startService/sendBroadcast — the classic "forward an
              attacker-controlled Intent" pattern.
  IS102 HIGH  WebView deep-link sink: a class reads Intent data/extras and
              calls WebView.loadUrl/postUrl/loadData — untrusted URL into a
              WebView (token/origin leak surface).
"""
from __future__ import annotations

from .models import Finding

# method names that read attacker-controllable Intent input
_INTENT_SOURCES = (
    "getParcelableExtra", "getStringExtra", "getSerializableExtra",
    "getBundleExtra", "getData", "getDataString", "getExtras",
)
_REDIRECT_SINKS = ("startActivity", "startActivityForResult", "startService",
                   "sendBroadcast", "startActivities")
_WEBVIEW_SINKS = ("loadUrl", "postUrl", "loadData", "loadDataWithBaseURL")

# Framework/library packages: reading an Intent and launching is normal here and
# not the app's own attack surface, so they are excluded to cut false positives.
_FRAMEWORK_PREFIXES = (
    "Landroid/", "Landroidx/", "Lcom/google/android/", "Lkotlin/", "Lkotlinx/",
    "Ldagger/", "Lio/reactivex/", "Lrx/", "Lcom/facebook/", "Lcom/squareup/",
    "Lokhttp3/", "Lretrofit2/", "Lcom/bumptech/", "Lorg/",
)


def _is_framework(cls: str) -> bool:
    return cls.startswith(_FRAMEWORK_PREFIXES)


def _classes_calling(dx, names) -> dict[str, set[str]]:
    """Map class_name -> set of sink/source method names it calls."""
    hits: dict[str, set[str]] = {}
    for name in names:
        for m in dx.find_methods(methodname=name):
            for _, caller, _ in m.get_xref_from():
                hits.setdefault(caller.class_name, set()).add(name)
    return hits


def _pretty(cls: str) -> str:
    # Lcom/example/Foo; -> com.example.Foo
    return cls.strip("L;").replace("/", ".")


def analyze_apk(path: str, exported_classes: set[str] | None = None) -> list[Finding]:
    try:
        from androguard.misc import AnalyzeAPK  # type: ignore
    except Exception as exc:  # pragma: no cover
        raise RuntimeError(
            "Deep analysis requires androguard. Install with 'pip install \"intentscope[apk]\"'."
        ) from exc

    _a, _d, dx = AnalyzeAPK(path)

    def _keep(cls: str) -> bool:
        if _is_framework(cls):
            return False
        if exported_classes:
            # only the app's externally-reachable components are real surface
            return _pretty(cls) in exported_classes
        return True

    sources = _classes_calling(dx, _INTENT_SOURCES)
    redirects = _classes_calling(dx, _REDIRECT_SINKS)
    webviews = _classes_calling(dx, _WEBVIEW_SINKS)

    findings: list[Finding] = []
    for cls in sorted(c for c in (sources.keys() & redirects.keys()) if _keep(c)):
        findings.append(Finding(
            rule_id="IS101", severity="HIGH",
            title="Possible intent redirection",
            component=_pretty(cls),
            detail=(f"Class reads incoming Intent data ({', '.join(sorted(sources[cls]))}) "
                    f"and calls a launch sink ({', '.join(sorted(redirects[cls]))}). If the "
                    f"forwarded Intent is attacker-controlled, this can redirect into "
                    f"non-exported components (intent redirection)."),
            recommendation=("Validate/allowlist the target before forwarding; never pass an "
                            "externally-supplied Intent/URI straight into startActivity et al. "
                            "Strip GRANT_URI flags and set the component explicitly."),
        ))
    for cls in sorted(c for c in (sources.keys() & webviews.keys()) if _keep(c)):
        findings.append(Finding(
            rule_id="IS102", severity="HIGH",
            title="Untrusted Intent data into WebView",
            component=_pretty(cls),
            detail=(f"Class reads incoming Intent data ({', '.join(sorted(sources[cls]))}) "
                    f"and calls a WebView sink ({', '.join(sorted(webviews[cls]))}). A "
                    f"deep-link-supplied URL loaded into a WebView can leak tokens/cookies "
                    f"or reach privileged JS bridges."),
            recommendation=("Allowlist the origin/scheme before loadUrl; disable "
                            "JavaScript/file access for untrusted content; never forward "
                            "auth tokens to a deep-link-controlled URL."),
        ))
    from .models import SEVERITY_ORDER
    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.rule_id, f.component))
    return findings
