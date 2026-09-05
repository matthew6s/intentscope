# intentscope

**Find hijackable Android deep links and risky exported components before an attacker does.**

`intentscope` scans an Android app's manifest for the deep-link and
intent-redirection patterns that lead to real vulnerabilities — link
hijacking, unverifiable custom-scheme OAuth callbacks, and unguarded exported
components — and reports each with a severity, the exact component, and a fix.

It runs on a full `.apk` (via [androguard](https://github.com/androguard/androguard))
**or** a decoded `AndroidManifest.xml` with **zero dependencies** for the XML path.

## Why

Most mobile scanners are broad. `intentscope` is focused on the deep-link /
intent surface that shows up again and again in bug-bounty reports:

- **Unverified web deep links** — an `http(s)` `BROWSABLE` link on an exported
  component with no `android:autoVerify`: a competing app can claim the host
  and hijack the link.
- **Custom-scheme deep links** — `myapp://…` links can't be verified; any app
  can register the same scheme. Especially dangerous for OAuth/auth callbacks.
- **Exported components without a permission** — reachable by any app,
  including the classic intent-redirection sink.
- **Deep-linked `singleTask`/`singleInstance` activities** — wider
  task-affinity / task-hijack surface.

## Install

```bash
pipx install intentscope           # or: pip install intentscope
pip install "intentscope[apk]"     # add androguard for scanning .apk files
```

## Usage

```bash
# Decoded manifest (no extra deps):
intentscope path/to/AndroidManifest.xml

# Full APK (needs the [apk] extra):
intentscope app.apk

# Reports + CI gating:
intentscope app.apk --md report.md --json report.json --fail-on HIGH
```

Exit code is non-zero when a finding at or above `--fail-on` (default `HIGH`)
is present, so it drops straight into CI.

### Example

```
$ intentscope examples/AndroidManifest.xml
[HIGH]   IS001 .OpenUrlActivity: Unverified web deep link (hijackable App Link)
[MEDIUM] IS002 .AuthCallbackActivity: Custom-scheme deep link (unverifiable, hijackable)
[LOW]    IS003 .ExportedSyncService: Exported component with no permission
[INFO]   IS004 .OpenUrlActivity: Deep-linked activity uses singleTask/singleInstance
```

## Rules

| ID | Severity | What it catches |
|----|----------|-----------------|
| IS001 | HIGH | Exported web deep link without `autoVerify` (hijackable App Link) |
| IS002 | MEDIUM | Exported custom-scheme deep link (unverifiable) |
| IS003 | LOW | Exported / implicitly-exported component with no permission |
| IS004 | INFO | Deep-linked `singleTask`/`singleInstance` activity |

## Roadmap

- Bytecode analysis for true **intent-redirection** sinks (`getIntent()` extra → `startActivity`)
- **WebView** deep-link → `loadUrl` token-leak detection
- SARIF output and a GitHub Action

## License

MIT
