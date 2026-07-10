# Project Argus Architecture

Project Argus 2.0 is a local, evidence-based browser security engine. It does not call an external AI service. The Chrome extension is the authoritative detector; the FastAPI process is an optional static demo server and compatibility endpoint.

## Data Flow

```text
content.js page metadata scan
  -> service_worker.js normalization and per-tab event correlation
  -> engine/argus_engine.js modular analyzers
  -> evidence/confidence combiner using engine/detection_policy.json
  -> SAFE, SUSPICIOUS, or HIGH_RISK decision
  -> storage, popup report, badge, and optional warning overlay
```

## Analyzer Contract

Every analyzer produces evidence with the same fields:

```json
{
  "id": "PASSWORD_CROSS_DOMAIN",
  "tool": "FORM_ANALYZER",
  "category": "DATA_EXFILTRATION",
  "points": 65,
  "confidence": 0.96,
  "severity": "critical",
  "message": "Password form submits to a different domain.",
  "decisive": true
}
```

The engine currently runs these tools:

- Domain Analyzer: suspicious host structure, punycode, IP hosts, and brand lookalikes.
- Credential Analyzer: password, OTP, banking, login, and disguised credential fields.
- Form Analyzer: cross-domain and insecure HTTP form behavior.
- Script Intent Analyzer: endpoint assembly, guarded sends, popup relays, clipboard/file metadata, and JavaScript form sinks.
- Download Analyzer: real APK hrefs, third-party APKs, and insecure APK delivery.
- Content Analyzer: gambling, adult content, scam language, aggressive ads, and popup abuse.
- Network Analyzer: third-party activity after credential/form interaction and post-submit redirects/downloads.
- Decision Combiner: high-confidence combinations that are stronger than an isolated signal.

## Score Calibration

Evidence points are multiplied by confidence. Repeated evidence in one category receives diminishing weight, and secondary categories contribute only a fraction of their score. This prevents many weak keywords from automatically becoming `100/100`.

- `0-34`: SAFE
- `35-69`: SUSPICIOUS
- `70-100`: HIGH_RISK
- Adult or gambling evidence alone is capped at 55 and classified as `CONTENT_RISK`.
- Trusted domains are capped at 20 unless decisive behavior is present.
- Search result pages are SAFE unless decisive behavior is present.
- A SAFE result always uses the SAFE category even if a weak observation was recorded.

`riskScore` represents estimated danger. `confidence` represents how strongly the available metadata supports that decision. They are intentionally separate.

## Temporal Correlation

The service worker keeps a privacy-safe 30-second event window per tab. It records event types and timestamps only, then correlates patterns such as:

```text
password focus -> third-party requests
form submit -> third-party requests -> cross-domain redirect
form submit -> download click
```

Typed values, request bodies, response bodies, and request headers are never retained.

## Reliability

The modular engine is loaded with `importScripts`. If it cannot load, `service_worker.js` falls back to the previous local detector so scanning still works. Policy and category files are cached after validation/loading by the extension.

Run the detector regression suite with:

```powershell
node tests/run_detector_tests.js
```

The suite covers safe pages, trusted/search false-positive guards, fake stores, fake banks, content-only risk, insecure and cross-domain forms, temporal exfiltration, aggressive advertising, and the three evasive test-only scenarios.
