# Project Argus Architecture

Project Argus 3.0 is a local, evidence-based browser security engine. It does not call an external AI service. The Chrome extension is the authoritative detector; the FastAPI process is an optional static demo server and compatibility endpoint.

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
  "priority": 1,
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
- Network Analyzer: write methods, insecure HTTP transport, cross-domain destinations, beacons/pings, query-bearing image requests, and post-submit timing.
- Decision Combiner: high-confidence combinations that are stronger than an isolated signal.

## Score Calibration

Evidence points are multiplied by confidence. Repeated evidence in one category receives diminishing weight, and secondary categories contribute only a fraction of their score. Score floors guarantee that directly observed unprotected sensitive transfers cannot be diluted by weaker observations.

- `0-34`: SAFE
- `35-69`: SUSPICIOUS
- `70-100`: HIGH_RISK
- Priority 1, `OBSERVED_DATA_FLOW`: unencrypted sensitive writes, cross-domain sensitive writes, beacon-like transfer after sensitive interaction, and direct unsafe sensitive form actions.
- Priority 2, `CONTEXT_OR_INTENT`: HTTP/domain/OTP/login metadata, static script sinks, endpoint assembly, and suspicious download context.
- Priority 3, `CONTENT_CATEGORY`: adult, gambling, image-heavy advertising, and content keywords. Content-only results are capped at 12 and remain SAFE.
- Trusted domains are capped at 20 unless decisive behavior is present.
- Search result pages are SAFE unless decisive behavior is present.
- A SAFE result always uses the SAFE category even if a weak observation was recorded.

`riskScore` represents estimated danger. `confidence` represents how strongly the available metadata supports that decision. They are intentionally separate.

## Temporal Correlation

The service worker keeps a privacy-safe 30-second event window per tab. It records event types and timestamps only, then correlates patterns such as:

```text
password/OTP/secret focus -> third-party requests
HTTP sensitive form -> unencrypted write request
form submit -> single cross-domain write or beacon
form submit -> third-party requests -> cross-domain redirect
form submit -> download click
```

Typed values, request bodies, response bodies, and request headers are never retained.

## Reliability

The modular engine is loaded with `importScripts`. If it cannot load, `service_worker.js` falls back to the previous local detector so scanning still works. Policy and category files are cached after validation/loading by the extension.

Run the detector regression suite with:

```powershell
node tests/run_detector_tests.js
node tests/run_exfiltration_calibration.js
```

The suites cover 15 legacy regressions and a 65-case exfiltration calibration corpus. The corpus is derived from browser-observable portions of MITRE ATT&CK, OWASP, NIST TLS guidance, CIC-Bell-DNS-EXF-2021, CIC-IDS2017, UNSW-NB15, and CTU-13. Full PCAP payload inspection is outside a Chrome extension's visibility boundary.
