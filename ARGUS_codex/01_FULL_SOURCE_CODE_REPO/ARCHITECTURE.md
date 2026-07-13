# Project Argus Architecture

## Evidence-first flow

```text
content.js + webRequest metadata
  -> engine/argus_engine.js (legacy evidence and advisory score)
  -> engine/brand_identity.js + versioned brand registry
  -> local offscreen perceptual hash support when reviewed visual hashes exist
  -> optional hostname-only loopback reputation gateway
  -> engine/evidence_decision_policy.js (sole visible decision authority)
  -> service_worker.js navigation/session validation
  -> version 3 badge/detail UI, popup dashboard, and report
```

`engine/navigation_session_guard.js` issues an opaque navigation ID for every top-level page identity. Content messages, delayed rescans, timeline events, stored scans, and policy decisions are tied to the current tab/navigation/frame. Old navigation messages are rejected and delayed callbacks verify the captured navigation ID.

The evidence policy distinguishes allowlisted direct evidence from correlated groups and weak context. `HIGH_RISK` requires direct evidence. `SUSPICIOUS` requires independently corroborated behavior. `RISKY_CONTEXT` provides a non-overlay early caution for gambling, claimed-brand/domain mismatch, or a sensitive action in a recognized risk context. Model output is adapted as `overallRiskProbability`; behavior-specific probabilities are marked unavailable rather than fabricated.

The optional FastAPI reputation gateway accepts a normalized hostname only, uses reviewed local seeds, and can query Google Web Risk when configured. Lookup failure returns unavailable/unknown evidence and never downgrades local detection.

The bundled identity registry carries a versioned compact public-suffix snapshot for registrable-domain checks. A signed cached registry must validate against the pinned Ed25519 public key, be unexpired, and be at least as new as the bundled bootstrap before it can replace it.

Project Argus 5.3 is a local evidence and identity ensemble with optional reputation enrichment. It does not call an external generative-AI service. The Chrome extension remains the authoritative detector.

## Data Flow

```text
content.js page metadata scan
  -> service_worker.js normalization and per-tab event correlation
  -> engine/argus_engine.js modular analyzers
  -> engine/feature_extractor.js + trained_model.json local calibration
  -> evidence/confidence combiner using engine/detection_policy.json
  -> SAFE, MONITORING, RISKY_CONTEXT, SUSPICIOUS, or HIGH_RISK decision
  -> storage, popup report, and version 3 badge/detail UI
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
- Browser Protection Analyzer: mixed active content, security-header posture, unsandboxed third-party frames, and scripts without integrity metadata.
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

## Local Calibration Model

`scripts/train_full_mega_model.py` trains a regularized logistic calibrator on 69 boolean/numeric browser-observable features. It streams all 1,260,000 records from the three external bundles, preserves their TRAIN/VALIDATION/TEST splits, performs 10,000 mini-batch Adam updates, and mixes a 1,400-case regression replay buffer into fine-tuning to prevent catastrophic forgetting.

URL lexical features include length, IP-host use, obfuscation, deep subdomains, digit ratio, credential wording in paths, and corroborated lexical clusters. A lexical cluster cannot warn by itself; credential or login behavior must corroborate it.

The model is constrained by the evidence engine:

- It cannot override direct-evidence score floors.
- It cannot escalate content-only pages.
- It needs at least two independent evidence groups and corroborating analyzer findings.
- Context or static intent remains capped at 60 unless direct priority-1 evidence exists.
- Trusted domains and search pages keep their explicit false-positive guards.

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

On every full navigation or SPA route change, Project Argus clears the tab's network counters, security-header state, timers, stored scan, and event history. A privacy-safe route fingerprint distinguishes query/hash routes without storing their values. Epoch and page-key checks discard late results from the previous page.

## Reliability

The modular engine is loaded with `importScripts`. If it cannot load, `service_worker.js` falls back to the previous local detector so scanning still works. Policy and category files are cached after validation/loading by the extension.

Run the detector regression suite with:

```powershell
node tests/run_detector_tests.js
node tests/run_exfiltration_calibration.js
node tests/run_model_training_tests.js
node tests/run_page_state_tests.js
```

The suites cover 15 detector regressions, 200 core cases, 200 benign robustness cases, 1,000 randomized real-vs-fake cases, and five-fold out-of-fold validation. Full PCAP payload and TLS certificate inspection remain outside a normal Chrome extension's visibility boundary.
