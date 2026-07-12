# Project Argus Chrome Extension

## Evidence-first decisions

ARGUS 5.3 routes every visible decision through `engine/evidence_decision_policy.js`. The legacy evidence engine and local model are producers, not warning authorities. A model-only score, including 100/100, cannot produce `SUSPICIOUS`, `HIGH_RISK`, or an overlay.

- `SAFE`: no meaningful behavioral evidence; no overlay.
- `MONITORING`: one weak or incomplete group; no overlay.
- `UNCERTAIN`: high model uncertainty without enough behavior; no overlay.
- `RISKY_CONTEXT`: an unverified gambling context, credible claimed-brand/domain mismatch, or sensitive action in one of nine impersonation contexts. This is a caution, not a claim of confirmed fraud.
- `SUSPICIOUS`: at least two independent groups with at least one behavioral group; non-blocking details only.
- `HIGH_RISK`: allowlisted direct behavior such as HTTP credential transfer, unknown sensitive cross-site write/beacon, or unsafe executable delivery; shown through the version 3 badge/detail UI without a top-right popup.

The optional local reputation gateway receives only a normalized hostname. It checks reviewed local seeds and can query Google Web Risk when `ARGUS_WEBRISK_API_KEY` is configured on the backend. Paths, query strings, affiliate codes, form values, and credentials are excluded.

The identity engine covers banking/lending, investment/crypto, payments/wallets, government services, telecom/utilities, shopping/delivery, platform accounts, technical support/security, and reward/job/charity advance-fee contexts. It compares locally extracted identity claims with a reviewed Thai-plus-global brand registry, approved authentication domains, deceptive subdomains, homograph/typosquat indicators, and optional local perceptual logo hashes.

Options expose `CONSERVATIVE`, `BALANCED` (default), and `PROTECTIVE` early-warning modes. These settings never weaken direct `HIGH_RISK` evidence. Balanced mode shows a badge for a strong identity mismatch and expands the detail panel when the user approaches a sensitive action.

Content/category evidence is capped at 10 and image/ad-only evidence at 5. Request volume, scripts, iframes, login text, analytics, and generic forms cannot independently create a warning.

## Destination roles and timeline

Network metadata is classified as same-site API, static asset, CDN, known analytics, known ad network, known identity provider, SSO redirect, first-party write, unknown read/write destination, unknown beacon, or executable source. A per-navigation timeline stores only event type, time, method, protocol, destination role, frame ID, scan phase, and evidence IDs.

## Shadow mode

Enable **Evidence-policy shadow comparison** in Options to include legacy and evidence-first decisions in privacy-safe reports. Only the evidence-first result controls the UI. Shadow output never displays warnings.

## Adding evidence rules

Add analyzers in `engine/argus_engine.js`, then explicitly classify the evidence ID in `engine/evidence_decision_policy.js`. Add an ID to `DIRECT_RULES` only when browser-observable metadata proves an insecure transfer or unsafe delivery. Otherwise map it to one independent group and add policy tests. Never promote context, counts, category, or model score to direct evidence.

## Known limitations

Manifest V3 `webRequest` observes request metadata, not sensitive payload values. ARGUS can identify insecure transport, destination changes, timing, method, and request role, but cannot prove the exact bytes transmitted. Unknown services may require additional role classification. User false-positive labels remain untrusted until reviewed to reduce poisoning risk.

## Progressive observation and feedback

Argus observes the page and aggregate Chrome `webRequest` metadata for a short window before publishing a final result. It never reads request bodies, form values, cookies, passwords, OTP values, or query strings. Datasets are offline training and evaluation assets only. The Chrome runtime loads the compact trained model artifact and policy, never raw training rows or domain datasets.

Use **Report False Positive** in the popup or badge details to save a privacy-filtered training example. With the local backend running, reports are appended to `backend/data/false_positive_reports.jsonl`; otherwise they remain queued in `chrome.storage.local`. Configure the collector and observation window from Options. Collector statistics are available at `http://localhost:8000/feedback/stats`.

Project Argus is a Manifest V3 browser security prototype. Version 5.0 uses a modular local evidence engine plus a locally trained calibration model. There is no external AI call, API key, or external classification service.

Version 5.0 trains the local calibrator offline on all 1,260,000 records from the 250K false-positive, 1M cross-sector, and 10K popular-domain bundles. Training uses 10,000 Adam optimization updates plus regression replay to prevent catastrophic forgetting. Raw datasets remain development-only; Chrome receives only model weights and normalization statistics.

The detector combines eight analyzers across network flow, credential capture, unsafe forms, script relays, browser protections, downloads, domains, URL structure, and page context. The local model uses 69 browser-observable features. Deterministic score floors and corroboration requirements remain authoritative for direct evidence and prevent a model-only warning.

Per-tab scan state is cleared on full navigation and SPA route changes. In-flight results from an old page are discarded, and popup lookup never falls back to another page's result.

See `ARCHITECTURE.md` for analyzer contracts, score calibration, temporal correlation, privacy boundaries, and fallback behavior.

## Load The Extension

1. Open Chrome.
2. Go to `chrome://extensions`.
3. Turn on `Developer mode`.
4. Click `Load unpacked`.
5. Select `Desktop/Project-Argus-Extension`.
6. After edits, click the extension `Reload` button on `chrome://extensions`.

## Options Page

Open the options page from either:

- Chrome extension card: `Details` -> `Extension options`
- Project Argus popup: `Open Options`

Options:

- `Risk flag threshold`: marks high-scoring results in reports. Argus no longer opens an automatic top-right page popup.
- `Show badge on SAFE pages`: turn off for a quieter browsing demo.
- `Demo mode`: keeps badge and detail-panel behavior stable for presentations.

The popup includes `Data Leak Guard` metadata, overall decision confidence, policy version, and an `Analyzer Evidence` section showing which local tools produced findings.

## Optional Local Demo Server

The extension does not need a backend to scan pages. The FastAPI server is only kept as a convenient local demo server for `test-site`.

```powershell
cd Desktop/Project-Argus-Extension/backend
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

## Test Pages

When the local demo server is running:

```text
http://localhost:8000/test-site/safe-site.html
http://localhost:8000/test-site/fake-store.html
http://localhost:8000/test-site/fake-bank.html
http://localhost:8000/test-site/gambling-risk.html
http://localhost:8000/test-site/adult-risk.html
http://localhost:8000/test-site/gambling-clean.html
http://localhost:8000/test-site/gambling-data-leak.html
http://localhost:8000/test-site/adult-clean.html
http://localhost:8000/test-site/adult-apk-leak.html
http://localhost:8000/test-site/cross-domain-login.html
http://localhost:8000/test-site/http-form-risk.html
```

Expected results:

- `safe-site.html`: SAFE.
- `fake-store.html`: HIGH_RISK.
- `fake-bank.html`: HIGH_RISK.
- `gambling-risk.html`: SAFE with a minimal content-only score unless stronger behavior appears.
- `adult-risk.html`: SAFE with a minimal content-only score unless stronger behavior appears.
- `gambling-clean.html`: SAFE with a minimal content-only score.
- `gambling-data-leak.html`: HIGH_RISK / DATA_EXFILTRATION.
- `adult-clean.html`: SAFE with a minimal content-only score.
- `adult-apk-leak.html`: supporting APK evidence; it escalates only when direct unsafe delivery or transfer evidence is strong enough.
- `cross-domain-login.html`: HIGH_RISK / DATA_EXFILTRATION.
- `http-form-risk.html`: HIGH_RISK / INSECURE_FORM_SUBMISSION.

See `QA_TEST_PLAN.md` for the full manual QA checklist.

## Export Scan Report

1. Open a page and wait for the Argus badge to show a score.
2. Open the Project Argus popup.
3. Click `Export Scan Report`.
4. A JSON file downloads with timestamp, URL, domain, trusted/search status, final score, level, category, confidence, policy version, analyzer evidence, source, reasons, data-leak metadata, and privacy-safe temporal network metadata.

The export does not include passwords, OTP values, cookies, tokens, storage values, request bodies, headers, full page text, or private messages.

## Automated Detector Tests

Run the local regression suite after changing scoring, analyzers, or policy:

```powershell
cd Desktop/Project-Argus-Extension
node tests/run_detector_tests.js
node tests/run_exfiltration_calibration.js
node tests/run_benign_robustness.js
node tests/run_randomized_web_evaluation.js
node tests/run_randomized_cross_validation.js
node tests/run_model_training_tests.js
node tests/run_page_state_tests.js
```

All cases must pass before rebuilding the ZIP. The randomized corpus contains 500 SAFE and 500 fake cases across ten behavior families per class, generated from sanitized UCI PhiUSIIL URL seeds with deterministic randomized metadata. Five-fold cross-validation tests every randomized case out-of-fold once before final training.

To reproduce the 100-epoch training and ten repeated stability runs:

```powershell
node scripts/generate_exfiltration_corpus.js
node scripts/generate_benign_robustness_corpus.js
node scripts/generate_randomized_web_corpus.js
node scripts/train_local_model.js
powershell -ExecutionPolicy Bypass -File scripts/run_stability_validation.ps1
```

## Rebuild ZIP

Validate and package with the included scripts:

```powershell
cd Desktop/Project-Argus-Extension
powershell -ExecutionPolicy Bypass -File scripts/validate.ps1
powershell -ExecutionPolicy Bypass -File scripts/build_zip.ps1
```

The ZIP must not include `backend/venv`, `__pycache__`, `.git`, or `node_modules`.

## Privacy

Project Argus does not collect typed usernames, typed passwords, OTP values, cookies, tokens, localStorage, sessionStorage, request bodies, headers, or private messages. It only uses minimized metadata and risk indicators. See `PRIVACY_NOTES.md`.
