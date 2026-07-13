# Project Argus Release Checklist

## ARGUS 5.3 identity registry

- [ ] Confirm `engine/brand_registry.json` is unexpired and every official/authentication domain was independently reviewed.
- [ ] Confirm any cached replacement registry has a valid pinned Ed25519 signature and is not an older version than the bundled registry.
- [ ] Run the nine-context impersonation corpus, identity mode tests, visual-hash guards, privacy audit, and existing detector/model suites.
- [ ] Manually verify the two-stage `fake-kbank-identity.html` flow in Balanced, Conservative, and Protective modes.
- [ ] Confirm no raw identity surface, screenshot, image crop, or logo resource URL appears in exported reports or false-positive feedback.

## Evidence-first policy

- [ ] All visible statuses are returned by `ArgusEvidencePolicy.decide`.
- [ ] Model-only score 100 produces no warning or overlay.
- [ ] `HIGH_RISK` includes at least one structured direct-evidence item.
- [ ] `SUSPICIOUS` includes at least two independent evidence groups.
- [ ] `MONITORING` and `UNCERTAIN` never create overlays.
- [ ] No status creates the removed top-right warning popup; HIGH_RISK remains visible in the badge, details, popup, and report.
- [ ] ZIP includes policy/model artifacts but no raw training datasets.

Run this before rebuilding the ZIP for submission or presentation.

## Security And Privacy

- [ ] No external AI API integration remains in extension files.
- [ ] No API key or `.env` file is included in the ZIP.
- [ ] `backend/venv` is not included in the ZIP.
- [ ] `__pycache__` folders are not included in the ZIP.
- [ ] `.git` is not included in the ZIP.
- [ ] `node_modules` is not included in the ZIP.
- [ ] Export Scan Report does not include sensitive values.
- [ ] Data Leak Guard does not collect typed values, cookies, tokens, request bodies, response bodies, or headers.
- [ ] False positive reports stay local in `chrome.storage.local`.

## Validation

- [ ] `manifest.json` is valid JSON.
- [ ] `trusted_domains.json` is valid JSON.
- [ ] `risky_categories.json` is valid JSON.
- [ ] `engine/detection_policy.json` is valid JSON.
- [ ] `datasets/exfiltration_eval_cases.json` is valid JSON and contains exactly 200 unique labeled cases.
- [ ] `datasets/benign_robustness_cases.json` is valid JSON and passes all 200 SAFE cases.
- [ ] `datasets/phiusiil_benign_cases.json` contains 100 sanitized legitimate URL cases.
- [ ] `datasets/randomized_web_eval_cases.json` contains exactly 500 SAFE and 500 fake cases.
- [ ] `tests/randomized_cv_report.json` records five balanced out-of-fold evaluations.
- [ ] `engine/trained_model.json` is valid JSON and records at least 10,000 offline optimization updates across 1,260,000 records.
- [ ] JavaScript files pass syntax check:
  - `content.js`
  - `service_worker.js`
  - `popup.js`
  - `options.js`
  - `engine/argus_engine.js`
  - `engine/feature_extractor.js`
  - `engine/trained_model.js`
  - `tests/run_detector_tests.js`
- [ ] `backend/main.py` compiles.
- [ ] `node tests/run_detector_tests.js` passes every case.
- [ ] `node tests/run_exfiltration_calibration.js` passes all 200 cases.
- [ ] `node tests/run_benign_robustness.js` passes all 200 cases without a warning-level result.
- [ ] `node tests/run_randomized_web_evaluation.js` passes all 1,000 cases.
- [ ] `node tests/run_randomized_cross_validation.js` reports zero SAFE false positives and zero fake false negatives.
- [ ] `node tests/run_model_training_tests.js` passes accuracy, recall, false-positive, and monotonic-loss gates.
- [ ] `node tests/run_page_state_tests.js` confirms navigation state isolation.
- [ ] Ten repeated stability runs pass.
- [ ] Test pages return expected results:
  - `safe-site.html`: SAFE
  - `fake-store.html`: HIGH_RISK
  - `fake-bank.html`: HIGH_RISK
  - `gambling-risk.html`: SAFE, content-only score <= 12
  - `adult-risk.html`: SAFE, content-only score <= 12
  - `gambling-clean.html`: SAFE, content-only score <= 12
  - `gambling-data-leak.html`: HIGH_RISK / DATA_EXFILTRATION
  - `adult-clean.html`: SAFE, content-only score <= 12
  - `adult-apk-leak.html`: SUSPICIOUS / MALICIOUS_APK
  - `cross-domain-login.html`: HIGH_RISK / DATA_EXFILTRATION
  - `http-form-risk.html`: HIGH_RISK / INSECURE_FORM_SUBMISSION
- [ ] Google Search, YouTube, Roblox, and Yahoo Finance remain SAFE.
- [ ] Popup source shows `LOCAL_RULE_ENGINE` or `LOCAL_ENSEMBLE`.
- [ ] Popup displays confidence, policy version, and analyzer evidence.

## Packaging

- [ ] `scripts/validate.ps1` completes successfully.
- [ ] `scripts/build_zip.ps1` completes successfully.
- [ ] `Project-Argus-Extension.zip` builds successfully.
- [ ] ZIP contains extension files, local demo server source, docs, and test pages.
- [ ] ZIP contains `engine/`, `datasets/`, `tests/`, and `ARCHITECTURE.md`.
- [ ] ZIP does not contain secrets or local virtual environment files.
