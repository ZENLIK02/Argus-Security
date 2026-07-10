# Project Argus Release Checklist

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
- [ ] `datasets/exfiltration_eval_cases.json` is valid JSON and contains 65 labeled cases.
- [ ] JavaScript files pass syntax check:
  - `content.js`
  - `service_worker.js`
  - `popup.js`
  - `options.js`
  - `engine/argus_engine.js`
  - `tests/run_detector_tests.js`
- [ ] `backend/main.py` compiles.
- [ ] `node tests/run_detector_tests.js` passes every case.
- [ ] `node tests/run_exfiltration_calibration.js` passes all 65 cases.
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
- [ ] Popup source shows `LOCAL_MODEL`.
- [ ] Popup displays confidence, policy version, and analyzer evidence.

## Packaging

- [ ] `scripts/validate.ps1` completes successfully.
- [ ] `scripts/build_zip.ps1` completes successfully.
- [ ] `Project-Argus-Extension.zip` builds successfully.
- [ ] ZIP contains extension files, local demo server source, docs, and test pages.
- [ ] ZIP contains `engine/`, `datasets/`, `tests/`, and `ARCHITECTURE.md`.
- [ ] ZIP does not contain secrets or local virtual environment files.
