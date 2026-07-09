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
- [ ] JavaScript files pass syntax check:
  - `content.js`
  - `service_worker.js`
  - `popup.js`
  - `options.js`
- [ ] `backend/main.py` compiles.
- [ ] Test pages return expected results:
  - `safe-site.html`: SAFE
  - `fake-store.html`: HIGH_RISK
  - `fake-bank.html`: HIGH_RISK
  - `gambling-risk.html`: SUSPICIOUS / CONTENT_RISK
  - `adult-risk.html`: SUSPICIOUS / CONTENT_RISK
  - `gambling-clean.html`: SUSPICIOUS / CONTENT_RISK, not HIGH_RISK
  - `gambling-data-leak.html`: HIGH_RISK / DATA_EXFILTRATION
  - `adult-clean.html`: SUSPICIOUS / CONTENT_RISK, not HIGH_RISK
  - `adult-apk-leak.html`: HIGH_RISK / MALICIOUS_APK
  - `cross-domain-login.html`: HIGH_RISK / DATA_EXFILTRATION
  - `http-form-risk.html`: HIGH_RISK / INSECURE_FORM_SUBMISSION
  - `Website_testonly/quiet-profile-sync.html`: HIGH_RISK / DATA_EXFILTRATION
  - `Website_testonly/consent-mirror.html`: HIGH_RISK / DATA_EXFILTRATION
  - `Website_testonly/clipboard-vault.html`: HIGH_RISK / DATA_EXFILTRATION
- [ ] Google Search, YouTube, Roblox, and Yahoo Finance remain SAFE.
- [ ] Popup source shows `LOCAL_MODEL`.

## Packaging

- [ ] `Project-Argus-Extension.zip` builds successfully.
- [ ] ZIP contains extension files, local demo server source, docs, and test pages.
- [ ] ZIP does not contain secrets or local virtual environment files.
