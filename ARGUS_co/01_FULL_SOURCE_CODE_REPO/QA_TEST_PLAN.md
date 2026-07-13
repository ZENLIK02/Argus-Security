# Project Argus QA Test Plan

## Evidence-first acceptance

- Model score 100 with no behavioral evidence: `UNCERTAIN`, no warning, no overlay.
- Login plus known analytics/SSO/iframe/POST: `SAFE`, `MONITORING`, or `UNCERTAIN`; no overlay.
- Sensitive HTTP form or unencrypted sensitive write: `HIGH_RISK`; direct evidence shown in badge/details with no top-right popup.
- Two independent non-direct behavior groups: `SUSPICIOUS`; non-blocking details only.
- Images/ads only: `SAFE`, score at most 5.
- Category only: `SAFE`, score at most 10.
- High-risk to safe navigation, rapid navigation, back/forward, iframe reload, tab reuse, delayed events, and cleared state: old navigation evidence rejected.

Run `powershell -ExecutionPolicy Bypass -File scripts/validate.ps1`. This includes policy unit tests, safe-pattern regressions, policy integration, navigation guard tests, existing adversarial suites, model checks, and syntax/JSON/Python validation.

Use this checklist before a demo or submission. Project Argus now uses the local detector/model only. There is no external AI call and no API key.

## Automated Regression Gate

Run before manual browser QA:

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

Expected: 15/15 detector regressions, 200/200 core cases, 200/200 benign cases, 1000/1000 randomized cases, five-fold cross-validation, 100 monotonic training epochs, and page-state isolation under policy `4.2.0`.

## Setup

1. Open Chrome and go to `chrome://extensions`.
2. Enable Developer mode.
3. Load unpacked: `Desktop/Project-Argus-Extension`.
4. Open Project Argus Options and confirm:
   - Warning threshold: `35`
   - Demo mode: ON
5. Optional: start the local demo server for test pages:

```powershell
cd Desktop/Project-Argus-Extension/backend
venv\Scripts\activate
uvicorn main:app --reload --port 8000
```

## Manual Test Cases

| Test | URL / Page | Expected | Checks |
| --- | --- | --- | --- |
| Safe local page | `http://localhost:8000/test-site/safe-site.html` | SAFE | Score in 0-34 range, badge remains available, source LOCAL_RULE_ENGINE or LOCAL_ENSEMBLE |
| Fake app store | `http://localhost:8000/test-site/fake-store.html` | HIGH_RISK | Badge turns HIGH RISK, detail panel shows FAKE_APP_STORE or MALICIOUS_APK and reasons |
| Fake bank | `http://localhost:8000/test-site/fake-bank.html` | HIGH_RISK | Badge turns HIGH RISK, detail panel shows FAKE_BANKING and credential reasons |
| Gambling content | `http://localhost:8000/test-site/gambling-risk.html` | SAFE | Content-only score stays at or below 12 unless stronger behavior appears |
| Adult content | `http://localhost:8000/test-site/adult-risk.html` | SAFE | Content-only score stays at or below 12 unless stronger behavior appears |
| Gambling clean category | `http://localhost:8000/test-site/gambling-clean.html` | SAFE | Gambling keywords alone have minimal score impact |
| Gambling data leak | `http://localhost:8000/test-site/gambling-data-leak.html` | HIGH_RISK / DATA_EXFILTRATION | Cross-domain payment/deposit form and hidden iframe are detected |
| Adult clean category | `http://localhost:8000/test-site/adult-clean.html` | SAFE | Adult keywords alone have minimal score impact |
| Adult APK leak | `http://localhost:8000/test-site/adult-apk-leak.html` | SUSPICIOUS / MALICIOUS_APK | Direct third-party/HTTP APK evidence is detected without content category dominating |
| Cross-domain login | `http://localhost:8000/test-site/cross-domain-login.html` | HIGH_RISK / DATA_EXFILTRATION | Password form posts to a different domain |
| HTTP form risk | `http://localhost:8000/test-site/http-form-risk.html` | HIGH_RISK / INSECURE_FORM_SUBMISSION | Password/OTP form action uses HTTP |
| Google Search | `https://www.google.com/search?q=google+play+download+app` | SAFE | Search page stays SAFE without APK/password/OTP false positive |
| YouTube | `https://www.youtube.com` | SAFE | Trusted domain, no warning |
| Roblox | `https://www.roblox.com` | SAFE | Trusted domain, no warning |
| Yahoo Finance | `https://finance.yahoo.com` | SAFE | Finance/account words should not trigger phishing by themselves |

## Export Report Test

1. Open any test page.
2. Open the Project Argus popup.
3. Click `Export Scan Report`.
4. Confirm a JSON file downloads.
5. Confirm it contains timestamp, url, domain, trusted status, search status, score, level, category, source, reasons, model status, data-leak metadata, and network metadata.
6. Confirm it does not contain passwords, OTP values, cookies, tokens, localStorage, request bodies, headers, or private messages.

## Navigation State Isolation

1. Open a HIGH_RISK test page and wait for its score.
2. In the same tab, navigate to `safe-site.html`.
3. Confirm the badge returns to scanning and then SAFE; the old reasons must disappear.
4. Repeat with a SPA-style `history.pushState` route change.
5. Confirm popup data matches only the current tab and route.

## Pass Criteria

- All expected levels match the table above.
- No page opens the removed automatic top-right warning popup.
- HIGH_RISK pages remain visible through the animated badge, detail panel, and extension popup.
- Popup source shows `LOCAL_RULE_ENGINE` or `LOCAL_ENSEMBLE`.
- Popup shows policy `4.2.0`, decision confidence, decision tier, local model analysis, and analyzer results.
- Automated detector regression suite passes completely.
- Adult/gambling category pages stay below HIGH_RISK unless data-leak, credential, APK, or insecure form behavior is present.
- Exported report contains only metadata and risk signals.
