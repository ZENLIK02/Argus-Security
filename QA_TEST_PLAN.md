# Project Argus QA Test Plan

Use this checklist before a demo or submission. Project Argus now uses the local detector/model only. There is no external AI call and no API key.

## Automated Regression Gate

Run before manual browser QA:

```powershell
cd Desktop/Project-Argus-Extension
node tests/run_detector_tests.js
node tests/run_exfiltration_calibration.js
```

Expected: 15/15 detector regressions and 65/65 exfiltration calibration cases pass under policy `3.0.0`. A failed SAFE, score range, category, tool-result, or confidence assertion blocks release.

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
| Safe local page | `http://localhost:8000/test-site/safe-site.html` | SAFE | Score in 0-34 range, no warning overlay, source LOCAL_MODEL |
| Fake app store | `http://localhost:8000/test-site/fake-store.html` | HIGH_RISK | Warning overlay appears, category FAKE_APP_STORE or MALICIOUS_APK, reasons mention APK/password/OTP/store |
| Fake bank | `http://localhost:8000/test-site/fake-bank.html` | HIGH_RISK | Warning overlay appears, category FAKE_BANKING, reasons mention banking/password/OTP |
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

## Adversarial Test-Only Cases

These pages are intentionally designed to be hard for Argus to catch. They should be used for beta QA and detector improvement, not as normal demo pass/fail pages.

| Test | URL / Page | Expected | Checks |
| --- | --- | --- | --- |
| Quiet profile sync | `http://localhost:8000/Website_testonly/quiet-profile-sync.html` | SUSPICIOUS / DATA_EXFILTRATION | Static intent stays below HIGH_RISK until an actual unsafe request is observed |
| Consent mirror | `http://localhost:8000/Website_testonly/consent-mirror.html` | SUSPICIOUS / DATA_EXFILTRATION | Popup/postMessage plus network-send intent is supporting evidence, not proof of transfer |
| Clipboard vault | `http://localhost:8000/Website_testonly/clipboard-vault.html` | SUSPICIOUS / DATA_EXFILTRATION | Clipboard/file metadata plus network-send intent stays below HIGH_RISK without an observed request |
| Plaintext network demo | `http://localhost:8000/Website_testonly/network-plaintext-demo.html` | HIGH_RISK / INSECURE_FORM_SUBMISSION | Sensitive form over HTTP scores high; after dummy submit, evidence includes an observed unencrypted write |

## Export Report Test

1. Open any test page.
2. Open the Project Argus popup.
3. Click `Export Scan Report`.
4. Confirm a JSON file downloads.
5. Confirm it contains timestamp, url, domain, trusted status, search status, score, level, category, source, reasons, model status, data-leak metadata, and network metadata.
6. Confirm it does not contain passwords, OTP values, cookies, tokens, localStorage, request bodies, headers, or private messages.

## Pass Criteria

- All expected levels match the table above.
- SAFE trusted/search pages do not show warning overlays.
- HIGH_RISK demo pages show clear warning overlays.
- Popup source shows `LOCAL_MODEL`.
- Popup shows policy `3.0.0`, decision confidence, decision tier, and analyzer results.
- Automated detector regression suite passes completely.
- Adult/gambling category pages stay below HIGH_RISK unless data-leak, credential, APK, or insecure form behavior is present.
- Exported report contains only metadata and risk signals.
