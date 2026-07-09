# Project Argus QA Test Plan

Use this checklist before a demo or submission. Project Argus now uses the local detector/model only. There is no external AI call and no API key.

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
| Gambling content | `http://localhost:8000/test-site/gambling-risk.html` | SUSPICIOUS / CONTENT_RISK | Score in 35-69 range unless stronger behavior appears |
| Adult content | `http://localhost:8000/test-site/adult-risk.html` | SUSPICIOUS / CONTENT_RISK | Score in 35-69 range unless stronger behavior appears |
| Gambling clean category | `http://localhost:8000/test-site/gambling-clean.html` | SUSPICIOUS / CONTENT_RISK | Gambling keywords alone should not become HIGH_RISK |
| Gambling data leak | `http://localhost:8000/test-site/gambling-data-leak.html` | HIGH_RISK / DATA_EXFILTRATION | Cross-domain payment/deposit form and hidden iframe are detected |
| Adult clean category | `http://localhost:8000/test-site/adult-clean.html` | SUSPICIOUS / CONTENT_RISK | Adult keywords alone should not become HIGH_RISK |
| Adult APK leak | `http://localhost:8000/test-site/adult-apk-leak.html` | HIGH_RISK / MALICIOUS_APK | HTTP APK link and fake install behavior are detected |
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

## Pass Criteria

- All expected levels match the table above.
- SAFE trusted/search pages do not show warning overlays.
- HIGH_RISK demo pages show clear warning overlays.
- Popup source shows `LOCAL_MODEL`.
- Adult/gambling category pages stay below HIGH_RISK unless data-leak, credential, APK, or insecure form behavior is present.
- Exported report contains only metadata and risk signals.
