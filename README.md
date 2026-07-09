# Project Argus Chrome Extension

Project Argus is a Manifest V3 browser security prototype. It uses a local Project Argus detector/model only. There is no external AI call, no API key, and no external classification service.

The detector is behavior-first. Adult or gambling keywords alone should normally stay `SUSPICIOUS / CONTENT_RISK`. Risk increases when a page combines category signals with concrete behavior such as cross-domain sensitive forms, HTTP form submission, third-party APK links, hidden iframes, fake install buttons, or third-party requests after form/password interaction.

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

- `Warning threshold`: minimum score for warning overlay behavior.
- `Show badge on SAFE pages`: turn off for a quieter browsing demo.
- `Demo mode`: keeps UI behavior stable for presentations and avoids repeated warning redraw flicker.

The popup includes a `Data Leak Guard` section with metadata counts for cross-domain forms, HTTP form actions, hidden iframes, external scripts, third-party requests, requests after form submit/password focus, and APK link behavior.

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
- `gambling-risk.html`: SUSPICIOUS / CONTENT_RISK.
- `adult-risk.html`: SUSPICIOUS / CONTENT_RISK.
- `gambling-clean.html`: SUSPICIOUS / CONTENT_RISK, not HIGH_RISK.
- `gambling-data-leak.html`: HIGH_RISK / DATA_EXFILTRATION.
- `adult-clean.html`: SUSPICIOUS / CONTENT_RISK, not HIGH_RISK.
- `adult-apk-leak.html`: HIGH_RISK / MALICIOUS_APK.
- `cross-domain-login.html`: HIGH_RISK / DATA_EXFILTRATION.
- `http-form-risk.html`: HIGH_RISK / INSECURE_FORM_SUBMISSION.

See `QA_TEST_PLAN.md` for the full manual QA checklist.

## Adversarial Test-Only Pages

`Website_testonly/` contains three intentionally evasive pages for stress-testing Argus. They should now classify as `HIGH_RISK / DATA_EXFILTRATION` because the local model checks evasive JavaScript metadata as well as visible form metadata:

- `quiet-profile-sync.html`: simulates delayed credential relay through JavaScript-built endpoints.
- `consent-mirror.html`: simulates a consent and popup-message trap.
- `clipboard-vault.html`: simulates clipboard/file metadata harvesting.

These pages are test-only and do not send typed values anywhere by default. Open them through the same local server:

```text
http://localhost:8000/Website_testonly/quiet-profile-sync.html
http://localhost:8000/Website_testonly/consent-mirror.html
http://localhost:8000/Website_testonly/clipboard-vault.html
```

## Export Scan Report

1. Open a page and wait for the Argus badge to show a score.
2. Open the Project Argus popup.
3. Click `Export Scan Report`.
4. A JSON file downloads with timestamp, URL, domain, trusted/search status, final score, level, category, source, reasons, model status, data-leak metadata, and network metadata.

The export does not include passwords, OTP values, cookies, tokens, storage values, request bodies, headers, full page text, or private messages.

## Rebuild ZIP

PowerShell:

```powershell
$project = "C:\Users\User\Desktop\Project-Argus-Extension"
$zip = "C:\Users\User\Desktop\Project-Argus-Extension.zip"
$stage = Join-Path $env:TEMP ("Project-Argus-Zip-" + [guid]::NewGuid().ToString())
New-Item -ItemType Directory -Path $stage | Out-Null
$stageRoot = Join-Path $stage "Project-Argus-Extension"
New-Item -ItemType Directory -Path $stageRoot | Out-Null
$rootFiles = @(
  "manifest.json","content.js","service_worker.js","popup.html","popup.js",
  "options.html","options.js","style.css","trusted_domains.json","risky_categories.json",
  "README.md","PRIVACY_NOTES.md","QA_TEST_PLAN.md","RELEASE_CHECKLIST.md"
)
foreach ($file in $rootFiles) { Copy-Item -LiteralPath (Join-Path $project $file) -Destination $stageRoot }
Copy-Item -LiteralPath (Join-Path $project "test-site") -Destination $stageRoot -Recurse
New-Item -ItemType Directory -Path (Join-Path $stageRoot "backend") | Out-Null
$backendFiles = @("main.py","requirements.txt","README_BACKEND.md")
foreach ($file in $backendFiles) { Copy-Item -LiteralPath (Join-Path (Join-Path $project "backend") $file) -Destination (Join-Path $stageRoot "backend") }
if (Test-Path $zip) { Remove-Item -LiteralPath $zip -Force }
Compress-Archive -Path $stageRoot -DestinationPath $zip -Force
Remove-Item -LiteralPath $stage -Recurse -Force
```

The ZIP must not include `backend/venv`, `__pycache__`, `.git`, or `node_modules`.

## Privacy

Project Argus does not collect typed usernames, typed passwords, OTP values, cookies, tokens, localStorage, sessionStorage, request bodies, headers, or private messages. It only uses minimized metadata and risk indicators. See `PRIVACY_NOTES.md`.
