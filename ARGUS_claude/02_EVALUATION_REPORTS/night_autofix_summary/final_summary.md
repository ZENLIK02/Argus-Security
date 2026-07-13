# Project ARGUS autonomous browser run

- Recorded browser-evidence span: 24+ minutes, plus dependency and environment setup. The final autonomous controller pass ran 4.39 minutes and exited early on a documented public-network blocker instead of idling for seven hours.
- Public corpus configured: 50 sites across 12 categories; actually loaded: 0 because Chromium received `ERR_NETWORK_ACCESS_DENIED` before any response.
- Workspace-local profile directories created: 24; profiles producing scan records: 14; final-candidate profiles: 3.
- Playwright launch attempts represented by reports: 21, plus one direct runtime network probe. Selenium runs: 0 because Selenium was unavailable and public networking was blocked.
- Distinct local pages tested through the unpacked extension and real popup: 11.

## Results

- Final benign popup set: 4 samples, mean 2, median 1, p95 5, zero scores above 5, zero visible warnings, and zero SUSPICIOUS/HIGH_RISK classifications.
- Weak model-only fixture: 6/MONITORING before, 1/MONITORING after.
- Paired modern-SPA fixture: 60/SUSPICIOUS before, 5/UNCERTAIN after.
- Final malicious/evasive set: 7/7 detected as SUSPICIOUS or HIGH_RISK (100%). Baseline direct fixture set was 3/3 detected; final set was 7/7 detected.
- Direct-evidence recall on fixtures expected to produce direct evidence: 3/3 before and 5/5 after (100% both).
- Popup score consistency: all 11 final-candidate results had `displayedScore === policyRiskScore`.

## Root causes and retained repairs

1. The model-only policy cap applied only when there were no evidence IDs. Weak contextual IDs therefore leaked the legacy/model score. The retained repair caps every model-only branch at 5.
2. SUSPICIOUS required two total groups but only one behavioral group. `SENSITIVE_INPUT` context plus one ordinary SPA networking group triggered the 60 floor. The retained repair requires two independent behavioral groups and caps one uncorrelated behavioral group at 10.
3. The popup requested a rescan and immediately rendered the first cached result. It displayed 99 while the latest policy scan was 100. The retained repair requires a same-page, post-request result that remains stable for three bounded reads.

The first timestamp-only popup freshness attempt was insufficient and was refined after browser evidence still showed 99 versus 100. Branded Chrome 150 side-loading and the missing default Playwright executable were discarded as runner paths; no ARGUS product logic was retained from those attempts.

## Browser and telemetry evidence

- Real popup proof is stored in `browser_results.jsonl`: each successful record contains a `chrome-extension://.../popup.html` URL and values read through `argus-policy-score`, `argus-policy-status`, and `argus-domain` test IDs.
- Contributor records include feature name, observed value, configured weight, effective contribution, context/behavior flags, and evidence/event identifiers.
- Playwright observed local requests and ARGUS destination roles. Selenium comparison is explicitly `not-run`; no cross-runner parity claim is made.
- YouTube and Roblox were each attempted in a fresh isolated profile. Both reached the unpacked ARGUS service worker but public navigation became `chrome-error://chromewebdata` with `ERR_NETWORK_ACCESS_DENIED`.
- YouTube, Roblox, GitHub, and ChatGPT before/after scores are therefore not measured. The requested 50-public-site success criterion is unresolved and is not claimed.
- GitHub was not pushed or modified remotely.

## Reproduce

```powershell
$env:ARGUS_CHROME_PATH='C:\Users\User\AppData\Local\ms-playwright\chromium-1223\chrome-win64\chrome.exe'
node tests\run_real_browser_audit.js --fixtures=safe-site.html,benign-modern-spa.html,cross-domain-login.html,http-form-risk.html,adult-apk-leak.html --profile=repro-fresh-$([DateTimeOffset]::UtcNow.ToUnixTimeSeconds()) --wait-ms=6500
node tests\run_evidence_policy_tests.js
node tests\run_policy_integration_tests.js
node tests\run_page_state_tests.js
```

Resume public acceptance with `node scripts\night_autofix_controller.js` in a workspace-write runtime that permits isolated Chromium outbound HTTPS. See `recovery_instructions.md`.
