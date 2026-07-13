# ARGUS — Progress, Migration & Issue Log

Living document. Tracks how this organized `Project\ARGUS` copy was built and every
known open issue carried over from the source project. Append new entries; do not
rewrite history.

**Version matrix:** manifest `5.1.1` · local model `5.0.0` · policy `evidence-first-v2`

---

## Fixes applied — 2026-07-12 (audit findings F1–F3)

Architecture audit (18 findings) recorded in the plan file. First remediation batch done:

- **F1 — pre-interaction beacon/pixel lost.** Root cause: `service_worker.js`
  derived the candidate's `isUnknownBeacon` from a destination role that only
  becomes `UNKNOWN_BEACON` *after* interaction, so a ping/pixel arriving first was
  dropped and correlation was lost → confirmed exfil stuck at 5/100. Fix: new
  `engine/network_correlation.js` recognizes an unknown third-party beacon/ping
  independent of interaction timing; the candidate now carries a race-safe flag.
- **F2 — `navigationId` drift rejected valid events.** Root cause: the content
  script held a stale `navigationId` after the SW re-sessioned, so `focusin`/
  `submit` events were rejected by the guard. Fix: `navigation_session_guard.js`
  `matches()` is now page-identity-first (a re-issued id for the same `pageKey`
  no longer rejects); added `note()` to adopt a `pageKey` onto a full-navigation
  session; `PAGE_CHANGED` now returns the fresh `navigationId` and `content.js`
  adopts it immediately.
- **F3 — race path untested.** The correlation decision logic was extracted into
  the pure `engine/network_correlation.js` and covered by
  `tests/run_correlation_race_tests.js` (18 cases: pre-focus beacon, out-of-order
  beacon-before-submit, window expiry, focus-vs-submit triggers). Guard test
  extended for F2 (`11/11`).

Files touched: `engine/network_correlation.js` (new), `engine/navigation_session_guard.js`,
`service_worker.js`, `content.js`, `tests/run_correlation_race_tests.js` (new),
`tests/run_navigation_guard_tests.js`. No scoring thresholds changed; refactor is
behavior-faithful for the existing live path.

Verification: correlation `18/18`, navigation `11/11`, evidence `13/13`, exfil
pipeline `3/3`, policy integration `788 SAFE / 0 warnings`, safe-policy `14/14`,
detector `15/15`, calibration `200/200`, benign robustness `200/200`, randomized
`1000/1000` (SAFE FP `0/500`, fake FN `0/500`), page-state/privacy/warning-path all PASS.

Still requires real-Chrome confirmation on `test-site/verified-network-exfil-demo.html`
(unit tests can't exercise Chrome `webRequest` timing). Remaining findings F4–F18 open.

## Fixes applied — 2026-07-12 (audit findings F4–F5)

- **F4 — misleading silent fallback.** The `importScripts` catch claimed a "legacy
  detector will be used", but `ArgusNavigationGuard.create()` ran at top level and
  crashed the worker first, so there was no working degraded mode. Fix: added an
  `engineReady` flag (verifies all engine globals loaded); the guard is only
  created and network monitoring only initialized when ready; `handlePageScan`
  now returns a **fail-closed `ENGINE_UNAVAILABLE`** result (level/status
  `UNAVAILABLE`, not SAFE — a green badge would falsely reassure). Guard/event/
  page-change entry points null-check the guard so degraded mode cannot crash.
  Popup renders `UNAVAILABLE` neutral (not green).
- **F5 — dead duplicated scoring authority removed.** Deleted `calculateLegacyRuleRisk`
  (~260 lines, second scorer with its own 35/70 thresholds whose `buildRisk`
  returned no `evidence` array → would have made every malicious site SAFE if it
  ran), the never-called `hasObviousHighRiskEvidence`, and all helpers used only by
  it (`buildRisk`, `addScore`, `sumScores`, `dominantCategory`,
  `overrideDominantCategory`, `isContentRiskCategory`, `hasContentRiskEscalator`,
  `hasStrongDangerSignals`, `levelFromScore`, `isFinanceOrNewsSafeContext`,
  `isOfficialAppStore`, `hasBrandImpersonationPattern`, const `CONTENT_RISK_MIN_SCORE`).
  `calculateRuleRisk` now delegates solely to `ArgusEngine.evaluate`. The evidence
  policy is the only decision authority. `service_worker.js`: ~1813 → ~1400 lines.

Files touched: `service_worker.js`, `popup.js`. No scoring thresholds changed.

Verification (re-ran full suite): correlation `18/18`, navigation `11/11`, evidence
`13/13`, exfil pipeline `3/3`, policy integration `788 SAFE / 0 warnings`, safe-policy
`14/14`, detector `15/15`, calibration `200/200`, benign `200/200`, randomized
`1000/1000` (FP `0/500`, FN `0/500`), page-state/privacy/warning-path PASS.
Remaining findings F6–F18 open (F7 version drift still visible: tests print "policy 4.2.0").

## Fixes applied — 2026-07-12 (audit findings F6, F7, F9)

- **F7 — version drift removed.** Aligned every stale version label to the release:
  `package.json` 5.1.0 → 5.1.1, `engine/detection_policy.json` 4.2.0 → 5.1.1,
  `argus_engine.js` `DEFAULT_POLICY.version` 4.2.0 → 5.1.1, `risky_categories.json`
  1.0 → 5.1.1. Coherent story now: **manifest / package / detection-policy /
  categories = 5.1.1**, **decision policy = evidence-first-v2**, **model = 5.0.0**.
  Tests that echoed the version now print `policy 5.1.1` (label only; no weights
  retuned, no thresholds changed).
- **F6 — single decision authority made explicit.** The evidence decision policy is
  the sole authority for status/level/score/warning. Changes: `service_worker.js`
  now sources `POLICY_VERSION`/`REPORT_SCHEMA_VERSION` from
  `ArgusEvidencePolicy.*` (one definition, safe fallback), the `finalRisk` merge
  carries a contract comment stating policy fields win and engine fields are
  advisory, and the two version concepts are separated everywhere:
  `policyVersion` = decision policy, new `detectionPolicyVersion` = weights/config.
  The engine no longer emits a field named `policyVersion` (renamed to
  `detectionPolicyVersion`) so its weights version can't masquerade as the
  decision version; its `level`/`score`/`decisionTier` are documented advisory-only
  (`shouldWarn` stays hard-false). `detectionPolicyVersion` surfaced in the scan
  result, shadow comparison, FP report, and popup export.
- **F9 — dead config no longer masquerades as authority.** `risky_categories.json`
  gained a `_meta` block marking it `REFERENCE_TAXONOMY` / `documentationOnly`,
  pointing to the real sources (weights in `detection_policy.json`, decision in
  `evidence_decision_policy.js`, runtime keywords in `content.js`). No scoring
  behavior depends on it; runtime keyword de-duplication across code files is left
  for F8.

Files touched: `service_worker.js`, `engine/argus_engine.js`,
`engine/detection_policy.json`, `risky_categories.json`, `package.json`, `popup.js`.
No scoring thresholds/weights changed.

Verification (full suite): correlation `18/18`, navigation `11/11`, evidence `13/13`,
exfil pipeline `3/3`, policy integration `788 SAFE / 0 warnings`, safe-policy `14/14`,
detector `15/15` (now `policy 5.1.1`), calibration `200/200`, benign `200/200`,
randomized `1000/1000` (FP `0/500`, FN `0/500`), page-state/privacy/warning-path PASS.
A version-coherence check asserts manifest = package = detection-policy = categories.
Remaining findings F8, F10–F18 open.

## Fixes applied — 2026-07-12 (audit findings F10, F11)

- **F10 — stale stored scan clobbered the final result.** `saveScanResult` had no
  ordering guard, so a slow `PRELIMINARY` resolving after `INTERACTION_FINAL` would
  overwrite the better result and the popup showed a preliminary/OBSERVING score.
  Fix: new `engine/scan_freshness.js` `shouldReplaceStoredScan()` — a monotonic
  write keyed on page identity (navigationId/pageKey): higher phase always wins,
  same phase takes the newer timestamp, a lower phase never downgrades, and a new
  page load always replaces. `service_worker.js:saveScanResult` now consults it.
- **F11 — popup showed preliminary scores and mis-matched SPA routes.** Two fixes in
  `popup.js`: (1) `getFreshLatestScan` now waits for a settled `isFinal` scan
  (polls up to ~3s, requires the existing `stableReadCount >= 3` stability guard)
  instead of returning whatever was cached within 2s; (2) `scanMatchesTab` now uses
  the shared `ArgusScanFreshness.scanMatchesTab`, which matches on the full
  `pageKey` (origin + pathname + fingerprint of `search#hash`) so SPA hash/query
  routes resolve to distinct identities — previously it compared origin+pathname
  only and could show another route's scan. Parity of the pageKey algorithm with
  `content.js` is asserted in tests.

Coverage: `tests/run_scan_freshness_tests.js` (16 cases: phase ranking, late-
preliminary-vs-final, higher-phase-wins, newer-same-phase, new-page-replaces, SPA
route distinctness, pageKey matching, origin+pathname fallback). `popup.html` now
loads `engine/scan_freshness.js` before `popup.js` so both worker and popup share one
implementation.

Files touched: `engine/scan_freshness.js` (new), `service_worker.js`, `popup.js`,
`popup.html`, `tests/run_scan_freshness_tests.js` (new). No scoring changed.

Verification (full suite): scan-freshness `16/16`, correlation `18/18`, navigation
`11/11`, evidence `13/13`, exfil pipeline `3/3`, policy integration `788 SAFE / 0
warnings`, safe-policy `14/14`, detector `15/15`, calibration `200/200`, benign
`200/200`, randomized `1000/1000` (FP `0/500`, FN `0/500`), page-state/privacy/
warning-path PASS. Remaining findings F8, F12–F18 open.

## Fixes applied — 2026-07-12 (audit findings F12–F15)

- **F12 — credential-phishing collapsing to SAFE (real sub-gap fixed; core is by
  design).** Credential *input alone* on an untrusted domain must stay SAFE — that
  is a deliberate false-positive guard (an ordinary login form is not malicious),
  locked by `run_evidence_policy_tests` ("known modern login context" → SAFE) and
  aligned with the user's minimize-FP priority; the dangerous cases (cross-domain /
  HTTP form, observed writes) already escalate via direct rules. The real defect
  was that the engine's *decisive* credential-phishing combos
  (`SUSPICIOUS_DOMAIN_CREDENTIAL_FLOW`, `LEXICAL_CREDENTIAL_CLUSTER`,
  `FAKE_BANK_FULL_FLOW`) mapped to **no policy group**, so a same-origin
  brand-lookalike / fake-bank page (engine says HIGH_RISK) silently returned
  SAFE/5 from the policy. Fix: added a non-observed `CREDENTIAL_PHISHING` group in
  `evidence_decision_policy.js` — such pages now surface as **MONITORING** and
  escalate to **SUSPICIOUS** only when correlated with a second, observed group.
  Also guarded the `model.score >= 85` branch with `modelOnly` so a confident model
  can no longer downgrade a real behavioral-evidence page to UNCERTAIN.
- **F13 — APK-only page read SAFE.** `APK_HREF` was in both `WEAK_IDS` and the
  observed `MALICIOUS_DOWNLOAD` group, so the low-context branch fired first and
  returned SAFE 0. Removed `APK_HREF` from `WEAK_IDS`; an APK-only untrusted page is
  now MONITORING (no warning), not green SAFE.
- **F14 — password-focus event de-duplicated for the page's life.** `content.js`
  suppressed all but the first `PASSWORD_FOCUS` per domain, so only the first
  interaction armed the correlation window; a later exfiltration interaction could
  never re-arm it. Replaced the permanent per-domain dedup with a 3s time throttle
  (`sentPageEvents` is now a timestamp Map), so genuine re-interaction re-arms the
  window while focusin spam is still throttled.
- **F15 — weak suspicious-domain-word signal: reviewed, no change.**
  `getSuspiciousDomainSignals` matches `secure/update/login/account/verify/bank/
  wallet` as substrings. This is weight-2, capped, and can never raise a warning on
  its own (verified: benign corpus 0 FP, max score 5). Broad substring matching is
  a deliberate recall/precision tradeoff — tightening to token boundaries would lose
  concatenated-phish patterns ("securebank.com") and risk false negatives for no
  measured false-positive benefit. Left as-is pending real-browser FP evidence; the
  list duplication across code files is tracked under F8.

Files touched: `engine/evidence_decision_policy.js`, `content.js`,
`tests/run_evidence_policy_tests.js` (3 new cases: APK-only MONITORING, fake-bank
MONITORING, lookalike+observed SUSPICIOUS).

Verification (full suite): evidence policy `16/16`, exfil pipeline `3/3`, policy
integration `788 SAFE / 0 warnings` + `236 HIGH_RISK`, safe-policy `14/14`, detector
`15/15`, calibration `200/200`, benign `200/200`, randomized `1000/1000` (FP `0/500`,
FN `0/500`), correlation `18/18`, scan-freshness `16/16`, navigation `11/11`,
page-state/privacy/warning-path PASS. No engine-level FP/FN movement; F12 change is
policy-only and improves detection of same-origin credential phishing.
Remaining findings F8, F16–F18 open.

## Fixes applied — 2026-07-12 (audit findings F16, F17)

- **F16 — feedback egress was user-retargetable.** The options page exposes the
  feedback endpoint as a free text field and the worker accepted any http/https
  URL, so a settings change (or a tampered stored setting) could POST
  false-positive reports (page domain + evidence ids + feature vector) to an
  arbitrary external host. Fix: new shared `engine/feedback_endpoint.js`
  (`normalizeFeedbackEndpoint` / `isLoopbackHost`) pins the endpoint to **loopback
  only** (`localhost`, `127.0.0.0/8`, `::1`); any other host reverts to the local
  default. Enforced in BOTH `service_worker.js` (point of egress) and `options.js`
  (on save, with a status note when a value is reverted), so the two agree — this
  also removes the duplication the fix would otherwise have created.
- **F17 — Private Network Access resilience.** A public page context reaching a
  loopback address is blocked by Chrome PNA (`ERR_NETWORK_ACCESS_DENIED`).
  Hardened `saveFalsePositiveReport`: the report is now **persisted locally BEFORE**
  any network attempt (so a PNA block, offline collector, or service-worker
  shutdown can never lose it), delivery is attempted only to a loopback endpoint
  (defense in depth), and PNA/network errors are classified into a plain
  `LOCAL_COLLECTOR_UNREACHABLE` note instead of a raw error. The stored record's
  delivery status is updated after the attempt. No user-facing failure; the local
  queue is authoritative. (No manifest change needed — the extension already holds
  host permission for localhost; the fix is about durability + not depending on the
  public→local path.)

Files touched: `engine/feedback_endpoint.js` (new), `service_worker.js`,
`options.js`, `options.html`, `tests/run_feedback_endpoint_tests.js` (new, 16 cases).

Verification (full suite): feedback-endpoint `16/16`, report-privacy PASS, evidence
policy `16/16`, policy integration `788 SAFE / 0 warnings`, safe-policy `14/14`,
detector `15/15`, calibration `200/200`, benign `200/200`, randomized `1000/1000`
(FP `0/500`, FN `0/500`), correlation `18/18`, scan-freshness `16/16`, navigation
`11/11`, exfil pipeline `3/3`, page-state/warning-path PASS. Remaining findings
F8, F18 open.

## Fixes applied — 2026-07-12 (audit finding F18)

- **F18 — `npm install` was broken in this copy.** `package.json` pinned Playwright
  to `file:reports/night_autofix/npm-packages/*.tgz`, a path the portfolio copy
  excluded as generated junk, so `npm install` failed with a missing-file error.
  Fix: re-vendored the two tarballs (`playwright-1.61.1.tgz`,
  `playwright-core-1.61.1.tgz`, ~3.6 MB) into a clean `vendor/` directory, repointed
  `package.json` to `file:vendor/*.tgz`, and moved them from `devDependencies` to
  `optionalDependencies` so a plain `npm install` never hard-fails when Playwright is
  absent or the browser download is offline. Added a `"//"` note recording that the
  Node unit suite needs no dependencies (`node tests/<file>.js`) and Playwright is
  only for the optional `test:browser` harness.

Verified with `npm install --dry-run --offline --ignore-scripts`: both packages
resolve from `vendor/` with no network — install is fixed and fully offline. Unit
suite unaffected. Files touched: `package.json`, `vendor/` (2 new tarballs).

## Status summary

Fixed: F1, F2, F3, F4, F5, F6, F7, F9, F10, F11, F12 (real sub-gap), F13, F14, F16,
F17, F18. Reviewed/no-change (intended design): F12 core, F15. **Open: F8** (trusted-
domain + category keyword config duplicated across `content.js`, `service_worker.js`,
and JSON). All other findings resolved. Full suite green; engine calibration
unchanged (0/500 FP, 0/500 FN); nothing pushed.

---

## Migration log

**2026-07-12 — initial portfolio copy**

- Source: `C:\Users\User\Desktop\Project-Argus-Extension` (untouched — copy only, no move/delete).
- Target: `C:\Users\User\Desktop\Project\ARGUS` (portfolio layout matching HEIMDALL_V2).
- Method: `robocopy /E` with excluded dir names, then curated copies into `02_` / `03_`.

Copied:
- `01_FULL_SOURCE_CODE_REPO\` — full runnable source (86 files, ~30 MB): manifest,
  content.js, service_worker.js, popup/options, style.css, `engine\` (7 files),
  `test-site\`, `tests\` (17), `scripts\`, `backend\` (no venv), `datasets\` (12),
  trusted_domains.json, risky_categories.json, package.json, package-lock.json, all root `.md`.
- `02_EVALUATION_REPORTS\` — CALIBRATION_REPORT.md, Architecture PDF,
  `night_autofix_summary\` (`.md` + small json/csv only).
- `03_DATASETS_OFFLINE\` — 12 dataset files + OFFLINE_ONLY.txt (curated presentation copy).
- `00_README\` — handoff, project instructions (ARGUS.md), START_HERE.txt.

Excluded (junk / offline / prior user decision):
- `node_modules`, `backend\venv`, `**\__pycache__`, `.git`, `tmp\`,
  `reports\night_autofix\{artifacts,npm-cache,npm-packages,profiles,logs}` (~231 MB),
  `output\` (only the one PDF was pulled into `02_`).
- `Website_testonly\` — deliberately excluded; it was removed from Git in commit
  `efcfa0a` by prior user request. Still present in the original local tree.

Rationale — source + tests + scripts + datasets kept together in one folder:
test files `require('../engine/...')` / `../service_worker.js` and calibration runners
read `datasets/*.json` via relative paths. Chrome ignores the extra `tests/`,`scripts/`,
`backend/` when loading the root unpacked, so `01_FULL_SOURCE_CODE_REPO` is both runnable
AND Load-unpacked-able.

Safety scan on copied tree: no API keys / `sk-` tokens / OpenAI refs / `.env` found. ✅

---

## Verification (2026-07-12, run inside `01_FULL_SOURCE_CODE_REPO`)

| Check | Result |
|-------|--------|
| `run_evidence_policy_tests.js` | ✅ 13/13 |
| `run_exfiltration_pipeline_regressions.js` | ✅ 3/3 |
| `run_policy_integration_tests.js` | ✅ 788 SAFE / 0 warnings; 236 direct-evidence HIGH_RISK |
| `run_safe_policy_regressions.js` | ✅ 14/14 |
| `run_navigation_guard_tests.js` | ✅ 7/7 |
| `manifest.json` parse | ✅ v5.1.1, manifest_version 3 |
| Secret / `.env` scan | ✅ none |

Copy is loadable and passes the full required suite identically to source.

---

## Known issues (carried from handoff §7 — NOT yet fixed here)

Documentation/version drift — do **not** patch blindly; fix only after behavior is final:

- [ ] **Version drift:** `manifest.json` = `5.1.1` but `package.json` = `5.1.0` (confirmed in copy).
- [ ] `README.md` still describes model-only as `MONITORING/UNCERTAIN`; policy v2 makes
      no-evidence model-only = `SAFE 0`.
- [ ] `ARCHITECTURE.md` still refers to "Project Argus 4.2" in places.
- [ ] `tests/CALIBRATION_REPORT.md` is a 4.2-era report; does not fully reflect policy v2.
- [ ] Git remote is `Argus-Security.git` (not the older "Argus-Cybersecurity" name from chat).
- [ ] Latest source work in the original tree is uncommitted / unpushed. This copy does
      not change that; nothing was pushed.

---

## Open browser-verify tasks

- [ ] **0/5 exfiltration bug:** unit/integration all green, but confirm on REAL Chrome —
      Load-unpacked `01_FULL_SOURCE_CODE_REPO` (v5.1.1), open
      `http://127.0.0.1:4173/verified-network-exfil-demo.html`, press submit, wait for
      interaction-final scan. Expect cross-domain sensitive write telemetry → HIGH_RISK (> 5).
      If still 0/5, inspect `scanResult.debug.pipeline`, network counters, accepted/rejected
      page events, policy version. Root cause was a form-event vs `webRequest` async race;
      retroactive correlation + telemetry-direct policy backstop already added — needs live proof.
- [ ] **Headless E2E harness** `tests/run_real_browser_audit.js` still times out (no service
      worker in headless context). Do not claim browser E2E passing until it runs on an actual
      loaded extension.

---

## Guardrails reminder

Copy is organization-only — no source, scoring, or threshold changes were made.
Original untouched · no push · local model only · datasets stay offline-labeled.

---

## 2026-07-12 Codex isolated upgrade — ARGUS 5.2.0

- [x] Added `RISKY_CATEGORY` as a non-overlay caution for unverified gambling/betting sites.
- [x] Added login, registration, deposit/withdrawal, payment, wallet, and identity-upload surface detection, including debounced SPA/DOM rescans.
- [x] Added hostname-only loopback reputation lookup with reviewed offline seeds and optional Google Web Risk support through `ARGUS_WEBRISK_API_KEY`.
- [x] Added the ten user-supplied domains as `GAMBLING_UNVERIFIED` field regressions; none are labeled as confirmed phishing or data theft.
- [x] Added distinct popup/badge styling, schema 3 reputation provenance, options, privacy documentation, and backend documentation.
- [x] Fixed manifest/package/detection taxonomy version drift to 5.2.0.
- [x] Passed JavaScript syntax checks, 18/18 evidence-policy cases, 51/51 field regressions, 19/19 shared-config checks, 14/14 safe-policy regressions, privacy checks, 200/200 calibration, 200/200 benign robustness, 1000/1000 randomized evaluation, and five-fold 969/1000 exact-level validation with 0/500 SAFE false positives and 0/500 fake false negatives.
- [x] Python-compiled `backend/main.py` and `backend/reputation.py`; standard-library reputation normalization, seed lookup, and offline fallback passed.
- [ ] Live Chrome verification remains required. The existing handoff notes that the headless extension harness does not reliably start the Manifest V3 service worker.

Scope guardrail for this upgrade: only files under `ARGUS_codex` were modified; the original project tree remains untouched.

---

## 2026-07-12 Codex isolated upgrade — ARGUS 5.3.0

- [x] Replaced the gambling-specific public state with general `RISKY_CONTEXT` while retaining gambling as context `GAMBLING`.
- [x] Added nine impersonation contexts: banking/lending, investment/crypto, payment/wallet, government/public service, telecom/utility, shopping/delivery, platform account, technical support/security, and reward/job/charity advance-fee.
- [x] Added a reviewed Thai-plus-global brand registry with official/authentication domains, aliases, locales, visual-hash slots, expiry, a compact public-suffix snapshot, and pinned Ed25519 verification for cached replacements.
- [x] Added claimed-brand/domain mismatch, deceptive subdomain, homograph/typosquat, high-value context, sensitive-action, and optional visual-identity evidence groups.
- [x] Added Conservative, Balanced-default, and Protective early-warning modes. Direct `HIGH_RISK` evidence cannot be suppressed by user sensitivity.
- [x] Added two-stage behavior: badge caution before interaction and automatic detail expansion after a sensitive focus/click event.
- [x] Added local offscreen dHash processing with HTTPS-only, credential-free, 512 KiB-limited image fetches and ephemeral caching. Images/hashes are never uploaded or reported.
- [x] Added schema 4 identity provenance, privacy-safe reporting, a local fake-KBank manual fixture, packaging updates, QA/release documentation, and explicit Python selection in the validator.
- [x] Complete validation passed: 22/22 non-browser Node suites, 17/17 identity tests, 54/54 nine-context assertions, 6/6 visual guards, 51/51 gambling regressions, 200/200 calibration, 200/200 benign robustness, 1000/1000 randomized evaluation, and five-fold 969/1000 exact levels with zero binary SAFE false positives/fake false negatives.
- [ ] Populate reviewed production visual hashes through a signed registry release; the bundled bootstrap currently contains empty visual-hash arrays, so visual matching is implemented and tested but text/domain/context evidence remains the active identity source.
- [ ] Perform live Chrome manual verification of the new offscreen visual worker and two-stage badge/detail interaction.

Scope guardrail remains unchanged: only `ARGUS_codex` was edited.
