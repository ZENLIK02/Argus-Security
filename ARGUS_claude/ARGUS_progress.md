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

## Feature added — 2026-07-12 (P1: domain reputation slice)

First slice of the scam-detection roadmap. Adds a **domain-reputation direct
signal** so a real scam site is flagged even when no cross-domain/HTTP write is
browser-observable (e.g. a phishing page posting credentials to its own HTTPS
domain — the structural blind spot behind "ARGUS can't detect fake sites").

Pipeline: `service_worker` looks up the page domain against a local blocklist via the
**localhost backend** `/reputation`, caches the verdict (6h TTL), and passes it to the
evidence policy as a new **DIRECT rule `REPUTATION_BLOCKLISTED`** → immediate
HIGH_RISK (score 95), warning allowed. Non-blocking: an uncached domain is fetched in
the background and a rescan applies the verdict, so scans are never delayed.

- **New `engine/reputation.js`** — pure module (normalize/cacheKey/TTL/query-gate/
  verdict parsing), loaded via importScripts + added to `engineReady`.
- **`engine/evidence_decision_policy.js`** — `REPUTATION_BLOCKLISTED` in
  `DIRECT_RULES`; `directEvidenceFromReputation(context)`; blocklist hit scored 95;
  `reputationDirectEvidenceIds` in output.
- **`service_worker.js`** — `resolveReputationContext` / `getCachedReputation` /
  `refreshReputation`; `useReputation` + loopback-pinned `reputationEndpoint`
  settings (reuses the F16 pin); background refresh + rescan.
- **`backend/main.py`** — `POST /reputation` (domain-only, no URL/path/content);
  loads `backend/data/phishing_blocklist.txt` (seed; exact + parent-suffix match).
- **`options.html` / `options.js`** — reputation toggle + endpoint (loopback-pinned).

Privacy: only the page **domain** (metadata) reaches the local backend; no URL path,
query, or page content. Endpoint is loopback-pinned. This relaxes the strict
"no external service" rule per the user's decision to allow reputation lookups;
routing through the local backend keeps any future API keys off the extension.

Tests: `run_reputation_tests.js` (18) + 3 new `run_evidence_policy_tests` cases
(blocklist hit → HIGH_RISK/95/warning; clean → SAFE). Full suite green; engine
calibration unchanged (788 SAFE / 0 warnings, benign 200/200, randomized FP 0/500,
FN 0/500). Backend match algorithm verified against the seed file
(subdomain + parent match, clean domains pass).

**Not yet done / follow-ups:** real feeds (URLhaus/OpenPhish/PhishTank/Safe Browsing
hash-prefix) to replace the seed blocklist; let a reputation hit warn at PRELIMINARY
(currently gated to FINAL like other direct evidence); popup surfacing of the
reputation verdict; then roadmap P2 (homoglyph/lookalike engine), P3 (policy
escalation for credential+low-trust), P4 (model retrain). Backend needs
`pip install -r backend/requirements.txt` (fastapi/uvicorn) to run.

### Manual real-Chrome QA (to see it work)
1. `cd ARGUS_claude/01_FULL_SOURCE_CODE_REPO/backend` → create venv →
   `pip install -r requirements.txt` → `uvicorn main:app --port 8000`.
2. Load unpacked `01_FULL_SOURCE_CODE_REPO` in Chrome; Options → reputation ON.
3. Add a domain you can visit to `backend/data/phishing_blocklist.txt`, restart the
   backend, visit it → expect HIGH_RISK with reason "known phishing or malware
   blocklist" and `debug.pipeline` showing `reputationDirectEvidenceIds`.
4. Confirm ordinary sites (not listed) stay SAFE.

## Feature added — 2026-07-12 (P2: offline brand-lookalike detector)

Pure-local homoglyph / typosquat / combosquat detection — catches fresh, UNLISTED
brand-impersonation phishing that reputation feeds miss. No network.

- **New `engine/domain_similarity.js`** — pure module: Unicode-confusable + leetspeak
  "skeleton" folding (`gооgle`→`google`, `paypa1`→`paypal`, `arnazon`→`amazon`),
  Levenshtein edit distance, registrable-domain extraction, and `analyze(host, brands)`
  returning the best of HOMOGLYPH / TYPOSQUAT / COMBOSQUAT with confidence. Strong
  false-positive guards: the brand itself, its subdomains, raw IPs, and unrelated
  legitimate domains are never flagged.
- **`engine/shared_lists.js`** — new `LOOKALIKE_BRANDS` (curated big-tech / payment /
  marketplace / crypto / Thai-bank registrable domains).
- **`engine/argus_engine.js` `analyzeDomain`** — replaces the toy
  `hasBrandImpersonationPattern` regex with the detector (regex kept as fallback):
  - HOMOGLYPH → `HOMOGLYPH_BRAND_DOMAIN` (decisive) → **DIRECT → HIGH_RISK** (very high
    precision; a domain that renders identically to a brand is near-certainly malicious).
  - TYPOSQUAT → `DOMAIN_BRAND_LOOKALIKE` → new **BRAND_IMPERSONATION** group → MONITORING
    (surfaced, not a hard warning; FP-conscious).
  - COMBOSQUAT → `DOMAIN_BRAND_LOOKALIKE` **only when the page also collects
    credentials** (combosquat alone is too FP-prone).
- **`engine/evidence_decision_policy.js`** — `HOMOGLYPH_BRAND_DOMAIN` in `DIRECT_RULES`;
  `BRAND_IMPERSONATION` behavioral group (non-observed).
- **`engine/detection_policy.json`** — `HOMOGLYPH_BRAND_DOMAIN` weight 90 / floor 85 /
  priority 1.
- **`service_worker.js`** — `domain_similarity.js` added to importScripts + engineReady.
  (Detector runs engine-side in the worker; no content-script or model-feature change,
  so the 69-feature model is untouched — model retrain with a lookalike feature is P4.)

Tests: `run_domain_similarity_tests.js` (30 cases incl. FP guards on the brands and
legit look-alike-ish domains) + 2 new `run_evidence_policy_tests` cases (homoglyph →
HIGH_RISK; typosquat → MONITORING). **Full suite green; engine calibration UNCHANGED**
— detector 15/15, benign 200/200 (max score 5, zero FP), randomized 1000/1000
(FP 0/500, FN 0/500), policy integration 788 SAFE / 0 warnings. The detector added
zero false positives across all corpora.

Real-Chrome QA: visit `http://paypa1.com` / a Cyrillic-`gооgle` style host (or add a
harmless test host that skeletons to a brand) → expect HIGH_RISK "look-alike
characters"; a 1-edit typo host → MONITORING; ordinary sites stay SAFE.

**Follow-ups:** widen `LOOKALIKE_BRANDS`; add a lookalike model feature + retrain (P4).

## Feature added — 2026-07-12 (P3: brand-impersonation + credentials → SUSPICIOUS)

Targeted, high-precision escalation in `engine/evidence_decision_policy.js`: a brand
look-alike domain (typosquat/combosquat, the `BRAND_IMPERSONATION` group) that ALSO
collects credentials/OTP/payment (`SENSITIVE_INPUT` or `CREDENTIAL_PHISHING`) now
reaches **SUSPICIOUS with a warning WITHOUT requiring observed network behavior** —
classic phishing warrants a warning before the user submits anything. (Homoglyph is
already DIRECT/HIGH_RISK from P2, so this covers the typosquat/combosquat tier.)

- `decide()` adds `impersonationPhishing = BRAND_IMPERSONATION ∧ (SENSITIVE_INPUT ∨
  CREDENTIAL_PHISHING)`; the SUSPICIOUS branch and `warningAllowed` now fire on
  `correlatedBehavior || impersonationPhishing`; a distinct
  `BRAND_IMPERSONATION_PHISHING` evidence level + a clear reason string.
- Deliberately narrow: it is NOT a blanket "any two non-observed groups warn" (that
  would break FP discipline). A brand-look-alike domain is required, and the P2
  detector only flags real look-alikes — so ordinary untrusted login pages are
  untouched.

Tests: new `run_evidence_policy_tests` case (typosquat + credentials → SUSPICIOUS +
warning) and the SUSPICIOUS invariant updated to encode the new rule. Full suite
green; **calibration unchanged** — policy integration still `788 SAFE / 0 visible
warnings`, safe-policy `14/14`, benign `200/200`, randomized FP `0/500` / FN `0/500`.

End-to-end (engine → policy) verified:
- `gogle.com` + password/login → **SUSPICIOUS**, warns.
- `paypa1.com` + password → **HIGH_RISK** (homoglyph direct), warns.
- `gogle.com` alone (no credentials) → **MONITORING**, no warning.
- ordinary `mysmallsite.com` + password/login → **SAFE**, no warning (no false positive).

## Feature added — 2026-07-12 (P1 completion: real blocklist feeds)

Reputation now backs onto **real phishing feeds**, not just the 3-domain seed.

- **`backend/main.py`** — `load_blocklist()` merges the bundled seed with every
  `*.txt` under `backend/data/blocklists/`; new `POST /reputation/reload` re-reads
  from disk without a restart; `/health` reports `blocklistDomains` + sources.
- **`scripts/refresh_blocklists.js`** (new, Node 18+, no deps) — fetches public
  no-key feeds (abuse.ch **URLhaus**, **OpenPhish**), extracts hostnames, writes
  `backend/data/blocklists/<feed>.txt`. Verified live: pulled **~2,059 real
  domains** (1,775 URLhaus + 282 OpenPhish). PhishTank / Safe Browsing need API keys
  and are left as documented extensions.
- Matching verified on real data: listed domain + its subdomains flagged; clean
  domains (google.com) pass. Full JS suite still green; no engine change.

To use: `node scripts/refresh_blocklists.js` → restart backend (or `POST
/reputation/reload`) → visiting any listed domain returns HIGH_RISK. Fetched feed
files are generated artifacts (do not commit).

## P4 (model retrain) — NOT done here, by design

A proper P4 retrain **cannot be done in this copy without regressing the model**:
- The live model `engine/trained_model.json` is **v5.0.0, trained on ~1.26M raw
  records** (highRiskRecall 0.42) that are **offline / excluded** from this copy.
- The only trainer present (`scripts/train_local_model.js`) uses ~21k cases and
  writes a v4.3.0-style model — **less data, lower quality**, and would shift the
  model-gated policy branches, risking the 0/500-FP / 0/500-FN calibration.
- Adding features to the 69-vector (`FEATURE_NAMES`) breaks the current model:
  `predict()` length-checks and would **disable the model entirely**.

Model impact is also low-leverage: the model is **advisory-only** (never warns
alone). The actual scam-detection gains ship at the rule/policy layer — P1
(reputation→HIGH_RISK), P2 (homoglyph→HIGH_RISK, typosquat→MONITORING), P3
(lookalike+credentials→SUSPICIOUS). The 5.0.0 model was left intact.

**P4 retrain runbook (run on the machine that has the offline raw datasets):**
1. Port `engine/domain_similarity.js` skeleton/edit-distance to Python (or precompute
   a `brand_lookalike` / `homoglyph` label per training row from the domain).
2. Append `brand_lookalike`, `homoglyph_domain`, `reputation_hit` to
   `engine/feature_extractor.js` `FEATURE_NAMES` **and** compute them in `extract()`.
3. Add the same features to `scripts/train_full_mega_model.py`; retrain on the full
   1.26M corpus; bump model version.
4. Regenerate `engine/trained_model.json` + `.js` (feature count now matches).
5. Gate on the full node suite — require benign FP `0/500`, fake FN `0/500`,
   `run_policy_integration` `0 warnings`, before shipping the new model.

## Fix — 2026-07-12 (reputation route mismatch → canonical /v1/reputation/check)

The extension called `POST /v1/reputation/check` while the backend only served
`/reputation` (404). Unified both onto one canonical route with a backward-compatible
alias, and aligned the request/response schemas exactly.

- **`backend/main.py`** — canonical `POST /v1/reputation/check` (+ `/reputation`
  alias); `/v1/reputation/reload` (+ `/reputation/reload` alias). `ReputationRequest`
  now accepts `host` (canonical) or `domain` (alias). Response is one shape:
  `{ ok, host, domain, listed, verdict, source, matchedDomain }` where
  `verdict = "malicious" | "unknown"`.
- **`service_worker.js` / `options.js`** — default `reputationEndpoint` →
  `http://localhost:8000/v1/reputation/check`; request body `{ host }` only, with
  `credentials: "omit"`.
- **`engine/reputation.js`** — `verdictFromResponse` treats `listed === true` OR
  `verdict === "malicious"` as listed; reads `matchedDomain || host || domain`.
- **`backend/test_reputation_route.py`** (new, FastAPI TestClient) + JS cases in
  `run_reputation_tests.js`. `httpx` added to `requirements.txt` (TestClient dep).

Confirmed (integration test 7/7 + JS 20/20):
- `POST /v1/reputation/check` → **200**.
- blocklisted host (and its subdomains) → `verdict:"malicious"`, `listed:true`.
- clean host → `verdict:"unknown"`, `listed:false`, `source:"NONE"`.
- legacy `/reputation` alias and `domain` field still work.
- smuggled fields (`url`/`cookie`/`password`) ignored, never reflected — response keys
  are exactly `{ok, host, domain, listed, verdict, source, matchedDomain}`.
- request carries the **hostname only** — no URL path, query, cookies, or user data.
- backend outage stays non-fatal: fire-and-forget fetch with a 1.5s abort; failure →
  `unavailableVerdict` → not cached → no reputation evidence → scan proceeds normally.

Full JS suite green; engine calibration unchanged (788 SAFE / 0 warnings, FP 0/500,
FN 0/500).

## Fix — 2026-07-12 (live Chrome reputation showed SAFE; diagnostics + rescan fix)

Backend confirmed malicious for the test host, but Chrome displayed SAFE 0. Traced the
full live path. The evidence chain itself is correct (proven: a REAL `fetch` to the
running backend → verdict → policy → **HIGH_RISK 95 with REPUTATION_BLOCKLISTED**).
Two concrete live-path defects fixed in `service_worker.js`, no backend/threshold change:

1. **Silent fetch failure.** `refreshReputation` mapped any fetch error to
   `unavailableVerdict` with **no logging** — a blocked/failed SW fetch left the
   domain at SAFE with no visible cause. Now every lookup logs
   `[Project Argus] reputation lookup { host, endpoint, httpStatus, verdict, error }`
   and stores `chrome.storage.local.lastReputationDiag`.
2. **Slow / overwritable rescan.** After caching a verdict it called
   `schedulePageRescan(200)`, which only reaches a final phase via `INTERACTION_FINAL`
   ~5 s later, during which a stale SAFE scan sat. Now a **malicious** verdict triggers
   a prompt `INTERACTION_FINAL` rescan (highest phase) — applies immediately and the
   monotonic `saveScanResult` guard prevents any lower-phase SAFE scan from
   overwriting it.

Diagnostics added end to end: `resolveReputationContext` returns `{ context, diag }`;
`scanResult.debug.pipeline.reputation` now shows `{ enabled, endpoint, domain, queried,
cache: hit|miss, listed, source, applied, reason }` and
`reputationDirectEvidenceIds`. This surfaces every checklist suspect (useReputation
off, endpoint, cache miss, hostname/key, dropped evidence, fetch error).

Regression test (`run_reputation_tests.js`, now 28 cases): a malicious backend JSON →
`verdictFromResponse` → `toPolicyContext` → `decide` → HIGH_RISK 95 with
REPUTATION_BLOCKLISTED (asserts it is in both `reputationDirectEvidenceIds` and
`directEvidence`, warns/overlays); PRELIMINARY phase stays pending; clean verdict stays
non-HIGH_RISK. Full suite green; calibration unchanged.

**To diagnose on the live extension:** reload the unpacked extension (a stale SW is the
most common cause), open the service-worker console, visit the listed host, and read
`[Project Argus] reputation lookup` + `chrome.storage.local.get("lastReputationDiag")`.
`error: "Failed to fetch"` → the SW cannot reach localhost (permission/PNA); `cache:
miss` repeatedly → fetch never succeeds; `enabled:false` → turn reputation on in
Options; `applied:true` with SAFE → a scoring issue (not observed — chain is proven).

## Final integration — 2026-07-12 (settings auto-init + real-path E2E)

Fixes the live "reputation settings missing from chrome.storage → stays SAFE" bug and
adds a real backend→policy→stored-result end-to-end test. No manual console steps.

- **Auto-init settings** (`service_worker.js`): `ensureSettingsInitialized()` runs at
  worker startup and on `chrome.runtime.onInstalled` / `onStartup`. If `argusSettings`
  is missing or lacks reputation keys, it writes a normalized object (reputation ON,
  loopback-pinned endpoint) while preserving any explicit user choices. Reputation is
  never silently absent again.
- **Dependency-injected reputation client** (`engine/reputation_client.js`, new): the
  resolve/refresh/cache/rescan/diagnostics orchestration extracted from the worker
  with injected `storageGet/storageSet/fetchImpl/getNavigationId/scheduleRescan/
  inFlight`. The worker delegates to it, so the *actual* client logic is testable
  against a real backend.
- **Automated E2E** (`tests/run_reputation_e2e.js`, new): spawns its own uvicorn on
  :8791 with a temp blocklist, then drives the real client + real HTTP + policy +
  freshness — malicious host → cached + INTERACTION_FINAL rescan + `debug` HTTP 200 →
  resolve hit → policy **HIGH_RISK 95 with REPUTATION_BLOCKLISTED**; freshness guard
  keeps HIGH_RISK over a stale SAFE; clean control → SAFE, no rescan; backend outage →
  non-fatal, not cached. Tears the server + temp file down (Windows-safe teardown).
- Removed a stray `_temp_manual.txt` (listed `example.net`) from the shipped
  blocklists dir so the build flags nothing unexpected.

Full verification (all green): 18 JS unit/integration files, `run_reputation_e2e`
**22/22** against a real spawned backend, `backend/test_reputation_route.py` **7/7**.
Engine calibration unchanged (788 SAFE / 0 warnings, benign 200/200, randomized FP
0/500 / FN 0/500). Manifest MV3 v5.1.1; all 12 importScripts modules present.

The build is ready to Load unpacked. On reload the service worker initializes
reputation settings automatically — no console commands needed.

## Roadmap status
P1 (reputation + real feeds), P2 (offline lookalike), P3 (impersonation+credential
escalation) — **DONE and testable now**. P4 (model retrain) — pending the offline raw
datasets; runbook above. The model retrain is optional for detection quality since the
warning logic is rule/policy-driven.
