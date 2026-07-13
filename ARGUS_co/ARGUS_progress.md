# ARGUS_co — Merge Progress Log

Living document for the merged tree. `ARGUS_co` = merge of the two 2026-07-12 forks:

- **A = ARGUS_claude** (v5.1.1 "depth"): verified reputation blocklist stack (DI client,
  URLhaus/OpenPhish feeds, E2E vs real uvicorn, live-Chrome debugged), offline lookalike
  detector (homoglyph/typosquat/combosquat), P3 lookalike+credentials → SUSPICIOUS.
- **B = ARGUS_codex** (v5.3.0 "breadth"): RISKY_CONTEXT state, brand-identity registry
  (Thai+global, Ed25519-signed updates), nine impersonation contexts, sensitivity modes,
  content.js sensitive-surface detection + SPA rescans, offscreen visual dHash (inert),
  graded reputation verdicts + optional Google Web Risk.

**Merged version matrix:** manifest/package/detection-policy/categories `6.0.0` ·
decision policy `evidence-first-v5` · report schema `5` · local model `5.0.0` (unchanged).

Base = A (every feature verified end-to-end); B layered on top.

## Merge decisions (2026-07-13)

- Reputation architecture from A (DI `reputation_client.js`); B's untested inline SW
  implementation deleted. Single injection point: MALICIOUS → policy direct rule
  `REPUTATION_BLOCKLISTED` (95); RISKY_CONTEXT verdict → injected
  `REPUTATION_RISKY_CONTEXT` evidence (20 pts).
- Verdict vocabulary from B: `UNKNOWN | TRUSTED | RISKY_CONTEXT | MALICIOUS` + confidence
  + categories. `listed` kept as MALICIOUS-compat boolean.
- Backend = A base (blocklists, reload routes) + B's `reputation.py` (IDNA normalize,
  reviewed seeds, optional Web Risk via `ARGUS_WEBRISK_API_KEY`). Resolution order:
  blocklist → Web Risk → seed → UNKNOWN.
- Decision ladder = evidence-first-v5, six states
  `SAFE/MONITORING/UNCERTAIN/RISKY_CONTEXT/SUSPICIOUS/HIGH_RISK`; A's direct rules +
  P3 escalation preserved; B's contextRisk/sensitivity/warningStage preserved.
- Brand source: B's `brand_registry.json` feeds A's `domain_similarity.js` via
  `signals.lookalikeBrandDomains` (fallback `LOOKALIKE_BRANDS` for node tests).
- Settings: canonical key `reputationEnabled` (migrates A's `useReputation`,
  explicit opt-out preserved); new `sensitivityMode: BALANCED`.
- Offscreen visual dHash included **inert**: code + guarded SW plumbing copied, but no
  `"offscreen"` manifest permission (registry visual hashes are empty anyway).
  Enable later = add permission + populate signed registry hashes.
- Excluded: B's inline reputation, B's committed Chrome-profile dump
  (`reports/night_autofix/profiles/**`), node_modules/.npm-cache/venv, P4 model retrain
  (still deferred; model byte-identical in both forks).

## Work log

### 2026-07-13 — Phase 0: scaffold
- Created `ARGUS_co/`, robocopied A's tree excluding `backend/venv`, `__pycache__`,
  `node_modules`, `.npm-cache`, `.git`.

### 2026-07-13 — Phase 1: additive copies from B
- Copied: `engine/brand_identity.js`, `engine/brand_registry.json` (expiry checked:
  valid until 2027-07-12), `backend/reputation.py` + `reputation_seed.json`,
  `offscreen.html/js`, both B datasets, five B-unique tests,
  `test-site/fake-kbank-identity.html`.
- Wholesale replaced with B (superset side): `content.js`, `popup.html/js`,
  `options.html/js`, `style.css`, `risky_categories.json`.

### 2026-07-13 — Phase 2: manual merges
- **shared_lists.js**: union — kept `LOOKALIKE_BRANDS`, added B's gambling patterns
  + 6 keyword categories (paymentWallet/government/telecomUtility/delivery/
  platformAccount/jobCharityFee).
- **evidence_decision_policy.js**: evidence-first-v5, schema 5, six states.
  DIRECT_RULES = shared 12 + `REPUTATION_BLOCKLISTED` + `HOMOGLYPH_BRAND_DOMAIN`
  (+ `REPUTATION_CONFIRMED_MALICIOUS` kept as recognized legacy alias, never
  emitted). Groups = union; `DOMAIN_BRAND_LOOKALIKE` removed from B's DOMAIN_RISK
  so one lookalike detection can't count as two correlation groups.
  `EXTERNAL_REPUTATION` carries graded verdicts only (malicious is direct-only).
  Ladder: direct (reputation floor 95 / homoglyph 90) → trusted/official SAFE →
  SUSPICIOUS (correlated ∨ impersonationPhishing[P3, extended to accept
  BRAND_HOMOGRAPH_OR_TYPOSQUAT] ∨ identitySuspicious) → RISKY_CONTEXT
  (contextRisk; reputation RISKY_CONTEXT verdict alone qualifies; before weak-SAFE)
  → weak-SAFE → model-only SAFE → MONITORING caps → SAFE. warningStage from B;
  payload = union incl. `reputationDirectEvidenceIds` + `identityEvidence.lookalikeKind`.
- **argus_engine.js** 6.0.0: A base + B's `analyzeIdentity` analyzer +
  `SENSITIVE_ACTION_SURFACE`; lookalike detector brand source =
  `signals.lookalikeBrandDomains` (registry) with `LOOKALIKE_BRANDS` fallback.
- **reputation.js / reputation_client.js**: A architecture + B graded vocabulary
  (UNKNOWN/TRUSTED/RISKY_CONTEXT/MALICIOUS; RISKY_CATEGORY normalized). Per-verdict
  TTL (MALICIOUS 6h, RISKY_CONTEXT 1h, else 30min). Rescan only on MALICIOUS.
  Request body `{hostname, host}` (canonical + compat). Key `reputationEnabled`.
- **service_worker.js**: A base. importScripts + engineReady add brand_identity.
  Settings: `reputationEnabled` (migrates `useReputation`, preserves explicit
  opt-out) + `sensitivityMode: BALANCED`; self-heal extended. Pipeline: registry
  load (signed-envelope Ed25519 path ported) → identitySignals → A's DI reputation
  client (B's inline `lookupReputation` NOT ported) → single-injection rule:
  MALICIOUS via policy direct only; `addReputationEvidence` keeps just the
  RISKY_CONTEXT arm (20 pts). Report schema 5 union (identity + reputation +
  A's diagnostics). Offscreen plumbing ported, inert (no manifest permission).
- **detection_policy.json** 6.0.0: union weights (homoglyph 90 + B's 7 identity
  weights + REPUTATION_RISKY_CONTEXT 20).
- **backend/main.py**: A base + B's reputation.py. Resolution: blocklist →
  MALICIOUS; Web Risk (optional `ARGUS_WEBRISK_API_KEY`) → MALICIOUS; seed →
  RISKY_CONTEXT; else UNKNOWN. Unified response (hostname/host/domain echo,
  graded verdict, `listed` compat). `/health` + reload report seed count.
  `requirements.txt` + pytest.
- **validate.ps1**: B base + A suites (domain similarity, reputation unit + E2E
  with spawned uvicorn, correlation, freshness, shared config, feedback, exfil
  pipeline) + backend route tests (own runner; pytest optional).
- **manifest** 6.0.0 — `offscreen` permission deliberately ABSENT (visual pipeline
  inert until reviewed hashes ship; adding the permission is the enable switch).
- Tests reconciled: evidence policy 27/27 (union: gambling → RISKY_CONTEXT replaces
  old category-only SAFE case; adult-only still SAFE; graded reputation cases
  added), policy integration counts 40 intentional gambling cautions, visual-hash
  guard flipped to assert the permission is absent + SW guards the missing API,
  reputation unit 41/41 (TTL/vocabulary/migration guards), route tests rewritten
  for the unified schema (11 PASS), E2E 30/30 incl. seed → RISKY_CONTEXT badge
  path, report privacy asserts hostname-only reputation payload + no identity
  text/screenshot retention.

### 2026-07-13 — Verification (full gate)
`scripts/validate.ps1` end-to-end PASS: detector 15/15 · calibration 200/200 ·
evidence policy 27/27 · safe policy 14/14 · integration 788 SAFE + 40 intentional
gambling cautions / 0 unexpected warnings / 236 direct HIGH_RISK · navigation 11/11 ·
warning-path PASS · report privacy PASS (schema 5) · gambling regressions 51/51 ·
identity 17/17 · impersonation corpus 54/54 · visual guards 7/7 · domain similarity
30/30 · reputation unit 41/41 · correlation 18/18 · freshness 16/16 · shared config
19/19 · feedback 16/16 · exfil pipeline 3/3 · benign robustness **200/200** ·
randomized **1000/1000 (SAFE FP 0/500, fake FN 0/500)** · five-fold 969/1000
(binary FP/FN 0) · backend reputation PASS · route tests 11/11 · reputation E2E
**30/30 vs real uvicorn**. Model 5.0.0 untouched (byte-identical in both forks).

### Open items
- [ ] Live Chrome manual pass: load unpacked `ARGUS_co/01_FULL_SOURCE_CODE_REPO`
  + `uvicorn main:app --port 8000`; verify (1) blocklisted host → HIGH_RISK 95,
  (2) seed gambling host → orange RISKY_CONTEXT badge → INTERACTION escalation on
  sensitive focus, (3) A's reputation INTERACTION_FINAL rescan coexists with B's
  debounced SPA MutationObserver rescan, (4) official bank domain → SAFE,
  (5) settings migration on an existing profile.
- [ ] Populate reviewed visual hashes via a signed registry release, then add the
  `offscreen` permission to enable visual matching.
- [ ] P4 model retrain (offline 1.26M corpus) — runbook in ARGUS_claude log.
