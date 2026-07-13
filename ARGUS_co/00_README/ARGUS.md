# Project Argus Claude Code Instructions

You are continuing development of Project Argus at:

`C:\Users\User\Desktop\Project-Argus-Extension`

Before making changes, read the complete handoff file:

`C:\Users\User\Desktop\Claude\PROJECT_ARGUS_CLAUDE_CODE_HANDOFF.md`

Then inspect the current working tree with `git status --short`, the latest commit, and the relevant source files. The working tree contains important uncommitted work. Never reset, revert, delete, or overwrite existing changes unless the user explicitly requests it.

## User Preferences

- Communicate in Thai by default; technical English is acceptable where clearer.
- When the user asks for silent work, do not send progress narration until finished.
- Prefer implementation and verified results over long plans.
- Preserve the old/version-3 bottom-left badge UI.
- Do not restore an automatic top-right warning popup.
- Keep risk text and borders color-matched: green SAFE, yellow suspicious/monitoring, red HIGH_RISK.
- Gambling, adult content, ads, popups, and image volume are low-priority context only.
- Prioritize browser-observed sensitive data movement, insecure transport, unknown cross-domain writes, and post-interaction beacons.
- Minimize false positives on ordinary websites.
- Clear old evidence on every navigation and SPA route change.

## Non-Negotiable Project Rules

- Local model only. Do not add OpenAI or another external AI classification API.
- Never store or transmit passwords, OTP values, cookies, tokens, request bodies, response bodies, query strings, authorization headers, or private messages.
- Raw datasets are offline training assets and must not be bundled into the Chrome extension or release ZIP.
- Do not use React.
- Do not add a database or large backend feature without an explicit request.
- Do not hardcode test domains or inflate thresholds/scores to make tests pass.
- Model-only evidence must never create a visible warning.
- Category/content evidence must never independently create HIGH_RISK.
- Do not claim payload theft is proven when Chrome exposes only metadata.
- Do not push to GitHub unless the user explicitly asks.
- Before any requested push, scan for secrets and exclude `.env`, venv, node_modules, caches, raw datasets, and generated junk.

## Current Technical Focus

- Manifest version: 5.1.1
- Local model: 5.0.0
- Final policy: evidence-first-v2
- Latest unresolved real-browser concern: some user screenshots still show only 0/5. Those screenshots mostly contain category/image context without confirmed sensitive data movement. Verify the dedicated runtime demo before changing scoring.
- Runtime demo: `http://127.0.0.1:4173/verified-network-exfil-demo.html`
- Start demo server: `node scripts\serve_argus_test_site.js`
- Reload the unpacked extension and refresh test tabs after source changes.

## Required Verification For Scoring Changes

Run at minimum:

```powershell
node tests\run_evidence_policy_tests.js
node tests\run_exfiltration_pipeline_regressions.js
node tests\run_policy_integration_tests.js
node tests\run_safe_policy_regressions.js
node tests\run_navigation_guard_tests.js
```

Report the root cause, modified files, test results, remaining browser limitations, and whether the latest changes are committed or pushed.

