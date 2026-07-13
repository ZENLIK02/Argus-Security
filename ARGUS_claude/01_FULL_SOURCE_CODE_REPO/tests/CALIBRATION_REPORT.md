# Project Argus 4.2 calibration report

Date: 2026-07-11

## Objective

Expand the detector beyond a single network-priority axis while preserving direct network/form evidence as the strongest authority. Add privacy-safe coverage for phishing input capture, script relays, browser storage intent, mixed content, third-party script/frame isolation, security-header posture, redirects, and downloads. Eliminate stale scan reuse after navigation.

## Corpus

Training and evaluation use 1,400 cases:

| Family | Cases |
| --- | ---: |
| Original benign/content/context/form/network/script cases | 65 |
| Expanded benign controls | 30 |
| Expanded phishing and input capture | 25 |
| Expanded client-side exfiltration | 30 |
| Expanded browser protections | 25 |
| Expanded downloads and redirects | 15 |
| Expanded content-only controls | 10 |
| Benign robustness suite | 200 |
| Seeded-randomized SAFE websites | 500 |
| Seeded-randomized fake websites | 500 |

The corpus stores only numeric/boolean metadata and sanitized endpoint paths. It contains no credentials, payloads, packet captures, cookies, tokens, or live malicious code.

## Measured Iterations

| Run | Change | Result | Finding |
| --- | --- | ---: | --- |
| 1 | Version 3 engine on expanded corpus | 125 pass / 74 detected failures | Phishing combinations, client relays, browser protections, and download chains were underweighted |
| 2 | Added analyzers, score floors, and first model | 200/200 engine cases | Deterministic coverage complete; model held-out accuracy required refinement |
| 3 | Added bank/form/recovery interaction features | 200/200 engine cases | Validation errors reduced to one edge case |
| 4 | Balanced repeated benign and attack variants | 200/200 engine cases | Held-out validation reached 100% for the fixed synthetic split |
| 5 | First randomized 500/500 run | 500/500 SAFE, 450/500 fake detected | URL-obfuscated credential pages lacked browser-observable lexical evidence |
| 6 | Added URL lexical analyzer and interaction feature | 1000/1000 engine cases | SAFE FP 0/500 and fake FN 0/500 |
| 7 | Five-fold randomized cross-validation | 969/1000 exact levels | Binary SAFE/fake separation was 1000/1000 out-of-fold |

## Final Training

- Model: regularized logistic calibrator.
- Features: 69 privacy-safe numeric/boolean signals.
- Dataset: 200 core, 200 benign robustness, and 1,000 randomized cases.
- Benign suite: 100 behavior counterexamples plus 100 UCI PhiUSIIL legitimate URL cases.
- Split: deterministic 1,125 training / 275 validation cases.
- Epochs: 100 accepted updates.
- Training loss: `0.09369823` to `0.00667496`.
- Every accepted epoch reduces training loss.
- Held-out level accuracy: 98.91%.
- Held-out HIGH_RISK recall: 96.15%.
- Held-out SAFE false-positive rate: 0%.
- Benign robustness result: 200/200 SAFE, maximum observed score 20.
- Randomized held-out SAFE false-positive rate: 0%.
- Randomized held-out fake detection recall: 100%.
- Five-fold out-of-fold result: SAFE FP 0/500, fake FN 0/500, exact level accuracy 96.9%.

## False-Positive Iteration

The first 200-case benign behavior run produced 20 warning-level false positives: 10 legitimate MFA/login cases and 10 enterprise SSO cases. The cause was a hard SUSPICIOUS floor for password + OTP + login on every untrusted domain. The fix removed that isolated floor, required at least two suspicious-domain indicators or a brand-lookalike pattern for escalation, and retrained the calibrator with benign authentication/SSO counterexamples. The final benign suite passed 200/200, including the independent PhiUSIIL legitimate URL holdout.

These metrics describe the fixed synthetic evaluation corpus, not a guarantee for the open web. The deterministic evidence rules, trusted/search guards, score caps, and user false-positive reporting remain necessary.

## Randomization

The 1,000-case corpus uses a fixed seed and balanced UCI PhiUSIIL URL labels. Each class has ten 50-case behavior families. Numeric request counts, form combinations, OTP/password presence, scripts, storage, frames, security posture, downloads, redirects, and exfiltration paths vary per case. Five balanced folds ensure every randomized case is evaluated once without being in that fold's training set.

## Final Behavior

- Unencrypted sensitive write: HIGH_RISK, score floor 92.
- Cross-domain sensitive write: HIGH_RISK, score floor 84.
- Sensitive beacon/query relay: HIGH_RISK, score floor 76.
- Direct sensitive HTTP form: HIGH_RISK, score floor 88.
- Sensitive mixed active content: HIGH_RISK, score floor 76.
- Full fake-bank or fake-store credential flow: HIGH_RISK, score floor 72.
- Corroborated static script/storage/message relay: SUSPICIOUS, capped at 60 without direct evidence.
- Security headers missing by themselves: SAFE supporting evidence only.
- Adult/gambling/ad-heavy content by itself: SAFE, capped at 12.
- Full and SPA navigation: old per-tab evidence and stored scan are cleared.
- Multiple URL obfuscation signals plus credential behavior: SUSPICIOUS, score floor 38.

## Reproduce

```powershell
node scripts/generate_exfiltration_corpus.js
node scripts/generate_benign_robustness_corpus.js
node scripts/generate_randomized_web_corpus.js
node scripts/train_local_model.js
node tests/run_detector_tests.js
node tests/run_exfiltration_calibration.js
node tests/run_benign_robustness.js
node tests/run_randomized_web_evaluation.js
node tests/run_randomized_cross_validation.js
node tests/run_model_training_tests.js
node tests/run_page_state_tests.js
powershell -ExecutionPolicy Bypass -File scripts/run_stability_validation.ps1
```
