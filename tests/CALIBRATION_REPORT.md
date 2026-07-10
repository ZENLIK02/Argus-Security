# Project Argus 3.0 calibration report

Date: 2026-07-10

## Objective

Move score authority away from page category and keyword volume toward evidence that data is actually sent without transport protection or to an unexpected destination.

## Measured iterations

| Run | Policy state | Passed | Main failure pattern |
|---|---|---:|---|
| 1 | Original 2.0 policy | 32/64 | Observed network group passed only 2/16; content/adult/gambling produced false warnings; static intent reached 97 without a request |
| 2 | Priority tiers, score floors, lower context/category weights | 63/64 | Dynamic endpoint intent scored 31, slightly below the intended SUSPICIOUS boundary |
| 3 | Static intent combination recalibrated | 64/64 | All original corpus cases passed |
| 4 | Added query-bearing image GET exfiltration case | 65/65 | Final corpus passed |

The existing detector regression suite also passes 15/15 under policy 3.0.0.

## Final behavior

- Unencrypted sensitive write: score floor 92, HIGH_RISK.
- Cross-domain sensitive write: score floor 84, HIGH_RISK.
- Beacon/ping or query-bearing image request after sensitive interaction: score floor 76, HIGH_RISK.
- Direct sensitive HTTP form: score floor 88, HIGH_RISK.
- Direct sensitive cross-domain form: score floor 78-82, HIGH_RISK.
- Generic HTTP form write without evidence of sensitive fields: SUSPICIOUS, about 40.
- Static exfiltration intent without an observed request: SUSPICIOUS, capped at 60.
- Password/OTP/login/domain text alone: SAFE, normally below 20.
- Adult/gambling/ad-heavy content alone: SAFE, capped at 12.

## Privacy boundary

The tests and detector use synthetic metadata only. Project Argus does not retain typed values, request bodies, request headers, cookies, or packet payloads. The network detector uses protocol, method, resource type, initiator/destination relationship, query presence, and short-lived event timing.

## Reproduce

```powershell
node scripts/generate_exfiltration_corpus.js
node tests/run_exfiltration_calibration.js
node tests/run_detector_tests.js
```
