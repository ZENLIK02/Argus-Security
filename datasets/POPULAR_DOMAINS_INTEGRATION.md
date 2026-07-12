# ARGUS Popular Domains 10K — Integration Guide

## Files

- `argus_popular_domains_10000.csv` — full research/training table
- `argus_popular_domains_10000.json` — optimized domain lookup map for the Chrome Extension
- `argus_popular_domains_10000.xlsx` — human-readable workbook with summary and full dataset

## Critical rule

This dataset is **not a hard whitelist**.

A domain being popular does not prove that every page, subdomain, script, form, or
network request is safe. Argus must continue to prioritize behavior-based evidence.

## Recommended scoring

```javascript
function applyPopularityAdjustment(result, popularEntry) {
  if (!popularEntry) return result;

  const strongSignals = [
    result.crossDomainPasswordForm,
    result.httpPasswordOrOtpSubmission,
    result.thirdPartyRequestsAfterSensitiveInteraction > 0,
    result.dynamicDataExfiltrationEndpoint,
    result.sendBeaconAfterSensitiveInteraction,
    result.httpApkLink,
    result.thirdPartyApkLink,
    result.hiddenIframeWithCredentialCollection
  ].some(Boolean);

  if (strongSignals || popularEntry.strong_behavior_override) {
    // The entry flag means behavior detection is always allowed to override popularity.
    // Apply the reduction only when strongSignals is false.
  }

  if (!strongSignals) {
    result.score = Math.max(
      0,
      result.score + popularEntry.score_adjustment
    );
  }

  return result;
}
```

## Lookup example

```javascript
const response = await fetch(chrome.runtime.getURL("argus_popular_domains_10000.json"));
const dataset = await response.json();

const entry = dataset.domains[currentDomain];
if (entry) {
  console.log(entry.rank, entry.tier, entry.score_adjustment);
}
```

## Recommended decision order

1. Extract DOM, script, form and network behavior signals.
2. Calculate the behavior-based score.
3. Check trusted official domains separately.
4. Check this popular-domain dataset as a weak negative-risk signal.
5. Do not reduce risk when strong exfiltration, insecure credential transfer,
   suspicious APK delivery or deceptive form behavior exists.
6. Keep a local false-positive log and periodically update the dataset.

## Data provenance

- Source: OpenDNS Top Domains List (public snapshot)
- URL: https://github.com/opendns/public-domain-lists/blob/master/opendns-top-domains.txt
- Generated bundle date: 2026-07-11
- Source snapshot date: unknown (public repository snapshot; refresh before production)

The source list is a public snapshot and may contain stale domains, infrastructure
domains, advertising domains and domains whose ownership or behavior can change.
Refresh and revalidate before production deployment.
