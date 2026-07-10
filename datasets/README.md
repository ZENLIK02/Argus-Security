# Defensive dataset references

Project Argus is a Chrome Extension, so it cannot ingest full PCAP traffic or inspect encrypted payloads. The local evaluation corpus converts authoritative network-exfiltration concepts into privacy-safe browser metadata signals that Chrome can actually observe: protocol, request method, resource type, initiator relationship, form sensitivity, and event timing.

The project does not store typed values, request bodies, request headers, cookies, or packet payloads.

## Primary references

- MITRE ATT&CK T1041, Exfiltration Over C2 Channel: https://attack.mitre.org/techniques/T1041/
- MITRE ATT&CK T1048.003, Exfiltration Over Unencrypted Non-C2 Protocol: https://attack.mitre.org/techniques/T1048/003/
- MITRE ATT&CK T1557, Adversary-in-the-Middle: https://attack.mitre.org/techniques/T1557/
- OWASP Form Action Hijacking: https://owasp.org/www-community/attacks/Form_action_hijacking
- NIST SP 800-52 Rev. 2, TLS implementation guidance: https://doi.org/10.6028/NIST.SP.800-52r2
- Chrome `webRequest` API: https://developer.chrome.com/docs/extensions/reference/api/webRequest

## Public network datasets used as design references

- CIC-Bell-DNS-EXF-2021: https://www.unb.ca/cic/datasets/dns-exf-2021.html
- CIC-IDS2017: https://www.unb.ca/cic/datasets/ids-2017.html
- UNSW-NB15: https://research.unsw.edu.au/projects/unsw-nb15-dataset
- CTU-13: https://www.stratosphereips.org/datasets-ctu13

These public datasets are not copied into the extension because their PCAP/flow files are large and contain features unavailable to an in-browser MV3 extension. Their useful design principles are represented in `exfiltration_eval_cases.json`: labeled benign controls, unencrypted transfers, cross-domain data movement, single-request exfiltration, low-and-slow sequences, and temporal correlation.

Regenerate and run the local corpus:

```powershell
node scripts/generate_exfiltration_corpus.js
node tests/run_exfiltration_calibration.js
```
