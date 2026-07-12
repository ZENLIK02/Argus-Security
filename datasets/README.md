# Defensive dataset references

Project Argus is a Chrome Extension, so it cannot ingest full PCAP traffic or inspect encrypted payloads. Training now uses 1,400 cases: 200 core cases, 200 benign robustness cases, and 1,000 seeded-randomized real-vs-fake cases.

The project does not store typed values, request bodies, request headers, cookies, or packet payloads.

## Primary references

- MITRE ATT&CK T1041, Exfiltration Over C2 Channel: https://attack.mitre.org/techniques/T1041/
- MITRE ATT&CK T1048.003, Exfiltration Over Unencrypted Non-C2 Protocol: https://attack.mitre.org/techniques/T1048/003/
- MITRE ATT&CK T1557, Adversary-in-the-Middle: https://attack.mitre.org/techniques/T1557/
- MITRE ATT&CK T1056, Input Capture: https://attack.mitre.org/techniques/T1056/
- MITRE ATT&CK T1027, Obfuscated Files or Information: https://attack.mitre.org/techniques/T1027/
- OWASP Form Action Hijacking: https://owasp.org/www-community/attacks/Form_action_hijacking
- OWASP Client-Side Security Risks: https://owasp.org/www-project-top-10-client-side-security-risks/
- OWASP Browser Storage Testing: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/12-Testing_Browser_Storage
- OWASP Third-Party JavaScript Management: https://cheatsheetseries.owasp.org/cheatsheets/Third_Party_Javascript_Management_Cheat_Sheet.html
- OWASP HTTP Security Response Headers: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html
- CWE-319 Cleartext Transmission of Sensitive Information: https://cwe.mitre.org/data/definitions/319.html
- NIST SP 800-52 Rev. 2, TLS implementation guidance: https://doi.org/10.6028/NIST.SP.800-52r2
- Chrome `webRequest` API: https://developer.chrome.com/docs/extensions/reference/api/webRequest

## Public network datasets used as design references

- CIC-Trap4Phish 2025: https://www.unb.ca/cic/datasets/trap4phish2025.html
- UCI PhiUSIIL Phishing URL Dataset: https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset
- URLHaus malicious URL feeds: https://urlhaus.abuse.ch/

- CIC-Bell-DNS-EXF-2021: https://www.unb.ca/cic/datasets/dns-exf-2021.html
- CIC-IDS2017: https://www.unb.ca/cic/datasets/ids-2017.html
- UNSW-NB15: https://research.unsw.edu.au/projects/unsw-nb15-dataset
- CTU-13: https://www.stratosphereips.org/datasets-ctu13

`randomized_web_eval_cases.json` contains 500 SAFE and 500 fake cases generated from balanced PhiUSIIL URL seeds. Ten behavior families per class vary authentication, SSO, commerce, content, scripts/storage, analytics, browser posture, phishing, fake stores/banks, unsafe forms, relays, mixed content, and observed exfiltration. Randomization is seeded for reproducibility.

No live malicious payload, credential, cookie, request body, packet payload, or page text is included.

Regenerate and run the local corpus:

```powershell
node scripts/generate_exfiltration_corpus.js
node scripts/generate_benign_robustness_corpus.js
node scripts/generate_randomized_web_corpus.js
node scripts/train_local_model.js
node tests/run_exfiltration_calibration.js
node tests/run_benign_robustness.js
node tests/run_randomized_web_evaluation.js
node tests/run_randomized_cross_validation.js
node tests/run_model_training_tests.js
```
