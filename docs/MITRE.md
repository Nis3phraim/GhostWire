# GhostWire MITRE ATT&CK Mapping

This document maps GhostWire capabilities to the MITRE ATT&CK framework for red team and blue team reference.

| Technique ID | Technique Name | GhostWire Implementation |
|--------------|----------------|-------------------------|
| **T1071.004** | Application Layer Protocol: DNS | All C2 traffic encoded in DNS TXT queries to covert channels |
| **T1573.001** | Encrypted Channel: Symmetric Cryptography | AES-256-CTR session encryption after key exchange |
| **T1573.002** | Encrypted Channel: Asymmetric Cryptography | RSA-2048-OAEP used to encrypt the AES session key during registration |
| **T1041** | Exfiltration Over C2 Channel | `upload` command reads files from target and sends them to the server |
| **T1105** | Ingress Tool Transfer | `download` command drops files from the server to the target disk |
| **T1568.001** | Dynamic Resolution: Domain Generation Algorithm | DGA generates time-based subdomains for resilience and fallback |
| **T1008** | Fallback Channels | Backup C2 domains used automatically if the primary fails |
| **T1029** | Scheduled Transfer | Beaconing interval with sleep + jitter (`60s ± 30s`) |

## Defensive Detections

- **DNS:** Monitor for high-volume TXT queries to unknown domains.
- **Beaconing:** Alert on regular 60-second intervals with jitter.
- **Entropy:** DGA labels have high entropy compared to standard DNS names.
- **Host:** Look for Python processes repeatedly resolving the same domain set.
