# OpenCTI Integrated Wazuh — Windows and Linux Endpoints

Step-by-step notes for wiring OpenCTI threat intelligence into Wazuh, with Windows and Linux
endpoint telemetry collected **natively** (no Sysmon on Windows — see `phase3-windows-native-telemetry.md`
for why). Files are listed below in the order you should work through them.

## Contents / step-by-step order

| Step | File | What it covers |
|---|---|---|
| 1 | `opencti-installation-core-dependencies.md` | OpenCTI hardware sizing, `vm.max_map_count`, `.env`, Docker Compose services (Elasticsearch, Redis, RabbitMQ, MinIO, platform, workers) |
| 2 | `opencti-external-import-connectors.md` | External-import connectors — AlienVault OTX, AbuseIPDB, MalwareBazaar, ThreatFox — common env vars and deployment steps |
| 3 | `phase2-threat-intel-detection.md` | Phase 2: generating a dedicated OpenCTI API token, opening the firewall path (`ufw allow 8080/tcp`), verifying OpenCTI is reachable |
| 4 | `phase3-agent-group-windows.md` | Phase 3: centralized Windows agent group config (`agent.conf`) |
| 5 | `ignore-rules-windows.md` | FIM ignore/suppression rules — Windows |
| 6 | `linux-ignore.md` | FIM/audit ignore rules — Linux |
| 7 | `linux-endpoints-auditd.md` | Linux endpoint auditd install, tuning, and command-monitor rules |
| 8 | `phase3-windows-native-telemetry.md` | Phase 3: Windows endpoint setup — native OpenCTI telemetry with **no Sysmon** (Script Block Logging, Event 4688 process creation, logon auditing, Wazuh agent `<localfile>` blocks) |
| 9 | `manager-conf-wrapper (1).md` | Manager Conf: the `custom-opencti` wrapper script under `/var/ossec/integrations/`, plus ownership/permissions |
| 10 | `custom-opencti.py` | The actual integration script — reads Wazuh alerts, extracts IOCs, queries OpenCTI, writes back to the Wazuh socket |
| 11 | `opencti-endpoint-ioc-rules.xml` | Wazuh local rules — IOC-correlated detections (FIM, vuln, auth, DNS, firewall, web-log) |
| 12 | `phase4-ossec-conf.md` | Ossec Conf: the `<integration>` block wiring `custom-opencti` into `ossec.conf`, plus manager restart |

Screenshots referenced by the markdown files above live in `ss/` (`ss/1.png` – `ss/9.png`).

## Known issues carried over from the Notion notes (not changed here — flagging only)

- `phase4-ossec-conf.md` has a live-looking OpenCTI API token (`flgrn_octi_tkn_...`) and an internal
  hook URL (`10.234.236.25:8080`) in plain text — worth rotating/redacting before this repo goes public.
- `ss/5.png` and `ss/7.png` in the `ss/` folder are unused — they were exact duplicates of other
  screenshots supplied for Phase 3 and were never referenced from any file. Safe to leave or delete.
- `manager-conf-wrapper (1).md` still has the original filename with a trailing ` (1)` and a space —
  GitHub allows it, but it's an awkward link target if you ever reference it from another doc.
- This repo documents the **no-Sysmon / native-telemetry** approach for Windows (Event 4104 + 4688 +
  4624/4625). It intentionally does not include Sysmon-based rules — those live in the separate
  `Opencti-Intergated-Wazuh-With-Sysmon-And-Audit` repo, so don't mix rule ID ranges between the two.
