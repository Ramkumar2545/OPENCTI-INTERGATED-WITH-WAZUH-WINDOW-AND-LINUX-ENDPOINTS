# OpenCTI Integrated Wazuh — Windows and Linux Endpoints

Step-by-step notes for wiring OpenCTI threat intelligence into Wazuh, with Windows and Linux
endpoint telemetry collected **natively** (no Sysmon on Windows — see `phase3-windows-native-telemetry.md`
for why). Files are listed below in the order you should work through them.

## Contents / step-by-step order

| Step | File | What it covers |
|---|---|---|
| 1 | [`opencti-installation-core-dependencies.md`](opencti-installation-core-dependencies.md) | OpenCTI hardware sizing, `vm.max_map_count`, `.env`, Docker Compose services (Elasticsearch, Redis, RabbitMQ, MinIO, platform, workers) |
| 2 | [`opencti-external-import-connectors.md`](opencti-external-import-connectors.md) | External-import connectors — AlienVault OTX, AbuseIPDB, MalwareBazaar, ThreatFox — common env vars and deployment steps |
| 3 | [`phase2-threat-intel-detection.md`](phase2-threat-intel-detection.md) | Phase 2: generating a dedicated OpenCTI API token, opening the firewall path (`ufw allow 8080/tcp`), verifying OpenCTI is reachable |
| 4 | [`phase3-agent-group-windows.md`](phase3-agent-group-windows.md) | Phase 3: centralized Windows agent group config (`agent.conf`) |
| 5 | [`ignore-rules-windows.md`](ignore-rules-windows.md) | FIM ignore/suppression rules — Windows |
| 6 | [`linux-ignore.md`](linux-ignore.md) | FIM/audit ignore rules — Linux |
| 7 | [`linux-endpoints-auditd.md`](linux-endpoints-auditd.md) | Linux endpoint auditd install, tuning, and command-monitor rules |
| 8 | [`phase3-windows-native-telemetry.md`](phase3-windows-native-telemetry.md) | Phase 3: Windows endpoint setup — native OpenCTI telemetry with **no Sysmon** (Script Block Logging, Event 4688 process creation, logon auditing, Wazuh agent `<localfile>` blocks) |
| 9 | [`manager-conf-wrapper (1).md`](<manager-conf-wrapper (1).md>) | Manager Conf: the `custom-opencti` wrapper script under `/var/ossec/integrations/`, plus ownership/permissions |
| 10 | [`custom-opencti.py`](custom-opencti.py) | The actual integration script — reads Wazuh alerts, extracts IOCs, queries OpenCTI, writes back to the Wazuh socket |
| 11 | [`opencti-endpoint-ioc-rules.xml`](opencti-endpoint-ioc-rules.xml) | Wazuh local rules — IOC-correlated detections (FIM, vuln, auth, DNS, firewall, web-log) |
| 12 | [`phase4-ossec-conf.md`](phase4-ossec-conf.md) | Ossec Conf: the `<integration>` block wiring `custom-opencti` into `ossec.conf`, plus manager restart |

Screenshots referenced by the markdown files above live in [`ss/`](ss) (`ss/1.png` – `ss/9.png`).

How the alert → sighting flow works

Whenever a Wazuh alert matches one of the IOC-correlation rules in opencti-endpoint-ioc-rules.xml, the manager fires the custom-opencti integration (wired up in phase4-ossec-conf.md's <integration> block), which runs custom-opencti.py against that alert. The script extracts the IOC (IP, domain, URL, or hash) from the alert, queries it against OpenCTI over the GraphQL API, and — if OpenCTI already knows about that indicator — writes a sighting back to it. In other words: the moment a user sets an alert/watch on an IOC in OpenCTI, any matching activity Wazuh later observes on a monitored endpoint gets reported back as a sighting on that same indicator in OpenCTI, closing the loop between "we're watching for this" and "we saw it happen here."
