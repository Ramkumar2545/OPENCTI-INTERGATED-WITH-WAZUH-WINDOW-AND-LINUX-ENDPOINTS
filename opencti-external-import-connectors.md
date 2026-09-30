# OpenCTI External-Import Connectors — AlienVault OTX, AbuseIPDB, MalwareBazaar, ThreatFox

Source repo: [https://github.com/OpenCTI-Platform/connectors/tree/master/external-import](https://github.com/OpenCTI-Platform/connectors/tree/master/external-import)

## The common pattern (every connector's docker-compose.yml)

Every external-import connector shares four core fields you must change before it will connect to your platform:

- **OPENCTI_URL** — your OpenCTI server address with the port number, e.g. `http://<your-server-ip>:8080` (or the internal Docker hostname if the connector runs in the same stack).
- **OPENCTI_TOKEN** — the token of the OpenCTI user this connector runs as. Best practice is a dedicated user in the "Connectors" group per connector, not the admin token, so each connector gets its own token.
- **CONNECTOR_ID** — a unique UUIDv4 you generate for that connector instance (one UUID per connector, never reused).
- **\<PROVIDER\>_API_KEY** — the API key issued by the external threat-intel source itself (AlienVault, AbuseIPDB, MalwareBazaar). This is separate from the OpenCTI token.

Optional but worth setting on all of them: `CONNECTOR_NAME`, `CONNECTOR_SCOPE`, `CONNECTOR_LOG_LEVEL`, `CONNECTOR_DURATION_PERIOD` (ISO 8601, e.g. `PT30M` = every 30 minutes).

---

## 1. AlienVault OTX

The AlienVault OTX connector imports threat intelligence "Pulses" from AlienVault's Open Threat Exchange (OTX) DirectConnect API into OpenCTI, converting them into STIX 2.1 bundles including reports, indicators, observables, threat actors, malware, vulnerabilities, and attack patterns.

Points to change in `docker-compose.yml`:

- `OPENCTI_URL` → your server IP:port
- `OPENCTI_TOKEN` → connector's OpenCTI user token
- `CONNECTOR_ID` → new UUIDv4
- `ALIENVAULT_API_KEY` — your OTX API key
- `ALIENVAULT_BASE_URL` (defaults to `https://otx.alienvault.com`)
- `ALIENVAULT_PULSE_START_TIMESTAMP` — ISO 8601 UTC date to start pulling pulses from (be careful, an early date can pull a huge volume)
- `ALIENVAULT_REPORT_TYPE` and `ALIENVAULT_REPORT_STATUS` for how imported reports are tagged
- `ALIENVAULT_GUESS_MALWARE` — whether to guess malware from tags

Get the API key by signing up on otx.alienvault.com and copying it from your account page.

---

## 2. AbuseIPDB (IP Blacklist)

Points to change:

- `OPENCTI_URL`, `OPENCTI_TOKEN`, `CONNECTOR_ID` — same as above
- `ABUSEIPDB_API_KEY` — required
- `ABUSEIPDB_SCORE` — confidence score threshold (default 75)
- `ABUSEIPDB_TLP_LEVEL` — TLP marking applied to imported data
- Optional filters: `ABUSEIPDB_IPVERSION`, `ABUSEIPDB_LIMIT`, `ABUSEIPDB_EXCEPT_COUNTRY`, `ABUSEIPDB_ONLY_COUNTRY`, `ABUSEIPDB_CREATE_INDICATOR`
- Runs automatically on the interval set by `CONNECTOR_DURATION_PERIOD` (default `PT12H`)

Get the API key from your AbuseIPDB account under API settings.

---

## 3. MalwareBazaar

Points to change:

- `OPENCTI_URL`, `OPENCTI_TOKEN`, `CONNECTOR_ID` — same as above
- `MALWAREBAZAAR_API_KEY` and `MALWAREBAZAAR_API_BASE_URL` (defaults to `https://mb-api.abuse.ch/api/v1/`)
- `MALWAREBAZAAR_TLP_LEVEL` and `MALWAREBAZAAR_X_OPENCTI_SCORE`
- `MALWAREBAZAAR_INCLUDE_TAGS` — only import samples matching these tags (e.g. exe, dll, docm, docx, xls)
- `MALWAREBAZAAR_INCLUDE_REPORTERS` and `MALWAREBAZAAR_LABELS` for filtering/labeling
- Imports recent samples as File observables with MD5/SHA-1/SHA-256 hashes, related to the associated malware

Free key issued instantly at bazaar.abuse.ch — no approval wait.

---

## 4. ThreatFox

- Same `OPENCTI_URL`, `OPENCTI_TOKEN`, `CONNECTOR_ID` pattern.
- No API key required — ThreatFox's feed is open, so there's no `THREATFOX_API_KEY` field to fill in like the other three.

---

## Deployment steps (Portainer / Docker)

1. Open the connector's folder on GitHub (e.g. `external-import/alienvault`) and copy its `docker-compose.yml`.
2. In Portainer, open your OpenCTI stack editor (or edit your local `docker-compose.yml`).
3. Paste the connector block in as a new service, keeping YAML indentation consistent with the rest of the file.
4. Replace `OPENCTI_URL`, `OPENCTI_TOKEN`, `CONNECTOR_ID`, and the provider API key.
5. Redeploy the stack, then check **Data > Connectors** in the OpenCTI UI to confirm the connector shows "Active" and starts producing work.
