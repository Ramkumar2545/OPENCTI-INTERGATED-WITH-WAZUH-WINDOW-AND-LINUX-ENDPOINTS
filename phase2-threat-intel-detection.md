# Phase 2: Building Threat-Intel-Driven Detection with Wazuh and OpenCTI

## Before integrating custom-opencti.py — set up OpenCTI-side access

- Click the profile icon (top right) → **Profile** → scroll to the **API Access** section — this is where the token lives.

ss/1.png

- Under **API Access**, click **Generate Token** to create a new token for this integration, rather than reusing your personal login session for a script.
- Give it a clear **Name** (e.g. `wazuh-opencti-integration`) so it's identifiable later in the token table alongside any others (like your `Base token`).
- Set **Expires At** to **Unlimited** for this one — it's a production automation, not a one-off test, so you don't want the script silently failing when a short-lived token expires mid-run.
- Copy the token immediately (it's masked afterward, e.g. `***eb99`) and store it in your script's env var / secrets file — never hardcode it in custom-opencti.py.
- Note the **OpenCTI URL** (server IP + port) alongside the token — the script needs both to authenticate against the GraphQL API.

  ![API Access panel — OpenCTI version, API key, required headers](phase2-assets/02-api-access.png)

**Open the firewall path between Wazuh and OpenCTI**

- If Wazuh and OpenCTI are on different hosts, make sure the firewall on the OpenCTI side allows inbound traffic from the Wazuh host's IP on that port.
- Also check the Wazuh side's outbound rules aren't blocking the connection.
- Enable/verify this before touching tokens — no point generating credentials if the network path is closed.

```bash
ufw allow 8080/tcp                       --noted please enable this on wazuh server machines
```

**3. Verify OpenCTI is reachable and healthy — before adding any keys**

Run a quick version check from the Wazuh host (or wherever the script will run) to confirm both connectivity and that you're hitting the right OpenCTI instance:

```bash
curl -X POST \
  -H "Authorization: Bearer flgrn_octi_tkn_..." \
  -H "Content-Type: application/json" \
  http://192.168.1.105:8080/graphql \
  -d '{"query": "{ about { version } }"}'
```

  ![Successful version check from the Wazuh host terminal](phase2-assets/03-curl-test-result.png)
