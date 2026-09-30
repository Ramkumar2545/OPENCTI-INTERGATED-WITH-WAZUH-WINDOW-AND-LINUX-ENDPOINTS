# Phase 3: Windows Endpoint Setup — Native OpenCTI Telemetry (No Sysmon)

> 📋 This page covers ONLY what needs to be enabled on the Windows endpoint and Wazuh agent side
> for native OpenCTI enrichment to work. It deliberately does not include the `custom-opencti.py`
> integration script or the `opencti-endpoint-ioc-rules.xml` ruleset — those are documented
> separately. This page is purely: what do I turn on, on the endpoint, so the telemetry exists in
> the first place.

## Scope: what "native" means here

Everything below uses telemetry Windows/PowerShell already ship with — no Sysmon, no third-party
agent. That was a deliberate choice to keep per-endpoint storage/performance overhead low across a
large SOC training fleet.

## 1. PowerShell Script Block Logging (Event 4104)

Catches PowerShell cmdlets, expressions, and download cradles
(`IEX (New-Object Net.WebClient).DownloadString(...)`, `Resolve-DnsName`, `Test-NetConnection`,
etc). Built into PowerShell 5.0+, enabled via a single registry key — no install required.

> ⚠️ Known limitation: Script Block Logging reliably captures actual PowerShell **script**
> (cmdlets, pipelines, expressions) but does **not** reliably capture bare native binary
> invocations like a plain `ping <target>` or `nslookup <target>` typed at the prompt — this was
> confirmed empirically, not assumed. For that, see Section 2 (Event 4688) below.

```powershell
# Run as Administrator
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1 -PropertyType DWord -Force

# Verify it actually took
Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
# Expected output: EnableScriptBlockLogging : 1
```

![New-Item + New-ItemProperty creating the ScriptBlockLogging registry key](phase3-native-telemetry-assets/01-scriptblocklogging-registry.png)

Fleet-wide via GPO instead: `Computer Configuration → Administrative Templates → Windows Components → Windows PowerShell → Turn on PowerShell Script Block Logging`

## 2. Windows Security Event 4688 — Process Creation (native, NOT Sysmon)

This is the one genuinely native way to see command-line arguments passed to bare binaries:
`ping`, `nslookup`, `curl`, `nmap`, `tracert`, `netstat`, `arp`, `route`, `ipconfig`, `wget`, and
similar network/recon tools — the exact case Script Block Logging misses.

> ⚠️ Volume trade-off, stated plainly: this logs **every** process creation on the box, not just
> network tools — same category of telemetry volume as Sysmon Event 1, just without Sysmon's extra
> metadata/driver overhead. Tool-name filtering happens downstream in the integration script, not
> at the Windows audit-policy level. Enable this deliberately, not by default, if endpoint storage
> is a hard constraint.

```powershell
# Run as Administrator
auditpol /set /subcategory:"Process Creation" /success:enable

# Required for the command line itself to actually populate — without this,
# 4688 fires but CommandLine is empty and nothing useful can be extracted
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -PropertyType DWord -Force

# Verify
auditpol /get /subcategory:"Process Creation"
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
```

![auditpol /set /subcategory:"Process Creation" /success:enable — command executed successfully](phase3-native-telemetry-assets/02-auditpol-process-creation-enable.png)

![New-ItemProperty setting ProcessCreationIncludeCmdLine_Enabled = 1](phase3-native-telemetry-assets/03-processcreationincludecmdline-registry.png)

## 3. Windows Logon Auditing (Events 4624 / 4625)

Captures successful/failed logon source IPs. Usually enabled by default on Windows Server, but
confirm rather than assume:

```powershell
auditpol /get /subcategory:"Logon"
auditpol /get /subcategory:"Logoff"

# If not enabled:
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
```

## 4. Wazuh agent configuration — required `<localfile>` blocks

Edit `C:\Program Files (x86)\ossec-agent\ossec.conf` and confirm these blocks exist inside
`<ossec_config>`:

```xml
<ossec_config>
  <localfile>
    <location>Security</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <localfile>
    <location>Microsoft-Windows-PowerShell/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
</ossec_config>
```

> 🚨 The `Security` channel block covers **both** 4624/4625 (logon) and 4688 (process creation) —
> they're the same Windows event log, so one `<localfile>` block covers all of Section 2 and
> Section 3's telemetry. If your `Security` `<localfile>` has a custom `<query>` filter excluding
> specific Event IDs (some hardened configs exclude noisy IDs like 5145/5156/5447), double-check
> that filter does **not** also accidentally exclude 4688 or 4624/4625.

Restart the agent after any config change:

```powershell
Restart-Service -Name wazuh
Get-Service -Name wazuh   # confirm Status = Running
```

## 5. Verification checklist

| Check | Command | Expected |
|---|---|---|
| Script Block Logging registry key set | `Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"` | `EnableScriptBlockLogging : 1` |
| 4104 events actually generating | `Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -MaxEvents 20 \| Where-Object {$_.Id -eq 4104}` | Events returned |
| Process Creation auditing on | `auditpol /get /subcategory:"Process Creation"` | Success auditing enabled |
| Command-line inclusion registry key set | `Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"` | `ProcessCreationIncludeCmdLine_Enabled : 1` |
| Logon auditing on | `auditpol /get /subcategory:"Logon"` | Success and Failure enabled |
| Agent watching PowerShell channel | `Select-String -Path "C:\Program Files (x86)\ossec-agent\ossec.conf" -Pattern "Microsoft-Windows-PowerShell"` | Match found |
| Agent service running | `Get-Service -Name wazuh` | Status = Running |

![auditpol /get + Get-ItemProperty confirming Process Creation auditing and the CmdLine registry key](phase3-native-telemetry-assets/04-verification-auditpol-get.png)

## What this page deliberately does NOT cover

- `custom-opencti.py` (the integration script that reads this telemetry and queries OpenCTI) — separate documentation
- `opencti-endpoint-ioc-rules.xml` (the Wazuh correlation ruleset) — separate documentation
- OPNsense/Unbound → Wazuh log forwarding — separate, not-yet-started project
- macOS endpoint setup — separate page, distinct telemetry sources (Unified Logging, not Windows Event Log)
