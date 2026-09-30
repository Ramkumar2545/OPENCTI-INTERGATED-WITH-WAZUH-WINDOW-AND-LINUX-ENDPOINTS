## Ignore Rules: Windows

```bash
<!-- ============================================================
     FIM IGNORE / SUPPRESSION RULES
     File: /var/ossec/etc/rules/local-rules.xml
     Copyright Ramkumar 2026
     ============================================================ -->

<group name="syscheck,">

  <!-- ── 1. Browser temp files in user folders ─────────────── -->
  <rule id="100600" level="0">
    <if_sid>550,553,554</if_sid>
    <field name="file" type="pcre2">(?i)\\(Downloads|Desktop|Documents)\\.*(\.(tmp|crdownload|partial)$|Unconfirmed|unconf~1\.crd$)</field>
    <description>Ignore FIM: browser temp files in user folders</description>
  </rule>

  <!-- ── 2. AppData Local Temp ──────────────────────────────── -->
  <rule id="100601" level="0">
    <if_sid>550,553,554</if_sid>
    <field name="file" type="pcre2">(?i)\\AppData\\Local\\Temp\\</field>
    <description>Ignore FIM: AppData Local Temp</description>
  </rule>

  <!-- ── 3. Windows INetCache (browser cache) ──────────────── -->
  <rule id="100602" level="0">
    <if_sid>550,553,554</if_sid>
    <field name="file" type="pcre2">(?i)\\AppData\\Local\\Microsoft\\Windows\\INetCache\\</field>
    <description>Ignore FIM: Windows INetCache browser cache</description>
  </rule>

  <!-- ── 4. Windows SoftwareDistribution (Windows Update) ──── -->
  <rule id="100603" level="0">
    <if_sid>550,553,554</if_sid>
    <field name="file" type="pcre2">(?i)\\Windows\\SoftwareDistribution\\</field>
    <description>Ignore FIM: Windows Update SoftwareDistribution</description>
  </rule>

  <!-- ── 5. Windows Temp ────────────────────────────────────── -->
  <rule id="100604" level="0">
    <if_sid>550,553,554</if_sid>
    <field name="file" type="pcre2">(?i)\\Windows\\Temp\\</field>
    <description>Ignore FIM: Windows Temp folder</description>
  </rule>

  <!-- ── 6. Startup folder desktop.ini (noisy) ─────────────── -->
  <rule id="100605" level="0">
    <if_sid>550,553,554</if_sid>
    <field name="file" type="pcre2">(?i)\\Start Menu\\Programs\\Startup\\desktop\.ini$</field>
    <description>Ignore FIM: Startup folder desktop.ini noise</description>
  </rule>

  <!-- ── 7. AppData Roaming noisy files (non-exe) ──────────── -->
  <rule id="100606" level="0">
    <if_sid>550,553,554</if_sid>
    <field name="file" type="pcre2">(?i)\\AppData\\Roaming\\.*\.(log|json|db|sqlite|cache|lock|ldb|tmp)$</field>
    <description>Ignore FIM: AppData Roaming non-suspicious file types</description>
  </rule>

  <!-- ── 8. ProgramData noisy logs/cache (non-exe) ─────────── -->
  <rule id="100607" level="0">
    <if_sid>550,553,554</if_sid>
    <field name="file" type="pcre2">(?i)\\ProgramData\\.*\.(log|tmp|cache|lock|etl)$</field>
    <description>Ignore FIM: ProgramData non-suspicious temp/log files</description>
  </rule>

  <!-- ── 9. Windows prefetch files (high noise, low value) ──── -->
  <rule id="100608" level="0">
    <if_sid>550,553,554</if_sid>
    <field name="file" type="pcre2">(?i)\\Windows\\Prefetch\\.*\.pf$</field>
    <description>Ignore FIM: Windows Prefetch .pf files</description>
  </rule>

  <!-- ── 10. Windows Event Logs rotating (high noise) ─────── -->
  <rule id="100609" level="0">
    <if_sid>550,553,554</if_sid>
    <field name="file" type="pcre2">(?i)\\Windows\\System32\\winevt\\Logs\\.*\.evtx$</field>
    <description>Ignore FIM: Windows Event Log .evtx rotation</description>
  </rule>

  <!-- ── 11. Wazuh agent self-changes (prevent loop) ───────── -->
  <rule id="100610" level="0">
    <if_sid>550,553,554</if_sid>
    <field name="file" type="pcre2">(?i)\\ossec-agent\\(queue|logs|tmp)\\</field>
    <description>Ignore FIM: Wazuh agent internal queue/log changes</description>
  </rule>

  <!-- ── 12. Microsoft Edge / Chrome update temp files ─────── -->
  <rule id="100611" level="0">
    <if_sid>550,553,554</if_sid>
    <field name="file" type="pcre2">(?i)\\(Google\\Chrome|Microsoft\\Edge)\\Update\\.*\.(tmp|crx|packed)$</field>
    <description>Ignore FIM: Browser auto-update temp files</description>
  </rule>

  <!-- ── 13. Recycle Bin desktop.ini noise ─────────────────── -->
  <rule id="100612" level="0">
    <if_sid>550,553,554</if_sid>
    <field name="file" type="pcre2">(?i)\\\$Recycle\.Bin\\.*desktop\.ini$</field>
    <description>Ignore FIM: Recycle Bin desktop.ini</description>
  </rule>

</group>

<!-- ============================================================
     PROCESS CREATION IGNORE / SUPPRESSION RULES
     Children of rule 100691 ("Windows: Process created -
     $(win.eventdata.newProcessName)") in opencti-endpoint-ioc-
     rules.xml. Same benign-noise-suppression pattern as the FIM
     block above, applied to Windows Security 4688 process creation.
     ============================================================ -->

<group name="windows,process_creation,noise_suppression,">

  <!-- ── 14. Benign Windows system UI/session helper processes ──
       Create constantly under any interactive Windows session.
       No persistence mechanism, no meaningful history as LOLBins,
       no network behavior of note - safe to fully suppress the
       same way the FIM noise above is.
  -->
  <rule id="100620" level="0">
    <if_sid>100691</if_sid>
    <field name="win.eventdata.newProcessName" type="pcre2">(?i)\\(smartscreen|SecurityHealthHost|taskhostw|conhost)\.exe$</field>
    <description>Ignore: benign Windows system process creation (UI/session helpers)</description>
  </rule>

  <!-- ── 15. rundll32.exe / auditpol.exe — READ BEFORE DEPLOYING ──
       CAUTION: both are legitimate most of the time, but both are
       also commonly abused:
         - rundll32.exe: classic LOLBin for DLL side-loading and
           fileless payload execution.
         - auditpol.exe: changing audit policy is the exact
           mechanism behind T1562.002 (Impair Defenses: Disable
           Windows Event Logging) - attackers run this to blind
           logging right before an attack.
       Suppressing these at level 0 means losing visibility into
       both techniques entirely, not just noise reduction. Included
       here because they matched the noise in the dashboard, but
       consider either removing this rule, or scoping it further
       (e.g. requiring a trusted parent process) instead of a blanket
       ignore, before deploying to production.
  -->
  <rule id="100621" level="0">
    <if_sid>100691</if_sid>
    <field name="win.eventdata.newProcessName" type="pcre2">(?i)\\(rundll32|auditpol)\.exe$</field>
    <description>Ignore: rundll32/auditpol process creation (see caution comment - LOLBin/log-tampering risk)</description>
  </rule>

</group>
```
