## Ossec Conf:

```bash
	nano /var/ossec/etc/ossec.conf
```

```bash
<integration>
  <name>custom-opencti</name>
  <group>syscheck_file,syscheck_entry_added,syscheck_entry_modified,syscheck_registry,ids,osquery,osquery_file,audit_command,auditd,vulnerability-detector,dns,dns_log,unbound,dnsmasq,named,bind,windows_dns,web_log,web-log,apache,nginx,iis,firewall,opnsense,pfsense,fw_drop,fw_permit,fw_pass,authentication_success,authentication_failed,authentication_failures,sshd,pam,journald,syslog,authentication</group>
  <alert_format>json</alert_format>
  <api_key>flgrn_octi_tkn_...</api_key>
  <hook_url>http://10.234.236.25:8080/graphql</hook_url>
</integration>
```

---

Restart Wazuh-Manager:

```bash
Systemctl restart wazuh-manager
```
