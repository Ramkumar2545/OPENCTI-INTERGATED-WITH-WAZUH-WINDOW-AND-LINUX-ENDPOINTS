#!/usr/bin/env python3
# custom-opencti.py — native-fields edition (v2.3)
# Dynamic Agent Sighting (No Wazuh Ignoring)
# Author: Ram Kumar G (IT Fortress SOC) (c) 2026

import sys
import os
import json
import time
import re
import ipaddress
import traceback
import fcntl
import sqlite3
import math
from collections import Counter
from datetime import datetime
from socket import socket, AF_UNIX, SOCK_DGRAM

import requests
from requests.exceptions import RequestException, ConnectionError as RequestsConnectionError

# ── Tunables ──────────────────────────────────────────────────
max_iocs_per_alert = 15
MIN_INDICATOR_CONFIDENCE = 40

# FIX (merging 101305/101306 duplicate alerts): this script had NO
# de-duplication at all. One `ping <target>` fires TWO independent native
# events (PowerShell 4104 AND Security 4688 for PING.EXE) within
# milliseconds of each other — each becomes its own Wazuh alert, each
# independently queries OpenCTI, and each independently writes a SEPARATE
# sighting for what is really one real-world action. That's real data
# pollution in OpenCTI (two sighting records for one event), not just
# dashboard noise. This cache throttles the OpenCTI query + sighting
# write-back (not the underlying Wazuh alert itself — 101305/101306
# still both fire in Wazuh as corroborating telemetry, which is useful
# for an analyst) to once per (agent, ioc_type, ioc_value) within this
# window. Disk-backed so it works across separate script invocations
# (Wazuh spawns a fresh process per alert) and fcntl-locked for safety
# when the manager dispatches multiple alerts to the integration in
# quick succession.
CACHE_TTL_SECONDS = 120
cache_file = None  # set below, once `pwd` is defined


def _load_cache():
    if not CACHE_TTL_SECONDS:
        return {}
    try:
        with open(cache_file, "r") as f:
            fcntl.flock(f, fcntl.LOCK_SH)
            try:
                data = json.load(f)
            finally:
                fcntl.flock(f, fcntl.LOCK_UN)
            return data if isinstance(data, dict) else {}
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}


def _save_cache(cache):
    if not CACHE_TTL_SECONDS:
        return
    try:
        cache_dir = os.path.dirname(cache_file)
        os.makedirs(cache_dir, exist_ok=True)
        with open(cache_file, "a+") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            try:
                f.seek(0)
                try:
                    on_disk = json.load(f)
                    if isinstance(on_disk, dict):
                        on_disk.update(cache)
                        cache = on_disk
                except json.JSONDecodeError:
                    pass
                f.seek(0)
                f.truncate()
                json.dump(cache, f)
            finally:
                fcntl.flock(f, fcntl.LOCK_UN)
    except OSError:
        pass


def _clean_cache(cache):
    now = time.time()
    return {k: v for k, v in cache.items() if now - v < CACHE_TTL_SECONDS}


def _cache_key(agent_id, ioc_type, ioc_value):
    return f"{agent_id}|{ioc_type}|{ioc_value.lower()}"
HTTP_MAX_ATTEMPTS = 3
HTTP_BACKOFF_SECONDS = (1, 3)
SIGHTING_DEFAULT_CONFIDENCE = 50

# ADD-ON (no OpenCTI match required): catches domains/IPs/URLs that
# OpenCTI has NO indicator for yet — fresh DGA infra, brand-new C2,
# first-seen infrastructure. Called ONLY from the "neither indicator
# nor observable matched" gap in query_opencti() — see below. No CDB
# list (every list here is a plain Python set/regex in this file), no
# automation-platform call, no outbound network request of any kind —
# zero latency added to the per-IOC loop.
LOCAL_HEURISTICS_ENABLED = True
DGA_SCORE_THRESHOLD = 70

SUSPICIOUS_TLDS = {
    "tk", "top", "xyz", "club", "gq", "ml", "cf", "ga", "work", "click",
    "link", "loan", "win", "bid", "men", "party", "review", "trade",
    "date", "download", "stream", "icu", "cam", "cyou", "sbs", "cn",
}
DYNAMIC_DNS_PROVIDERS = {
    "duckdns.org", "no-ip.org", "no-ip.com", "no-ip.biz", "ngrok.io",
    "ngrok-free.app", "dynu.com", "dynu.net", "hopto.org", "zapto.org",
    "sytes.net", "myftp.org", "myftp.biz", "servehttp.com", "serveftp.com",
    "trycloudflare.com", "loca.lt", "localtunnel.me",
}
_punycode_re = re.compile(r"xn--", re.IGNORECASE)
_long_subdomain_re = re.compile(r"^[a-z0-9]{40,}\.", re.IGNORECASE)
_raw_ip_url_re = re.compile(r"https?://(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::\d+)?(/|$)")

debug_enabled = False
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
cache_file = f"{pwd}/var/run/opencti_ioc_cache.json"
local_state_db = f"{pwd}/var/run/opencti_local_ioc_state.db"
url = ""

log_file = f"{pwd}/logs/integrations.log"
socket_addr = f"{pwd}/queue/sockets/queue"

_agent_identities = {}

regex_cve = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
regex_url = re.compile(r"https?://[^\s'\"<>]+", re.IGNORECASE)
regex_domain = re.compile(r"\b([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)\b")
regex_pure_ipv4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
regex_ipv4_loose = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")
regex_ipv6_loose = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b")
regex_sha256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
regex_sha1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
regex_md5 = re.compile(r"\b[a-fA-F0-9]{32}\b")

LOCAL_IP_LITERALS = {"127.0.0.1", "::1", "-", "", "0.0.0.0", "::"}

AUTH_GROUPS = {
    "authentication_success", "authentication_failed", "authentication_failures",
    "sshd", "pam", "journald", "syslog", "authentication",
}
WEB_LOG_GROUPS = {"web_log", "web-log", "apache", "nginx", "iis"}
FIM_REGISTRY_GROUPS = {"syscheck_registry"}
VULN_GROUPS = {"vulnerability-detector", "vulnerability"}
DNS_LOG_GROUPS = {"dns", "dns_log", "unbound", "dnsmasq", "named", "bind", "windows_dns"}
FIREWALL_GROUPS = {"firewall", "opnsense", "pfsense", "fw_drop", "fw_permit", "fw_pass"}

POWERSHELL_CHANNEL = "Microsoft-Windows-PowerShell/Operational"
POWERSHELL_SCRIPTBLOCK_EVENT_ID = "4104"
WINDOWS_PROCESS_CREATION_EVENT_ID = "4688"

NETWORK_TOOL_BINARIES = {
    "ping.exe", "ping", "nslookup.exe", "nslookup", "tracert.exe", "tracert",
    "arp.exe", "arp", "netstat.exe", "netstat", "ipconfig.exe", "ipconfig",
    "route.exe", "route", "curl.exe", "curl", "wget.exe", "wget",
    "powershell.exe", "powershell", "pwsh.exe", "pwsh",
    "ping6", "dig", "host", "traceroute", "tracepath", "ss", "ip",
    "ifconfig", "iptables", "nftables", "ufw", "firewalld", "tcpdump",
    "wireshark", "tshark", "nmap", "nc", "netcat", "ncat", "socat",
    "telnet", "ssh", "scp", "rsync", "ftp", "tftp", "tcpflow", "iftop",
    "nethogs", "lsof", "fuser", "tcping", "hping3", "masscan",
    "dnsenum", "dnsrecon", "nikto", "gobuster", "ffuf",
}

NETWORK_TOOL_COMMAND_NAMES = NETWORK_TOOL_BINARIES | {
    "resolve-dnsname", "test-connection", "test-netconnection",
    "clear-dnsclientcache", "get-dnsclientcache", "invoke-webrequest",
    "invoke-restmethod",
}
_network_tool_keyword_re = re.compile(
    r"\b(?:" + "|".join(re.escape(t) for t in sorted(NETWORK_TOOL_COMMAND_NAMES, key=len, reverse=True)) + r")\b",
    re.IGNORECASE,
)

LINUX_AUDITD_BIN_RE = re.compile(
    r"^(?:curl|wget|ping6?|nslookup|dig|host|nmap|nc|netcat|ncat|socat|"
    r"ftp|tftp|scp|ssh|tcpdump|openssl|telnet|"
    r"python[0-9.]*|php[0-9.]*|perl|bash|sh|zsh|ksh)$",
    re.IGNORECASE,
)

_auth_from_host_re = re.compile(r"\bfrom\s+([A-Za-z0-9.-]+)\b")
_FILE_EXTENSIONS = {
    "exe", "dll", "sys", "ocx", "msi", "bat", "cmd", "ps1", "psm1", "psd1",
    "txt", "log", "cfg", "conf", "ini", "json", "xml", "yml", "yaml",
    "zip", "rar", "7z", "dat", "tmp", "py", "sh", "csv", "doc", "docx",
    "xls", "xlsx", "pdf", "jpg", "jpeg", "png", "gif", "bmp", "reg",
    "vbs", "js", "html", "htm", "css",
}


def _looks_like_domain_not_filename(token):
    parts = token.split(".")
    if len(parts) < 2:
        return False
    tld = parts[-1].lower()
    if tld in _FILE_EXTENSIONS:
        return False
    if not re.match(r"^[a-z]{2,24}$", tld):
        return False
    return True


_LOG_SOURCE_PRIORITY = (
    ("fim", lambda groups, alert: "syscheck" in alert),
    ("vulnerability_scan", lambda groups, alert: bool(VULN_GROUPS & groups)),
    ("windows_logon", lambda groups, alert: bool(
        isinstance(alert.get("data", {}).get("win"), dict)
        and (alert["data"]["win"].get("eventdata") or {}).get("ipAddress")
    )),
    ("windows_process_creation", lambda groups, alert: bool(
        isinstance(alert.get("data", {}).get("win"), dict)
        and str((alert["data"]["win"].get("system") or {}).get("eventID", "")) == WINDOWS_PROCESS_CREATION_EVENT_ID
    )),
    ("powershell_script", lambda groups, alert: bool(
        isinstance(alert.get("data", {}).get("win"), dict)
        and (alert["data"]["win"].get("system") or {}).get("channel") == POWERSHELL_CHANNEL
    )),
    ("linux_process_creation", lambda groups, alert: bool(
        (alert.get("data", {}).get("audit") or {}).get("key") == "command_monitor"
    )),
    ("linux_auth", lambda groups, alert: bool(AUTH_GROUPS & groups)),
    ("dns_log", lambda groups, alert: bool(DNS_LOG_GROUPS & groups)),
    ("firewall", lambda groups, alert: bool(FIREWALL_GROUPS & groups)),
    ("web_log", lambda groups, alert: bool(WEB_LOG_GROUPS & groups)),
)


def _classify_log_source(alert):
    groups = set(alert.get("rule", {}).get("groups", []) or [])
    for label, test in _LOG_SOURCE_PRIORITY:
        try:
            if test(groups, alert):
                return label
        except Exception:
            continue
    return None


def debug(msg, do_log=False):
    do_log |= debug_enabled
    if not do_log:
        return
    now = time.strftime("%a %b %d %H:%M:%S %Z %Y")
    try:
        with open(log_file, "a") as f:
            f.write(f"{now}: {msg}\n")
    except OSError:
        pass


def log(msg):
    debug(msg, do_log=True)


def remove_empties(value):
    def empty(v):
        return False if isinstance(v, bool) else not bool(v)

    if isinstance(value, list):
        return [x for x in (remove_empties(x) for x in value) if not empty(x)]
    if isinstance(value, dict):
        return {k: v for (k, v) in ((k, remove_empties(v)) for k, v in value.items()) if not empty(v)}
    return value


def safe_stix_value(value):
    return str(value).replace("\\", "\\\\").replace("'", "\\'")


def _extract_author_name(entity):
    if not isinstance(entity, dict):
        return "Unknown"
    created_by = entity.get("createdBy")
    if isinstance(created_by, dict):
        name = created_by.get("name")
        if name and str(name).strip():
            return str(name).strip()
    return "Unknown"


def indicator_sort_func(x):
    valid_until = x.get("valid_until", "1970-01-01T00:00:00.000Z")
    try:
        expired = datetime.strptime(valid_until, "%Y-%m-%dT%H:%M:%S.%fZ") <= datetime.now()
    except Exception:
        expired = True

    return (
        x.get("revoked", False),
        not x.get("x_opencti_detection", False),
        -int(x.get("x_opencti_score", 0) or 0),
        -int(x.get("confidence", 0) or 0),
        expired
    )


def sort_indicators(indicators):
    return sorted(indicators, key=indicator_sort_func)


def _post_graphql(url, token, body, agent=None, max_attempts=HTTP_MAX_ATTEMPTS, report_errors=True):
    query_headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
        "Accept": "application/json"
    }

    response = None
    last_exc = None
    for attempt in range(1, max_attempts + 1):
        try:
            response = requests.post(url, headers=query_headers, json=body, timeout=20)
            response.raise_for_status()
            last_exc = None
            break
        except (RequestsConnectionError, RequestException) as e:
            last_exc = e
            response = None
            if attempt < max_attempts:
                backoff = HTTP_BACKOFF_SECONDS[min(attempt - 1, len(HTTP_BACKOFF_SECONDS) - 1)]
                debug(f"# GraphQL request attempt {attempt} failed ({e}); retrying in {backoff}s")
                time.sleep(backoff)

    if last_exc is not None or response is None:
        if report_errors:
            if isinstance(last_exc, RequestsConnectionError):
                log(f"Failed to connect to {url} after {max_attempts} attempts")
                send_error_event("Failed to connect to the OpenCTI API", agent)
            else:
                log(f"OpenCTI HTTP error after {max_attempts} attempts: {last_exc}")
                send_error_event(f"OpenCTI HTTP error: {str(last_exc)}", agent)
        return None

    try:
        parsed = response.json()
    except json.decoder.JSONDecodeError:
        log("Failed to parse response from OpenCTI API")
        if report_errors:
            send_error_event("Failed to parse response from OpenCTI API", agent)
        return None

    if parsed.get("errors"):
        log(f"OpenCTI GraphQL errors: {parsed.get('errors')}")
        if report_errors:
            send_error_event("OpenCTI GraphQL returned errors", agent)
        return None

    return parsed


def init_sighting_identity(url, token, agent_name):
    global _agent_identities
    if agent_name in _agent_identities:
        return _agent_identities[agent_name]

    query_body = {
        "query": """
        query SearchSystem($search: String) {
          systems(search: $search) {
            edges {
              node {
                id
                name
              }
            }
          }
        }
        """,
        "variables": {"search": agent_name}
    }
    res = _post_graphql(url, token, query_body, report_errors=False)
    if res and res.get("data") and res["data"].get("systems"):
        for edge in res["data"]["systems"].get("edges", []):
            node = edge.get("node", {})
            if node.get("name", "").strip().lower() == agent_name.strip().lower():
                _agent_identities[agent_name] = node["id"]
                debug(f"# Found existing System entity for agent '{agent_name}': {node['id']}")
                return node["id"]

    create_body = {
        "query": """
        mutation CreateAgentSystem($input: SystemAddInput!) {
          systemAdd(input: $input) {
            id
            name
          }
        }
        """,
        "variables": {
            "input": {
                "name": agent_name,
                "description": f"Wazuh Managed Endpoint Agent: {agent_name}"
            }
        }
    }
    res = _post_graphql(url, token, create_body, report_errors=False)
    if res and res.get("data") and res["data"].get("systemAdd"):
        sys_id = res["data"]["systemAdd"]["id"]
        _agent_identities[agent_name] = sys_id
        debug(f"# Created new System entity for agent '{agent_name}': {sys_id}")
        return sys_id

    fallback_body = {
        "query": """
        mutation CreateAgentOrg($input: OrganizationAddInput!) {
          organizationAdd(input: $input) {
            id
          }
        }
        """,
        "variables": {
            "input": {
                "name": agent_name,
                "description": f"Wazuh Endpoint Agent: {agent_name}"
            }
        }
    }
    res = _post_graphql(url, token, fallback_body, report_errors=False)
    if res and res.get("data") and res["data"].get("organizationAdd"):
        org_id = res["data"]["organizationAdd"]["id"]
        _agent_identities[agent_name] = org_id
        debug(f"# Fallback created Organization entity for agent '{agent_name}': {org_id}")
        return org_id

    debug(f"# Failed to initialize OpenCTI identity for agent '{agent_name}'")
    return None


def create_sighting(url, token, entity_id, first_seen, last_seen, confidence, description, agent_name, agent=None):
    identity_id = init_sighting_identity(url, token, agent_name)
    if not identity_id or not entity_id:
        # FIX: was a silent `return None` — impossible to tell from
        # integrations.log whether the identity lookup/creation failed
        # or the entity_id itself was missing. Now explicit either way.
        log(f"# Sighting skipped: identity_id={identity_id!r} entity_id={entity_id!r} agent='{agent_name}' — "
            f"{'identity lookup/creation failed (check preceding GraphQL/HTTP errors)' if not identity_id else 'entity_id was empty (matched node had no id field)'}")
        return None

    body = {
        "query": """
        mutation CreateWazuhSighting($input: StixSightingRelationshipAddInput!) {
          stixSightingRelationshipAdd(input: $input) {
            id
          }
        }
        """,
        "variables": {
            "input": {
                "fromId": entity_id,
                "toId": identity_id,
                "first_seen": first_seen,
                "last_seen": last_seen,
                "confidence": confidence,
                # FIX: OpenCTI's schema rejected "count" outright —
                # "Expected value ... not to include unknown field 'count'"
                # AND "to include required field 'attribute_count'" in the
                # same error. Confirmed via live GraphQL error, not a guess.
                "attribute_count": 1,
                "description": description,
            }
        }
    }

    log(f"# Attempting sighting write-back: entity={entity_id} identity={identity_id} agent='{agent_name}'")

    # FIX: was max_attempts=1 — a single attempt for something this
    # important is too fragile against a transient network blip. Bumped
    # to 2, still best-effort (report_errors=False so a genuine failure
    # never generates a noisy Wazuh alert on top of the real detection).
    result = _post_graphql(url, token, body, agent=agent, max_attempts=2, report_errors=False)
    if not result:
        # FIX: was debug() — debug() only writes when debug_enabled is
        # True (production default is False), so this failure was
        # completely invisible in integrations.log unless the script was
        # manually re-run with the "debug" argv flag. log() always
        # writes regardless of debug mode. Note: if the failure was a
        # GraphQL schema/validation error (as opposed to a network
        # error), _post_graphql() already logs the raw error text
        # unconditionally — check integrations.log for a preceding
        # "OpenCTI GraphQL errors: ..." line to see the exact reason.
        log(f"# Sighting write-back FAILED for entity {entity_id} (identity={identity_id}, agent='{agent_name}') — see preceding GraphQL/HTTP error above, if any")
        return None

    sighting = (result.get("data") or {}).get("stixSightingRelationshipAdd") or {}
    sighting_id = sighting.get("id")
    if sighting_id:
        # FIX: was debug() — same reasoning, success confirmation should
        # always be traceable too.
        log(f"# Sighting created: {sighting_id} for entity {entity_id} on agent '{agent_name}'")
    else:
        log(f"# Sighting mutation returned no error but also no id — unexpected response shape for entity {entity_id}")
    return sighting_id


def ind_ip_pattern(string):
    ip = ipaddress.ip_address(string)
    if ip.version == 6:
        return f"[ipv6-addr:value = '{safe_stix_value(string)}']"
    return f"[ipv4-addr:value = '{safe_stix_value(string)}']"


def _is_global_ip(value):
    if not value or value in LOCAL_IP_LITERALS:
        return False
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    if ip.is_loopback:
        return False
    return ip.is_global


def _add_ip_ioc(value, add):
    if not _is_global_ip(value):
        return
    ip = ipaddress.ip_address(value)
    add("ipv6" if ip.version == 6 else "ipv4", value)


def _extract_domain_from_url(u):
    try:
        rest = u.split("://", 1)[1]
        host = rest.split("/", 1)[0]
        host = host.split("@")[-1]
        host = host.split(":")[0]
        return host.lower().strip(".") or None
    except Exception:
        return None


def scan_text_for_iocs(text, add, include_domains=False):
    if not text:
        return

    for cve in regex_cve.findall(text):
        add("vulnerability", cve.upper())

    for u in regex_url.findall(text):
        add("url", u.rstrip(".,;)'\""))

    for ip_s in regex_ipv4_loose.findall(text):
        _add_ip_ioc(ip_s, add)

    for ip6_s in regex_ipv6_loose.findall(text):
        _add_ip_ioc(ip6_s, add)

    for h in regex_sha256.findall(text):
        add("sha256", h.lower())
    for h in regex_sha1.findall(text):
        add("sha1", h.lower())
    for h in regex_md5.findall(text):
        add("md5", h.lower())

    if include_domains:
        for dom in regex_domain.findall(text):
            if not regex_pure_ipv4.match(dom) and _looks_like_domain_not_filename(dom):
                add("domain", dom.lower())


def _build_execve_string(execve):
    try:
        keys = sorted(execve.keys(), key=lambda k: int(k[1:]) if k[1:].isdigit() else 0)
        return " ".join(str(execve[k]) for k in keys)
    except Exception:
        return " ".join(str(v) for v in execve.values())


def _extract_linux_auditd_iocs(alert, data, add):
    audit = data.get("audit", {}) or {}
    if not audit or audit.get("key") != "command_monitor":
        return

    execve = audit.get("execve", {}) or {}
    command = audit.get("command", "") or ""
    bin_to_check = execve.get("a0", "") if execve else command
    if not bin_to_check:
        return

    basename = bin_to_check.replace("\\", "/").rsplit("/", 1)[-1]
    if not LINUX_AUDITD_BIN_RE.match(basename):
        return

    if execve:
        cmd_string = _build_execve_string(execve)
        scan_text_for_iocs(cmd_string, add, include_domains=True)
    else:
        full_log = alert.get("full_log", "") or ""
        scan_text_for_iocs(full_log, add, include_domains=True)
        m = re.search(r"proctitle=([0-9A-Fa-f]+)", full_log)
        if m:
            try:
                decoded = bytes.fromhex(m.group(1)).replace(b"\x00", b" ").decode("utf-8", errors="ignore")
                scan_text_for_iocs(decoded, add, include_domains=True)
            except Exception:
                pass


def _shannon_entropy(s):
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def _longest_consonant_run(s):
    vowels = set("aeiou")
    longest = run = 0
    for ch in s:
        if ch.isalpha() and ch not in vowels:
            run += 1
            longest = max(longest, run)
        else:
            run = 0
    return longest


def score_domain(domain):
    """
    Score a domain 0-100 for DGA/randomly-generated likelihood using pure
    string heuristics - no feed, no lookup, no network call. Scores the
    registrable label (the part right before the TLD), which is where
    DGA randomness shows up.
    """
    domain = domain.strip().lower().rstrip(".")
    labels = domain.split(".")
    label = labels[-2] if len(labels) >= 2 else domain

    entropy = _shannon_entropy(label)
    digits = sum(c.isdigit() for c in label)
    hyphens = label.count("-")
    length = len(label)
    consonant_run = _longest_consonant_run(label)
    digit_ratio = digits / length if length else 0

    entropy_component = min(entropy / 4.0, 1.0) * 40
    digit_component = min(digit_ratio * 2, 1.0) * 20
    length_component = min(max(length - 12, 0) / 20, 1.0) * 15
    hyphen_component = min(hyphens / 3, 1.0) * 10
    consonant_component = min(max(consonant_run - 4, 0) / 4, 1.0) * 15

    total = round(entropy_component + digit_component + length_component
                  + hyphen_component + consonant_component)
    return {"score": total, "entropy": round(entropy, 2), "digit_ratio": round(digit_ratio, 2)}


def _local_state_conn():
    os.makedirs(os.path.dirname(local_state_db), exist_ok=True)
    conn = sqlite3.connect(local_state_db)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS seen_indicators ("
        "indicator TEXT NOT NULL, ioc_type TEXT NOT NULL, "
        "first_seen TEXT NOT NULL, hit_count INTEGER NOT NULL DEFAULT 1, "
        "PRIMARY KEY (indicator, ioc_type))"
    )
    return conn


def check_first_seen(indicator, ioc_type):
    """
    Local rarity check: has this domain/IP/URL ever been observed in this
    environment before? Pure SQLite read/write on local disk - no
    external service, no automation platform, no shared state.
    """
    indicator = indicator.strip().lower()
    now = datetime.utcnow().isoformat()
    conn = _local_state_conn()
    try:
        row = conn.execute(
            "SELECT hit_count FROM seen_indicators WHERE indicator=? AND ioc_type=?",
            (indicator, ioc_type)
        ).fetchone()
        if row is None:
            conn.execute(
                "INSERT INTO seen_indicators (indicator, ioc_type, first_seen, hit_count) VALUES (?,?,?,1)",
                (indicator, ioc_type, now)
            )
            conn.commit()
            return True
        conn.execute(
            "UPDATE seen_indicators SET hit_count = hit_count + 1 WHERE indicator=? AND ioc_type=?",
            (indicator, ioc_type)
        )
        conn.commit()
        return False
    finally:
        conn.close()


def check_pattern(indicator, ioc_type):
    """Pure regex/set-membership checks - every list is literal Python
    in this file, not an external CDB list, not fetched, not automation."""
    findings = []
    v = indicator.strip().lower()

    if ioc_type in ("domain", "url"):
        host = v
        if ioc_type == "url":
            m = re.match(r"https?://([^/:]+)", v)
            host = m.group(1) if m else v
        tld = host.rsplit(".", 1)[-1] if "." in host else ""
        if tld in SUSPICIOUS_TLDS:
            findings.append(("suspicious_tld", f"TLD .{tld} is in the high-abuse TLD set"))
        registrable = ".".join(host.split(".")[-2:]) if "." in host else host
        if registrable in DYNAMIC_DNS_PROVIDERS:
            findings.append(("dynamic_dns_provider", f"{registrable} is a free dynamic-DNS/tunneling provider"))
        if _punycode_re.search(host):
            findings.append(("punycode_homograph", "Domain uses punycode (xn--) - possible homograph/typosquat"))
        if _long_subdomain_re.match(host):
            findings.append(("long_subdomain_label", "Very long subdomain label - possible DNS tunneling"))

    if ioc_type == "url":
        m = _raw_ip_url_re.match(v)
        if m:
            findings.append(("raw_ip_url", f"URL points directly at IP {m.group(1)} instead of a domain"))

    return findings


def evaluate_local_heuristic(ioc):
    """
    Called ONLY when OpenCTI found neither an indicator nor an observable
    match for this IOC (see the gap in query_opencti(), right after the
    observable-match block). Returns None if nothing trips, otherwise a
    dict shaped to drop straight into new_alert["opencti"]["local"].

    first_contact alone never returns a hit on its own - a brand-new
    domain is extremely common (CDN, SaaS, normal browsing) and would be
    too noisy. It only rides along as extra context once another check
    has already flagged the indicator.
    """
    if not LOCAL_HEURISTICS_ENABLED:
        return None

    t, v = ioc["type"], ioc["value"]
    if t not in ("domain", "ipv4", "ipv6", "url"):
        return None

    local_type = "ip" if t in ("ipv4", "ipv6") else t
    reasons = []

    if t == "domain":
        dga = score_domain(v)
        if dga["score"] >= DGA_SCORE_THRESHOLD:
            reasons.append((
                "dga_heuristic_score",
                f"score={dga['score']} entropy={dga['entropy']} digit_ratio={dga['digit_ratio']}"
            ))

    reasons.extend(check_pattern(v, t))

    first_contact = check_first_seen(v, local_type)

    if not reasons:
        return None

    check_name, detail = reasons[0]
    return {
        "check": check_name,
        "detail": detail,
        "first_contact": first_contact,
        "all_reasons": [{"check": c, "detail": d} for c, d in reasons],
    }


def extract_iocs(alert):
    iocs = []
    groups = set(alert.get("rule", {}).get("groups", []) or [])
    data = alert.get("data", {}) or {}

    def add(t, v):
        if v is not None and isinstance(v, str) and v.strip():
            iocs.append({"type": t, "value": v.strip()})

    if "syscheck" in alert:
        sc = alert["syscheck"] or {}
        if FIM_REGISTRY_GROUPS & groups or sc.get("syscheck_registry"):
            reg_path = sc.get("path")
            if reg_path:
                add("windows-registry-key", reg_path)
        else:
            path = sc.get("path")
            if path:
                add("filename", path)
        add("sha256", sc.get("sha256_after"))
        add("sha1", sc.get("sha1_after"))
        add("md5", sc.get("md5_after"))

    if VULN_GROUPS & groups:
        vuln = data.get("vulnerability", {})
        if isinstance(vuln, dict):
            for v in vuln.values():
                if isinstance(v, str):
                    for cve in regex_cve.findall(v):
                        add("vulnerability", cve.upper())
        scan_text_for_iocs(alert.get("full_log", "") or "", add)

    if AUTH_GROUPS & groups:
        _add_ip_ioc(data.get("srcip"), add)
        _add_ip_ioc(data.get("dstip"), add)
        full_log_auth = alert.get("full_log", "") or ""
        for m in _auth_from_host_re.finditer(full_log_auth):
            token = m.group(1)
            if regex_pure_ipv4.match(token):
                _add_ip_ioc(token, add)
            elif _looks_like_domain_not_filename(token):
                add("domain", token.lower())
        scan_text_for_iocs(full_log_auth, add)

    win_eventdata = {}
    if isinstance(data.get("win"), dict):
        win_eventdata = data["win"].get("eventdata", {}) or {}
    if win_eventdata.get("ipAddress"):
        _add_ip_ioc(win_eventdata.get("ipAddress"), add)
        win_system_early = (data.get("win", {}) or {}).get("system", {}) or {}
        scan_text_for_iocs(win_system_early.get("message", "") or "", add)

    win_system = {}
    if isinstance(data.get("win"), dict):
        win_system = data["win"].get("system", {}) or {}

    if str(win_system.get("eventID", "")) == WINDOWS_PROCESS_CREATION_EVENT_ID:
        cmdline = win_eventdata.get("commandLine") or win_eventdata.get("CommandLine") or ""
        new_proc = (win_eventdata.get("newProcessName") or win_eventdata.get("NewProcessName") or "").lower()
        proc_basename = new_proc.replace("\\", "/").rsplit("/", 1)[-1]
        if cmdline and proc_basename in NETWORK_TOOL_BINARIES:
            scan_text_for_iocs(cmdline, add, include_domains=True)

    if DNS_LOG_GROUPS & groups:
        qname = (
            data.get("query") or data.get("queryName") or data.get("qname")
            or data.get("question") or data.get("hostname")
        )
        if qname:
            d = str(qname).strip().lower().strip(".")
            if d and not regex_pure_ipv4.match(d):
                add("domain", d)

        for k in ("answer", "answers", "response", "rdata", "resolved_ip"):
            v = data.get(k)
            if isinstance(v, str):
                for ip_s in regex_ipv4_loose.findall(v):
                    _add_ip_ioc(ip_s, add)
            elif isinstance(v, list):
                for item in v:
                    if isinstance(item, str):
                        _add_ip_ioc(item, add)

    _extract_linux_auditd_iocs(alert, data, add)

    if FIREWALL_GROUPS & groups:
        _add_ip_ioc(data.get("dstip") or data.get("dst_ip"), add)
        _add_ip_ioc(data.get("srcip") or data.get("src_ip"), add)
        fw_host = data.get("hostname") or data.get("sni") or data.get("domain")
        if fw_host:
            d = str(fw_host).strip().lower().strip(".")
            if d and not regex_pure_ipv4.match(d) and _looks_like_domain_not_filename(d):
                add("domain", d)

    if (
        win_system.get("channel") == POWERSHELL_CHANNEL
        and str(win_system.get("eventID", "")) == POWERSHELL_SCRIPTBLOCK_EVENT_ID
    ):
        script_text = win_eventdata.get("scriptBlockText") or win_eventdata.get("ScriptBlockText", "") or ""
        has_tool_keyword = bool(_network_tool_keyword_re.search(script_text))
        scan_text_for_iocs(script_text, add, include_domains=has_tool_keyword)

    if WEB_LOG_GROUPS & groups:
        url_val = data.get("url") or data.get("uri") or data.get("request")
        if url_val:
            add("url", url_val)
            dom = _extract_domain_from_url(url_val)
            if dom and not regex_pure_ipv4.match(dom):
                add("domain", dom)

        scan_text_for_iocs(alert.get("full_log", "") or "", add)

        ua = data.get("user_agent") or data.get("http_user_agent") or data.get("UserAgent")
        if ua:
            add("user-agent", ua)

        host_val = data.get("hostname") or data.get("domain") or data.get("vhost")
        if host_val:
            d = host_val.strip().lower().strip(".")
            if d and not regex_pure_ipv4.match(d):
                add("domain", d)

    seen = set()
    out = []
    for x in iocs:
        norm_val = x["value"].strip()
        key = (x["type"], norm_val.lower() if x["type"] in ("domain", "url", "user-agent", "vulnerability") else norm_val)
        if key not in seen:
            seen.add(key)
            out.append({"type": x["type"], "value": norm_val})

    return out[:max_iocs_per_alert]


def add_context(source_event, event):
    event.setdefault("opencti", {})
    event["opencti"].setdefault("source", {})
    src = event["opencti"]["source"]

    src["alert_id"] = source_event.get("id")
    src["rule_id"] = source_event.get("rule", {}).get("id")

    log_source = _classify_log_source(source_event)
    if log_source:
        src["log_source"] = log_source

    if source_event.get("location"):
        src["location"] = source_event.get("location")
    if source_event.get("full_log"):
        src["full_log"] = source_event.get("full_log")

    data = source_event.get("data", {}) or {}

    if "syscheck" in source_event:
        sc = source_event["syscheck"] or {}
        src["file"] = sc.get("path")
        src["sha256_after"] = sc.get("sha256_after")
        src["sha1_after"] = sc.get("sha1_after")
        src["md5_after"] = sc.get("md5_after")

    if data.get("srcip"):
        src["srcip"] = data.get("srcip")
    if data.get("dstip"):
        src["dstip"] = data.get("dstip")

    win_eventdata = {}
    if isinstance(data.get("win"), dict):
        win_eventdata = data["win"].get("eventdata", {}) or {}
    if win_eventdata.get("ipAddress"):
        src["ipAddress"] = win_eventdata.get("ipAddress")

    if data.get("url"):
        src["url"] = data.get("url")

    ua = data.get("user_agent") or data.get("http_user_agent") or data.get("UserAgent")
    if ua:
        src["user_agent"] = ua

    dns_query = (
        data.get("query") or data.get("queryName") or data.get("qname") or data.get("question")
    )
    if dns_query and log_source == "dns_log":
        src["dns_query"] = dns_query

    if log_source == "firewall":
        fw_host = data.get("hostname") or data.get("sni") or data.get("domain")
        if fw_host:
            src["fw_hostname"] = fw_host

    if log_source == "linux_auth":
        full_log_ctx = source_event.get("full_log", "") or ""
        m = _auth_from_host_re.search(full_log_ctx)
        if m and not regex_pure_ipv4.match(m.group(1)):
            src["resolved_hostname"] = m.group(1)

    if log_source == "powershell_script":
        script_text = win_eventdata.get("scriptBlockText") or win_eventdata.get("ScriptBlockText", "") or ""
        if script_text:
            src["script_snippet"] = script_text[:300]

    if log_source == "windows_process_creation":
        cmdline = win_eventdata.get("commandLine") or win_eventdata.get("CommandLine") or ""
        new_proc = win_eventdata.get("newProcessName") or win_eventdata.get("NewProcessName") or ""
        if cmdline:
            src["command_line"] = cmdline[:300]
        if new_proc:
            src["process_name"] = new_proc

    if log_source == "linux_process_creation":
        audit_ctx = data.get("audit", {}) or {}
        execve_ctx = audit_ctx.get("execve", {}) or {}
        if execve_ctx:
            src["command_line"] = _build_execve_string(execve_ctx)[:300]
        elif audit_ctx.get("command"):
            src["command_line"] = str(audit_ctx.get("command"))[:300]
        if audit_ctx.get("exe"):
            src["process_name"] = audit_ctx.get("exe")


def build_opencti_filters(ioc):
    t = ioc["type"]
    v = ioc["value"]

    obs_key = "value"
    obs_values = [v]
    ind_patterns = []
    file_name_values = []

    sv = safe_stix_value(v)

    if t in ("ipv4", "ipv6"):
        ind_patterns = [ind_ip_pattern(v)]
    elif t == "domain":
        ind_patterns = [
            f"[domain-name:value = '{sv}']",
            f"[hostname:value = '{sv}']",
        ]
    elif t == "url":
        ind_patterns = [f"[url:value = '{sv}']"]
    elif t == "user-agent":
        ind_patterns = [f"[user-agent:string_value = '{sv}']"]
    elif t == "windows-registry-key":
        ind_patterns = [f"[windows-registry-key:key = '{sv}']"]
    elif t == "vulnerability":
        ind_patterns = [f"[vulnerability:name = '{sv}']"]
    elif t in ("sha256", "sha1", "md5"):
        alg = {"sha256": "SHA-256", "sha1": "SHA-1", "md5": "MD5"}[t]
        # FIX: was f"hashes.'{alg}'" — the quotes are correct STIX pattern
        # syntax (used below in ind_patterns, a real STIX pattern string)
        # but this obs_key is a plain OpenCTI filter key, not a pattern.
        # Confirmed via live error: "Schema definition named [hashes] is
        # missing mapping for attribute ['MD5']" — the quoted string was
        # being read as a literal attribute name including the quote
        # characters.
        obs_key = f"hashes.{alg}"
        obs_values = [v]
        ind_patterns = [f"[file:hashes.'{alg}' = '{sv}']"]
    elif t == "filename":
        base = os.path.basename(v.replace("\\", "/"))
        val = base or v
        file_name_values = [val]
        obs_values = [val]
        obs_key = "value"
        ind_patterns = []

    return obs_key, obs_values, ind_patterns, file_name_values


def graphql_query_body(obs_filters, obs_filter_groups, ind_var):
    return {
        "query": """
        fragment Object on StixCoreObject {
          id
          entity_type
          createdBy {
            ... on Identity { id name }
            ... on Organization { id name }
            ... on Individual { id name }
          }
        }

        fragment IndShort on Indicator {
          id
          name
          valid_until
          revoked
          confidence
          x_opencti_score
          x_opencti_detection
          pattern_type
          pattern
          ...Object
        }

        query IoCs($obs: FilterGroup, $ind: FilterGroup) {
          indicators(filters: $ind, first: 10) {
            edges { node { ...IndShort } }
          }
          stixCyberObservables(filters: $obs, first: 10) {
            edges {
              node {
                ...Object
                observable_value
                x_opencti_score
                indicators { edges { node { ...IndShort } } }
              }
            }
          }
        }
        """,
        "variables": {
            "obs": {
                "mode": "and",
                "filterGroups": obs_filter_groups,
                "filters": obs_filters
            },
            "ind": ind_var
        }
    }


def send_event(msg, agent=None):
    if not agent or agent.get("id") == "000":
        string = f"1:opencti:{json.dumps(msg)}"
    else:
        string = "1:[{0}] ({1}) {2}->opencti:{3}".format(
            agent.get("id"),
            agent.get("name"),
            agent.get("ip", "any"),
            json.dumps(msg)
        )

    debug("# Event:")
    debug(string)

    sock = socket(AF_UNIX, SOCK_DGRAM)
    sock.connect(socket_addr)
    sock.send(string.encode())
    sock.close()


def send_error_event(msg, agent=None):
    send_event({
        "integration": "opencti",
        "opencti": {
            "error": msg,
            "event_type": "error"
        }
    }, agent)


def _send_now(msg, agent=None):
    """
    FIX (dashboard alert latency): previously every detection was
    appended to a list and only sent to the Wazuh socket after the
    ENTIRE per-alert IOC loop finished — meaning a real match could sit
    unsent while later, unrelated IOCs in the same alert were still being
    queried against OpenCTI (each query + sighting write-back is its own
    blocking HTTP round trip, up to 20s timeout x 3 retries). This sends
    the detection the moment it's found, so the dashboard alert isn't
    gated on anything happening afterward for other IOCs. Same
    try/except shape main() already used for send_event().
    """
    try:
        send_event(remove_empties(msg), agent)
    except Exception as e:
        log(f"Failed to send enrichment event to Wazuh socket: {e}")


def query_opencti(alert, url, token):
    iocs = extract_iocs(alert)
    if not iocs:
        return 0

    log_source_label = _classify_log_source(alert) or "unknown"
    agent = alert.get("agent", {})
    agent_id = agent.get("id", "000")
    agent_name = agent.get("name") or "Wazuh Server"

    # Load + prune the throttle cache once per invocation.
    cache = {}
    if CACHE_TTL_SECONDS:
        cache = _clean_cache(_load_cache())

    # FIX (latency): events are now sent inline via _send_now() the
    # moment each match is found (see below) instead of being batched
    # into a list and sent only after every IOC in the alert has been
    # processed. This counter is kept purely for the debug log line at
    # the end — it no longer gates delivery of anything.
    sent_count = 0

    for ioc in iocs:
        # FIX: skip the OpenCTI query + sighting write-back entirely if
        # this exact (agent, ioc_type, ioc_value) was already processed
        # within CACHE_TTL_SECONDS — this is what actually merges
        # 101305/101306-style duplicate detections down to one sighting
        # per real action, since both fire from the SAME ioc value
        # within milliseconds of each other. The Wazuh alert for
        # whichever event arrives second still shows in the dashboard as
        # corroborating telemetry (100690/100691/100692 passthrough
        # rules still fire) — only the OpenCTI-side work is throttled.
        ck = _cache_key(agent_id, ioc["type"], ioc["value"])
        if CACHE_TTL_SECONDS and ck in cache:
            log(f"# Throttled (already processed within {CACHE_TTL_SECONDS}s): {ioc['type']}={ioc['value']} agent={agent_id}")
            continue

        obs_key, obs_values, ind_filter, file_name_values = build_opencti_filters(ioc)
        debug(f"# Querying OpenCTI for IOC {ioc}")

        obs_filters = [{"key": obs_key, "values": obs_values}]
        obs_filter_groups = []

        if file_name_values:
            obs_filter_groups.append({
                "mode": "or",
                "filters": [
                    {"key": "name", "values": file_name_values},
                    {"key": "x_opencti_additional_names", "values": file_name_values},
                ],
                "filterGroups": []
            })

        ind_var = {
            "mode": "and",
            "filterGroups": [],
            "filters": [{"key": "id", "values": ["__never__"]}]
        }

        if ind_filter:
            ind_var = {
                "mode": "and",
                "filterGroups": [],
                "filters": [
                    {"key": "pattern_type", "values": ["stix"]},
                    {"mode": "or", "key": "pattern", "values": ind_filter}
                ]
            }

        api_json_body = graphql_query_body(obs_filters, obs_filter_groups, ind_var)
        response = _post_graphql(url, token, api_json_body, agent=alert.get("agent"))
        if response is None:
            continue

        # Mark as processed regardless of match outcome — a "no match
        # found" result is just as valid a reason to throttle a repeat
        # query within the window as a real match is.
        if CACHE_TTL_SECONDS:
            cache[ck] = time.time()

        resp_data = response.get("data")
        if not resp_data:
            continue

        indicators_section = resp_data.get("indicators", {})
        observables_section = resp_data.get("stixCyberObservables", {})

        # FIX: was `alert.get("timestamp") or datetime.utcnow()...` — since
        # every real Wazuh alert always HAS a timestamp field, the `or`
        # fallback never actually triggered, and Wazuh's raw format
        # ("...+0530", no colon in the UTC offset) is not valid per
        # GraphQL's DateTime scalar. Confirmed via live error: "DateTime
        # cannot represent an invalid date-time-string 2026-08-07T18:10:05.700+0530".
        # Always construct a known-good UTC "Z"-suffixed string ourselves
        # instead of trusting Wazuh's timestamp formatting.
        sighting_ts = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z")
        indicator_matched = False

        if ind_filter and indicators_section and "edges" in indicators_section:
            valid_inds = [
                e["node"] for e in indicators_section["edges"]
                if e.get("node") and e["node"].get("revoked") is not True
            ]
            if valid_inds:
                indicator_matched = True
                best_ind = sort_indicators(valid_inds)[0]
                author_name = _extract_author_name(best_ind)

                new_alert = {
                    "integration": "opencti",
                    "opencti": {
                        "indicator": best_ind,
                        "author_name": author_name,
                        "createdBy": {"name": author_name},
                        "query_key": obs_key,
                        "query_values": ";".join(obs_values),
                        "ioc_type": ioc["type"],
                        "event_type": "indicator_pattern_match",
                    }
                }
                add_context(alert, new_alert)

                # FIX (latency): send the detection now — don't wait on
                # the sighting write-back below. The dashboard alert no
                # longer depends on this second GraphQL round trip.
                _send_now(new_alert, alert.get("agent"))
                sent_count += 1

                # FIX: was `best_ind.get("confidence") or SIGHTING_DEFAULT_CONFIDENCE`
                # — `or` treats a real confidence of 0 as falsy and
                # silently overwrites it with 50, corrupting genuine
                # low-confidence data. Explicit None-check instead.
                ind_confidence = best_ind.get("confidence")
                sighting_id = create_sighting(
                    url, token, best_ind.get("id"),
                    first_seen=sighting_ts, last_seen=sighting_ts,
                    confidence=ind_confidence if ind_confidence is not None else SIGHTING_DEFAULT_CONFIDENCE,
                    description=f"Sighted via Wazuh SOC ({log_source_label}) - {ioc['type']} match on agent {agent_name}",
                    agent_name=agent_name,
                    agent=alert.get("agent"),
                )
                if sighting_id:
                    # Sent as its own lightweight follow-up event (see
                    # rule 100715) instead of being embedded in the
                    # already-sent detection alert above.
                    _send_now({
                        "integration": "opencti",
                        "opencti": {
                            "event_type": "sighting_confirmed",
                            "sighting_id": sighting_id,
                            "ioc_type": ioc["type"],
                            "query_values": ";".join(obs_values),
                        }
                    }, alert.get("agent"))

        observable_matched = False
        if not indicator_matched and observables_section and "edges" in observables_section:
            valid_obss = [e["node"] for e in observables_section["edges"] if e.get("node")]
            if valid_obss:
                observable_matched = True
                best_obs = valid_obss[0]
                author_name = _extract_author_name(best_obs)
                obs_type = best_obs.get("entity_type", ioc["type"])

                new_alert = {
                    "integration": "opencti",
                    "opencti": {
                        "observable": best_obs,
                        "type": obs_type,
                        "author_name": author_name,
                        "createdBy": {"name": author_name},
                        "query_key": obs_key,
                        "query_values": ";".join(obs_values),
                        "ioc_type": ioc["type"],
                        "event_type": "observable_without_indicator",
                    }
                }

                inds = [x.get("node") for x in best_obs.get("indicators", {}).get("edges", []) if x.get("node")]
                if inds:
                    new_alert["opencti"]["event_type"] = "observable_with_indicator"
                    new_alert["opencti"]["indicator"] = inds[0]

                add_context(alert, new_alert)

                # FIX (latency): send now, don't gate on the sighting call.
                _send_now(new_alert, alert.get("agent"))
                sent_count += 1

                sighting_id = create_sighting(
                    url, token, best_obs.get("id"),
                    first_seen=sighting_ts, last_seen=sighting_ts,
                    confidence=SIGHTING_DEFAULT_CONFIDENCE,
                    description=f"Sighted via Wazuh SOC ({log_source_label}) - {ioc['type']} match on agent {agent_name}",
                    agent_name=agent_name,
                    agent=alert.get("agent"),
                )
                if sighting_id:
                    _send_now({
                        "integration": "opencti",
                        "opencti": {
                            "event_type": "sighting_confirmed",
                            "sighting_id": sighting_id,
                            "ioc_type": ioc["type"],
                            "query_values": ";".join(obs_values),
                        }
                    }, alert.get("agent"))

        # ADD-ON: OpenCTI had no indicator AND no observable for this
        # IOC. Before, that meant the IOC was silently dropped here.
        # Run the local, no-network, no-CDB heuristics as a fallback -
        # this is the only place they're called from.
        if not indicator_matched and not observable_matched:
            local_hit = evaluate_local_heuristic(ioc)
            if local_hit:
                new_alert = {
                    "integration": "opencti",
                    "opencti": {
                        "local": local_hit,
                        "ioc_type": ioc["type"],
                        "query_key": obs_key,
                        "query_values": ";".join(obs_values),
                        "event_type": "local_heuristic_match",
                    }
                }
                add_context(alert, new_alert)
                _send_now(new_alert, alert.get("agent"))
                sent_count += 1

    if CACHE_TTL_SECONDS:
        _save_cache(cache)

    return sent_count


def main(args):
    global url, debug_enabled

    if len(args) < 4:
        log(f"Incorrect arguments: {' '.join(args)}")
        sys.exit(1)

    alert_path = args[1]
    token = os.environ.get("OPENCTI_API_TOKEN") or args[2]
    url = args[3]
    debug_enabled = len(args) > 4 and args[4] == "debug"

    debug(f"# Starting OpenCTI v2.3 integration, alert_path={alert_path}, url={url}")

    try:
        with open(alert_path, errors="ignore") as alert_file:
            alert = json.load(alert_file)
    except Exception as e:
        log(f"Failed to read alert file {alert_path}: {e}")
        sys.exit(1)

    # FIX (latency): query_opencti() now sends each detection to the
    # Wazuh socket immediately as it's found (via _send_now()), rather
    # than returning a list here to be sent only after the entire
    # per-alert IOC loop finished. This just runs it and logs the count.
    sent_count = query_opencti(alert, url, token)
    debug(f"# Sent {sent_count} enrichment event(s) to Wazuh socket")


if __name__ == "__main__":
    try:
        main(sys.argv)
    except Exception as e:
        debug(str(e), do_log=True)
        debug(traceback.format_exc(), do_log=True)
        raise
