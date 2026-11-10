"""Detection rules. Each rule takes the full, time-sorted event list and returns alerts.

Every rule is mapped to MITRE ATT&CK so alerts can be triaged and reported in a
common language. Thresholds live in `Thresholds` so they can be tuned per
environment from the command line.
"""

from __future__ import annotations

import base64
import binascii
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Callable

from . import events as ev
from .enrich import ip_scope, is_allowed
from .events import Event
from .parsers import PRIVILEGED_GROUPS

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


@dataclass
class Alert:
    rule_id: str
    title: str
    severity: str
    mitre: list[tuple[str, str]]
    first_seen: datetime
    last_seen: datetime
    description: str
    host: str = ""
    user: str = ""
    src_ip: str = ""
    count: int = 1
    evidence: list[str] = field(default_factory=list)
    details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "mitre": [{"id": tid, "name": name} for tid, name in self.mitre],
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "host": self.host,
            "user": self.user,
            "src_ip": self.src_ip,
            "count": self.count,
            "description": self.description,
            "details": self.details,
            "evidence": self.evidence,
        }


@dataclass
class Thresholds:
    brute_force_count: int = 10          # failures from one IP ...
    brute_force_window_min: int = 5      # ... within this many minutes
    spray_distinct_users: int = 5        # distinct usernames that turn brute force into spraying
    success_after_failures: int = 5      # failures before a success that look like a compromise
    success_lookback_min: int = 30
    new_admin_window_min: int = 60       # account created then made admin within this window
    max_evidence: int = 10


# --- helpers ----------------------------------------------------------------

def _evidence(events: list[Event], limit: int) -> list[str]:
    if len(events) <= limit:
        return [e.raw for e in events]
    half = limit // 2
    skipped = len(events) - 2 * half
    return [e.raw for e in events[:half]] + [f"... {skipped} more ..."] + [e.raw for e in events[-half:]]


def _sessions(events: list[Event], gap: timedelta) -> list[list[Event]]:
    """Split time-sorted events into bursts where consecutive events are at most `gap` apart."""
    bursts: list[list[Event]] = []
    for e in events:
        if bursts and e.timestamp - bursts[-1][-1].timestamp <= gap:
            bursts[-1].append(e)
        else:
            bursts.append([e])
    return bursts


def _max_in_window(events: list[Event], window: timedelta) -> int:
    best, start = 0, 0
    for end in range(len(events)):
        while events[end].timestamp - events[start].timestamp > window:
            start += 1
        best = max(best, end - start + 1)
    return best


# --- rules ------------------------------------------------------------------

def detect_brute_force_and_spray(events: list[Event], t: Thresholds) -> list[Alert]:
    """T1110.001 password guessing and T1110.003 password spraying, grouped per source IP."""
    window = timedelta(minutes=t.brute_force_window_min)
    by_ip: dict[str, list[Event]] = defaultdict(list)
    for e in events:
        if e.event_type == ev.AUTH_FAILURE and e.src_ip:
            by_ip[e.src_ip].append(e)

    alerts = []
    for ip, failures in by_ip.items():
        for burst in _sessions(failures, window):
            if _max_in_window(burst, window) < t.brute_force_count:
                continue
            users = sorted({e.user for e in burst if e.user})
            hosts = sorted({e.host for e in burst if e.host})
            if len(users) >= t.spray_distinct_users:
                alerts.append(Alert(
                    rule_id="AUTH-002",
                    title="Password spraying from single source",
                    severity="high",
                    mitre=[("T1110.003", "Brute Force: Password Spraying")],
                    first_seen=burst[0].timestamp, last_seen=burst[-1].timestamp,
                    description=(f"{ip} failed {len(burst)} logins against {len(users)} different "
                                 f"accounts. Many users with few attempts each is typical of spraying."),
                    host=", ".join(hosts), src_ip=ip, count=len(burst),
                    evidence=_evidence(burst, t.max_evidence),
                    details={"targeted_users": users},
                ))
            else:
                alerts.append(Alert(
                    rule_id="AUTH-001",
                    title="Brute force against account(s)",
                    severity="medium",
                    mitre=[("T1110.001", "Brute Force: Password Guessing")],
                    first_seen=burst[0].timestamp, last_seen=burst[-1].timestamp,
                    description=(f"{ip} failed {len(burst)} logins "
                                 f"(at least {t.brute_force_count} within {t.brute_force_window_min} min)."),
                    host=", ".join(hosts), user=", ".join(users), src_ip=ip, count=len(burst),
                    evidence=_evidence(burst, t.max_evidence),
                    details={"targeted_users": users},
                ))
    return alerts


def detect_success_after_failures(events: list[Event], t: Thresholds) -> list[Alert]:
    """A successful login from an IP that just failed many times: possible compromised account."""
    lookback = timedelta(minutes=t.success_lookback_min)
    failures_by_ip: dict[str, list[Event]] = defaultdict(list)
    alerts = []
    for e in events:
        if not e.src_ip:
            continue
        if e.event_type == ev.AUTH_FAILURE:
            failures_by_ip[e.src_ip].append(e)
        elif e.event_type == ev.AUTH_SUCCESS:
            recent = [f for f in failures_by_ip[e.src_ip] if e.timestamp - f.timestamp <= lookback]
            if len(recent) >= t.success_after_failures:
                same_user = sum(1 for f in recent if f.user == e.user)
                alerts.append(Alert(
                    rule_id="AUTH-003",
                    title="Successful login after repeated failures",
                    severity="critical" if same_user else "high",
                    mitre=[("T1110", "Brute Force"), ("T1078", "Valid Accounts")],
                    first_seen=recent[0].timestamp, last_seen=e.timestamp,
                    description=(f"{e.user} logged in from {e.src_ip} after {len(recent)} failures from "
                                 f"that IP in the previous {t.success_lookback_min} min "
                                 f"({same_user} of them against this account). Treat as compromised "
                                 f"until proven otherwise."),
                    host=e.host, user=e.user, src_ip=e.src_ip, count=len(recent) + 1,
                    evidence=_evidence(recent + [e], t.max_evidence),
                ))
                failures_by_ip[e.src_ip].clear()  # one alert per break-in
    return alerts


def detect_account_changes(events: list[Event], t: Thresholds) -> list[Alert]:
    """T1136 new accounts and T1098 privileged group membership, correlated."""
    window = timedelta(minutes=t.new_admin_window_min)
    created: dict[tuple[str, str], Event] = {}
    alerts = []
    for e in events:
        if e.event_type == ev.ACCOUNT_CREATED:
            created[(e.host, e.user.lower())] = e
            by = e.extra.get("created_by")
            alerts.append(Alert(
                rule_id="ACCT-001",
                title="Local account created",
                severity="medium",
                mitre=[("T1136.001", "Create Account: Local Account")],
                first_seen=e.timestamp, last_seen=e.timestamp,
                description=f"New account '{e.user}' created on {e.host}" + (f" by {by}." if by else "."),
                host=e.host, user=e.user, evidence=[e.raw],
            ))
        elif e.event_type == ev.GROUP_MEMBER_ADDED:
            group = str(e.extra.get("group", ""))
            if group.lower() not in PRIVILEGED_GROUPS:
                continue
            new = created.get((e.host, e.user.lower()))
            fresh = new is not None and timedelta(0) <= e.timestamp - new.timestamp <= window
            by = e.extra.get("added_by")
            alerts.append(Alert(
                rule_id="ACCT-003" if fresh else "ACCT-002",
                title=("Newly created account added to privileged group" if fresh
                       else "Account added to privileged group"),
                severity="critical" if fresh else "high",
                mitre=[("T1098", "Account Manipulation")] + (
                    [("T1136.001", "Create Account: Local Account")] if fresh else []),
                first_seen=new.timestamp if fresh else e.timestamp, last_seen=e.timestamp,
                description=(f"'{e.user}' added to '{group}' on {e.host}" + (f" by {by}" if by else "")
                             + (f", only {int((e.timestamp - new.timestamp).total_seconds() // 60)} min "
                                f"after the account was created. Classic persistence pattern." if fresh else ".")),
                host=e.host, user=e.user,
                evidence=([new.raw] if fresh else []) + [e.raw],
                details={"group": group},
            ))
    return alerts


_PS_IMAGES = ("\\powershell.exe", "\\pwsh.exe", "/pwsh")
# PowerShell accepts any unambiguous prefix of -EncodedCommand (-e, -en, -enc, ...) plus -ec.
# -ex (ExecutionPolicy) does not match because only 'n' or 'c' may follow the 'e'.
_ENC_FLAG = re.compile(
    r"(?i)(?:^|\s)[-/](?:ec|e(?:n(?:c(?:o(?:d(?:e(?:d(?:c(?:o(?:m(?:m(?:a(?:n(?:d)?)?)?)?)?)?)?)?)?)?)?)?)?)"
    r"\s+[\"']?(?P<payload>[A-Za-z0-9+/=]{8,})"
)
_SUSPICIOUS_DECODED = re.compile(
    r"(?i)downloadstring|downloadfile|invoke-expression|\biex\b|net\.webclient|frombase64string|"
    r"invoke-webrequest|bitstransfer|-nop\b|hidden|mimikatz|amsi"
)


def decode_powershell(payload: str) -> str | None:
    """Decode a -EncodedCommand payload (Base64 of UTF-16LE). Returns None if it is not valid."""
    try:
        padded = payload + "=" * (-len(payload) % 4)
        return base64.b64decode(padded, validate=True).decode("utf-16-le")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None


def detect_encoded_powershell(events: list[Event], t: Thresholds) -> list[Alert]:
    """T1059.001 PowerShell with an encoded command, decoded for the analyst."""
    alerts = []
    for e in events:
        if e.event_type != ev.PROCESS_CREATED:
            continue
        image = str(e.extra.get("image", "")).lower()
        cmd = str(e.extra.get("command_line", ""))
        if not image.endswith(_PS_IMAGES):
            continue
        m = _ENC_FLAG.search(cmd)
        if not m:
            continue
        decoded = decode_powershell(m["payload"])
        suspicious = sorted({k.lower() for k in _SUSPICIOUS_DECODED.findall(decoded or "")})
        alerts.append(Alert(
            rule_id="EXEC-001",
            title="Encoded PowerShell command",
            severity="high" if suspicious else "medium",
            mitre=[("T1059.001", "Command and Scripting Interpreter: PowerShell"),
                   ("T1027", "Obfuscated Files or Information")],
            first_seen=e.timestamp, last_seen=e.timestamp,
            description=("PowerShell started with an encoded command"
                         + (f"; decoded script contains: {', '.join(suspicious)}." if suspicious else ".")),
            host=e.host, user=e.user, evidence=[e.raw],
            details={"decoded_command": decoded, "parent_image": e.extra.get("parent_image", "")},
        ))
    return alerts


def detect_log_cleared(events: list[Event], t: Thresholds) -> list[Alert]:
    """T1070.001 Windows Security log cleared (event 1102)."""
    return [Alert(
        rule_id="EVADE-001",
        title="Security event log cleared",
        severity="high",
        mitre=[("T1070.001", "Indicator Removal: Clear Windows Event Logs")],
        first_seen=e.timestamp, last_seen=e.timestamp,
        description=f"Security log on {e.host} was cleared by {e.user or 'unknown'}. "
                    f"Attackers do this to hide their tracks; check what happened just before.",
        host=e.host, user=e.user, evidence=[e.raw],
    ) for e in events if e.event_type == ev.LOG_CLEARED]


def _basename(path: str) -> str:
    return path.replace("/", "\\").rsplit("\\", 1)[-1].lower()


OFFICE_APPS = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe",
               "mspub.exe", "onenote.exe", "visio.exe"}
SCRIPT_HOSTS = {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe",
                "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "msiexec.exe"}
EXECUTABLE_EXTENSIONS = {".exe", ".dll", ".scr", ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse",
                         ".hta", ".bat", ".cmd", ".wsf", ".msi", ".cpl"}


def detect_office_child_process(events: list[Event], t: Thresholds) -> list[Alert]:
    """T1204.002 / T1566.001: an Office app launching a shell or script host (macro or exploit)."""
    alerts = []
    for e in events:
        if e.event_type != ev.PROCESS_CREATED:
            continue
        parent = _basename(str(e.extra.get("parent_image", "")))
        child = _basename(str(e.extra.get("image", "")))
        if parent in OFFICE_APPS and child in SCRIPT_HOSTS:
            alerts.append(Alert(
                rule_id="EXEC-002",
                title="Office application spawned a shell or script host",
                severity="high",
                mitre=[("T1204.002", "User Execution: Malicious File"),
                       ("T1566.001", "Phishing: Spearphishing Attachment")],
                first_seen=e.timestamp, last_seen=e.timestamp,
                description=(f"{parent} started {child}. Documents should not launch interpreters; this is "
                             f"the usual sign of a malicious macro or exploit. Find the document and "
                             f"the email it arrived in."),
                host=e.host, user=e.user, evidence=[e.raw],
                details={"parent_image": e.extra.get("parent_image"), "image": e.extra.get("image"),
                         "command_line": e.extra.get("command_line")},
            ))
    return alerts


def detect_script_host_external_connection(events: list[Event], t: Thresholds) -> list[Alert]:
    """T1105 / T1071: PowerShell, cmd and LOLBins talking to the internet (Sysmon event 3)."""
    grouped: dict[tuple[str, str, str, str], list[Event]] = defaultdict(list)
    for e in events:
        if e.event_type != ev.NETWORK_CONNECTION:
            continue
        image = _basename(str(e.extra.get("image", "")))
        dest = str(e.extra.get("dest_ip", ""))
        if image in SCRIPT_HOSTS and ip_scope(dest) == "external":
            grouped[(e.host, image, dest, str(e.extra.get("dest_port", "")))].append(e)
    alerts = []
    for (host, image, dest, port), conns in grouped.items():
        dest_host = next((c.extra.get("dest_host") for c in conns if c.extra.get("dest_host")), "")
        alerts.append(Alert(
            rule_id="NET-001",
            title="Script host connected to external address",
            severity="medium",
            mitre=[("T1105", "Ingress Tool Transfer"), ("T1071.001", "Application Layer Protocol: Web Protocols")],
            first_seen=conns[0].timestamp, last_seen=conns[-1].timestamp,
            description=(f"{image} on {host} connected to {dest}:{port}" + (f" ({dest_host})" if dest_host else "")
                         + f" {len(conns)} time(s). Check the process command line and what was downloaded."),
            host=host, user=conns[0].user, count=len(conns), evidence=_evidence(conns, t.max_evidence),
            details={"image": image, "dest_ip": dest, "dest_port": port, "dest_host": dest_host,
                     "dest_scope": "external"},
        ))
    return alerts


def detect_executable_dropped(events: list[Event], t: Thresholds) -> list[Alert]:
    """T1204.002 / T1105: Office or a script host writing an executable or script to disk (Sysmon 11)."""
    alerts = []
    for e in events:
        if e.event_type != ev.FILE_CREATED:
            continue
        creator = _basename(str(e.extra.get("image", "")))
        target = str(e.extra.get("target", ""))
        ext = "." + target.rsplit(".", 1)[-1].lower() if "." in _basename(target) else ""
        if ext not in EXECUTABLE_EXTENSIONS or not (creator in OFFICE_APPS or creator in SCRIPT_HOSTS):
            continue
        office = creator in OFFICE_APPS
        alerts.append(Alert(
            rule_id="FILE-001",
            title="Executable or script written by " + ("Office application" if office else "script host"),
            severity="high" if office else "medium",
            mitre=[("T1105", "Ingress Tool Transfer"), ("T1204.002", "User Execution: Malicious File")],
            first_seen=e.timestamp, last_seen=e.timestamp,
            description=f"{creator} wrote {target}. Hash the file and check whether it was executed.",
            host=e.host, user=e.user, evidence=[e.raw],
            details={"image": e.extra.get("image"), "target": target},
        ))
    return alerts


RULES: list[Callable[[list[Event], Thresholds], list[Alert]]] = [
    detect_brute_force_and_spray,
    detect_success_after_failures,
    detect_account_changes,
    detect_encoded_powershell,
    detect_office_child_process,
    detect_script_host_external_connection,
    detect_executable_dropped,
    detect_log_cleared,
]


def _enrich(alerts: list[Alert], allow: list) -> list[Alert]:
    kept = []
    for a in alerts:
        if a.src_ip and a.rule_id.startswith("AUTH-") and is_allowed(a.src_ip, allow):
            continue  # trusted source: scanner, jump host, admin subnet
        if a.src_ip:
            a.details["src_ip_scope"] = scope = ip_scope(a.src_ip)
            if a.rule_id == "AUTH-003" and scope == "external" and a.severity != "critical":
                a.severity = "critical"
                a.description += " The source is external to the organisation."
        kept.append(a)
    return kept


def run_all(events: list[Event], thresholds: Thresholds | None = None,
            allow: list | None = None) -> list[Alert]:
    """Run every rule. `allow` is a list of trusted networks (see enrich.parse_allow_list)."""
    thresholds = thresholds or Thresholds()
    events = sorted(events, key=lambda e: e.timestamp)
    alerts = _enrich([a for rule in RULES for a in rule(events, thresholds)], allow or [])
    return sorted(alerts, key=lambda a: (-SEVERITY_ORDER[a.severity], a.first_seen))
