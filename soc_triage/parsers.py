"""Parsers that turn raw log files into normalized Event objects.

Supported inputs:
  * Linux auth.log / secure (sshd lines), classic syslog or ISO-8601 timestamps
  * Windows Security events exported as JSON lines or a JSON array
    (for example: Get-WinEvent ... | ConvertTo-Json, or a SIEM export)
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator

from . import events as ev
from .events import Event

# --- Linux auth.log ---------------------------------------------------------

_SYSLOG_TS = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<rest>.*)$"
)
_ISO_TS = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+(?P<host>\S+)\s+(?P<rest>.*)$"
)
_SSHD_FAILED = re.compile(
    r"sshd\[\d+\]:\s+Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+) port \d+"
)
_SSHD_INVALID = re.compile(
    r"sshd\[\d+\]:\s+Invalid user (?P<user>\S*) from (?P<ip>[0-9a-fA-F:.]+)"
)
_SSHD_ACCEPTED = re.compile(
    r"sshd\[\d+\]:\s+Accepted (?P<method>password|publickey|keyboard-interactive/pam) for (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+) port \d+"
)
_USERADD = re.compile(r"useradd\[\d+\]:\s+new user: name=(?P<user>[^,\s]+)")
_USERMOD_GROUP = re.compile(
    r"(?:usermod|gpasswd)\[\d+\]:\s+(?:add '(?P<user1>[^']+)' to group '(?P<group1>[^']+)'|"
    r"user (?P<user2>\S+) added by \S+ to group (?P<group2>\S+))"
)


def _parse_syslog_time(text: str, year: int) -> datetime:
    # Classic syslog has no year or zone; we treat it as UTC in the given year.
    return datetime.strptime(f"{year} {' '.join(text.split())}", "%Y %b %d %H:%M:%S").replace(
        tzinfo=timezone.utc
    )


def _parse_iso_time(text: str) -> datetime:
    dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def parse_auth_log(lines: Iterable[str], year: int | None = None) -> Iterator[Event]:
    """Parse Linux auth.log lines. Lines that are not security-relevant are skipped."""
    year = year or datetime.now(timezone.utc).year
    for line in lines:
        line = line.rstrip("\n")
        m = _ISO_TS.match(line)
        if m:
            ts = _parse_iso_time(m["ts"])
        else:
            m = _SYSLOG_TS.match(line)
            if not m:
                continue
            ts = _parse_syslog_time(m["ts"], year)
        host, rest = m["host"], m["rest"]

        if fm := _SSHD_FAILED.search(rest):
            yield Event(ts, "linux-auth", ev.AUTH_FAILURE, host, fm["user"], fm["ip"], line,
                        {"service": "sshd"})
        elif _SSHD_INVALID.search(rest):
            # "Invalid user" is usually followed by a "Failed password" line for the
            # same attempt, so we only keep it as context rather than counting it twice.
            continue
        elif am := _SSHD_ACCEPTED.search(rest):
            yield Event(ts, "linux-auth", ev.AUTH_SUCCESS, host, am["user"], am["ip"], line,
                        {"service": "sshd", "method": am["method"]})
        elif um := _USERADD.search(rest):
            yield Event(ts, "linux-auth", ev.ACCOUNT_CREATED, host, um["user"], "", line, {})
        elif gm := _USERMOD_GROUP.search(rest):
            user = gm["user1"] or gm["user2"]
            group = gm["group1"] or gm["group2"]
            yield Event(ts, "linux-auth", ev.GROUP_MEMBER_ADDED, host, user, "", line,
                        {"group": group})


# --- Windows Security log ---------------------------------------------------

PRIVILEGED_GROUPS = {
    "administrators", "domain admins", "enterprise admins", "schema admins",
    "account operators", "backup operators", "remote desktop users",
    # Linux equivalents, used by the auth.log parser
    "sudo", "wheel", "root", "adm",
}


def _clean(value) -> str:
    if value is None:
        return ""
    value = str(value).strip()
    return "" if value == "-" else value


SYSMON_IDS = {1, 3, 11}


def _is_sysmon(record: dict, event_id: int) -> bool:
    channel = str(record.get("Channel") or record.get("ProviderName") or "")
    if "sysmon" in channel.lower():
        return True
    # Exports without a channel: Sysmon events carry Image; Security events do not.
    return event_id in SYSMON_IDS and "Image" in record


def _short_user(value: str) -> str:
    # Sysmon reports DOMAIN\user; Security events report the bare name.
    return value.rsplit("\\", 1)[-1] if value else ""


def _sysmon_event(record: dict, event_id: int, ts: datetime, host: str, raw: str) -> Event | None:
    image = _clean(record.get("Image"))
    user = _short_user(_clean(record.get("User")))
    if event_id == 1:
        return Event(ts, "windows-sysmon", ev.PROCESS_CREATED, host, user, "", raw,
                     {"event_id": 1, "image": image,
                      "command_line": _clean(record.get("CommandLine")),
                      "parent_image": _clean(record.get("ParentImage")),
                      "hashes": _clean(record.get("Hashes"))})
    if event_id == 3:
        return Event(ts, "windows-sysmon", ev.NETWORK_CONNECTION, host, user, _clean(record.get("SourceIp")), raw,
                     {"event_id": 3, "image": image,
                      "dest_ip": _clean(record.get("DestinationIp")),
                      "dest_port": _clean(record.get("DestinationPort")),
                      "dest_host": _clean(record.get("DestinationHostname"))})
    if event_id == 11:
        return Event(ts, "windows-sysmon", ev.FILE_CREATED, host, user, "", raw,
                     {"event_id": 11, "image": image, "target": _clean(record.get("TargetFilename"))})
    return None


def _win_event(record: dict) -> Event | None:
    try:
        event_id = int(record.get("EventID") or record.get("Id") or record.get("event_id"))
    except (TypeError, ValueError):
        return None
    ts_raw = (record.get("UtcTime") or record.get("TimeCreated") or record.get("@timestamp")
              or record.get("timestamp"))
    if not ts_raw:
        return None
    ts = _parse_iso_time(str(ts_raw))
    host = _clean(record.get("Computer") or record.get("host"))
    raw = json.dumps(record, sort_keys=True)
    if _is_sysmon(record, event_id):
        return _sysmon_event(record, event_id, ts, host, raw)
    ip = _clean(record.get("IpAddress"))
    target = _clean(record.get("TargetUserName"))
    subject = _clean(record.get("SubjectUserName"))

    if event_id == 4625:
        return Event(ts, "windows-security", ev.AUTH_FAILURE, host, target, ip, raw,
                     {"event_id": 4625, "logon_type": record.get("LogonType"),
                      "status": record.get("Status") or record.get("SubStatus")})
    if event_id == 4624:
        return Event(ts, "windows-security", ev.AUTH_SUCCESS, host, target, ip, raw,
                     {"event_id": 4624, "logon_type": record.get("LogonType")})
    if event_id == 4720:
        return Event(ts, "windows-security", ev.ACCOUNT_CREATED, host, target, "", raw,
                     {"event_id": 4720, "created_by": subject})
    if event_id in (4728, 4732, 4756):
        member = _clean(record.get("MemberName")) or _clean(record.get("MemberSid"))
        # MemberName is often a DN like "CN=eve,CN=Users,DC=corp,DC=local"
        if member.upper().startswith("CN="):
            member = member.split(",")[0][3:]
        return Event(ts, "windows-security", ev.GROUP_MEMBER_ADDED, host, member, "", raw,
                     {"event_id": event_id, "group": target, "added_by": subject})
    if event_id == 4688:
        return Event(ts, "windows-security", ev.PROCESS_CREATED, host, subject, "", raw,
                     {"event_id": 4688,
                      "image": _clean(record.get("NewProcessName")),
                      "command_line": _clean(record.get("CommandLine")),
                      "parent_image": _clean(record.get("ParentProcessName"))})
    if event_id == 1102:
        return Event(ts, "windows-security", ev.LOG_CLEARED, host, subject, "", raw,
                     {"event_id": 1102})
    return None


def parse_windows_json(text: str) -> Iterator[Event]:
    """Parse Windows Security events from a JSON array or JSON lines."""
    text = text.strip()
    if not text:
        return
    if text.startswith("["):
        records = json.loads(text)
    else:
        records = [json.loads(line) for line in text.splitlines() if line.strip()]
    for record in records:
        if isinstance(record, dict) and (event := _win_event(record)):
            yield event


# --- Linux auditd -------------------------------------------------------------

_AUDIT_HEADER = re.compile(
    r"^(?:node=(?P<node>\S+)\s+)?type=(?P<type>\w+)\s+msg=audit\((?P<epoch>\d+(?:\.\d+)?):\d+\):\s*(?P<body>.*)$"
)
_KV = re.compile(r"(\w+)=(\"[^\"]*\"|'[^']*'|\S+)")
_HEX = re.compile(r"^(?:[0-9A-Fa-f]{2})+$")


def _audit_value(raw: str) -> str:
    if raw[:1] in {'"', "'"}:
        return raw[1:-1]
    # auditd hex-encodes untrusted strings that contain spaces or odd characters
    if _HEX.match(raw) and len(raw) >= 4:
        try:
            return bytes.fromhex(raw).decode("utf-8")
        except UnicodeDecodeError:
            pass
    return "" if raw == "?" else raw


def _audit_fields(body: str) -> dict[str, str]:
    # Enriched format appends translated fields after a 0x1d separator; we only need the raw ones.
    body = body.split("\x1d", 1)[0]
    fields: dict[str, str] = {}
    for key, raw in _KV.findall(body):
        if key == "msg" and raw[:1] == "'":
            for ikey, iraw in _KV.findall(raw[1:-1]):
                fields.setdefault(ikey, _audit_value(iraw))
        else:
            fields.setdefault(key, _audit_value(raw))
    return fields


def parse_audit_log(lines: Iterable[str], default_host: str = "") -> Iterator[Event]:
    """Parse Linux auditd records (audit.log). Unrelated record types are skipped.

    A failed SSH login writes both USER_AUTH and USER_LOGIN records; only USER_AUTH is
    counted as the failure and only USER_LOGIN as the success, so nothing is counted twice.
    """
    seen_group_adds: set[tuple] = set()
    for line in lines:
        m = _AUDIT_HEADER.match(line.strip())
        if not m:
            continue
        rtype = m["type"]
        if rtype not in {"USER_AUTH", "USER_LOGIN", "ADD_USER", "USER_MGMT", "ADD_GROUP"}:
            continue
        f = _audit_fields(m["body"])
        ts = datetime.fromtimestamp(float(m["epoch"]), tz=timezone.utc)
        host = m["node"] or default_host
        ip = f.get("addr") or (f.get("hostname") if re.match(r"^[0-9a-fA-F:.]+$", f.get("hostname", "")) else "")
        user = f.get("acct") or f.get("id", "")
        result = f.get("res", "").lower()
        exe = f.get("exe", "")
        extra = {"audit_type": rtype, "exe": exe, "terminal": f.get("terminal", "")}
        line = line.rstrip("\n")

        if rtype == "USER_AUTH" and result == "failed":
            yield Event(ts, "linux-auditd", ev.AUTH_FAILURE, host, user, ip, line, extra)
        elif rtype == "USER_LOGIN" and result == "success" and ip:
            yield Event(ts, "linux-auditd", ev.AUTH_SUCCESS, host, user, ip, line, extra)
        elif rtype == "ADD_USER" and result == "success":
            yield Event(ts, "linux-auditd", ev.ACCOUNT_CREATED, host, user, "", line,
                        {**extra, "created_by_auid": f.get("auid", "")})
        elif rtype == "USER_MGMT" and result == "success" and f.get("op") in {"add-user-to-group", "add-to-group"}:
            group = f.get("grp", "")
            key = (host, user, group, int(ts.timestamp()))
            if key in seen_group_adds:
                continue
            seen_group_adds.add(key)
            yield Event(ts, "linux-auditd", ev.GROUP_MEMBER_ADDED, host, user, "", line,
                        {**extra, "group": group})


# --- File dispatch ----------------------------------------------------------

FORMATS = ("auth-log", "auditd", "windows-json")


def detect_format(path: Path, sample: str) -> str:
    stripped = sample.lstrip()
    if path.suffix.lower() in {".json", ".jsonl", ".ndjson"} or stripped[:1] in {"{", "["}:
        return "windows-json"
    if stripped.startswith(("type=", "node=")):
        return "auditd"
    return "auth-log"


def parse_file(path: str | Path, fmt: str = "auto", year: int | None = None) -> list[Event]:
    path = Path(path)
    text = path.read_text(encoding="utf-8", errors="replace")
    if fmt == "auto":
        fmt = detect_format(path, text[:200])
    if fmt == "windows-json":
        events = list(parse_windows_json(text))
    elif fmt == "auth-log":
        events = list(parse_auth_log(text.splitlines(), year=year))
    elif fmt == "auditd":
        events = list(parse_audit_log(text.splitlines()))
    else:
        raise ValueError(f"unknown format: {fmt}")
    return sorted(events, key=lambda e: e.timestamp)
