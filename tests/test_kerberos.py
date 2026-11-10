import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from soc_triage import events as ev
from soc_triage.cli import main
from soc_triage.detections import run_all
from soc_triage.events import Event
from soc_triage.parsers import parse_file, parse_windows_json

SAMPLES = Path(__file__).resolve().parent.parent / "sample_logs"
T0 = datetime(2026, 11, 10, 9, 0, tzinfo=timezone.utc)


def win(event_id, minutes=0.0, **fields):
    ts = (T0 + timedelta(minutes=minutes)).isoformat().replace("+00:00", "Z")
    return {"EventID": event_id, "TimeCreated": ts, "Computer": "DC01", **fields}


def parse(*records):
    return list(parse_windows_json("\n".join(json.dumps(r) for r in records)))


def tgs(service, minutes=0.0, user="eve@CORP.EXAMPLE", enc="0x17", status="0x0"):
    return win(4769, minutes, TargetUserName=user, ServiceName=service, IpAddress="::ffff:10.0.0.5",
               TicketEncryptionType=enc, Status=status)


def ids(events):
    return sorted(a.rule_id for a in run_all(events))


# --- parsing ----------------------------------------------------------------

def test_4769_normalises_realm_mapped_ip_and_encryption():
    (e,) = parse(win(4769, TargetUserName="eve@CORP.EXAMPLE", ServiceName="svc_sql",
                     IpAddress="::ffff:10.0.0.5", TicketEncryptionType=23, Status="0x0"))
    assert e.event_type == ev.TGS_REQUEST
    assert (e.user, e.src_ip) == ("eve", "10.0.0.5")
    assert e.extra["encryption"] == "0x17" and e.extra["service"] == "svc_sql"


def test_4771_bad_password_is_auth_failure_other_codes_are_not():
    events = parse(win(4771, TargetUserName="bob", IpAddress="::ffff:10.0.0.9", Status="0x18"),
                   win(4771, TargetUserName="bob", IpAddress="::ffff:10.0.0.9", Status="0x12"))
    assert [e.event_type for e in events] == [ev.AUTH_FAILURE]
    assert events[0].extra["event_id"] == 4771


def test_real_ipv6_is_not_truncated():
    (e,) = parse(win(4768, TargetUserName="a", IpAddress="2001:db8::5", PreAuthType="2", Status="0x0"))
    assert e.src_ip == "2001:db8::5"


# --- KERB-001 Kerberoasting -------------------------------------------------

def test_kerberoasting_three_rc4_services_alerts():
    alerts = run_all(parse(tgs("svc_sql"), tgs("svc_web", 0.1), tgs("svc_backup", 0.2)))
    (alert,) = alerts
    assert alert.rule_id == "KERB-001" and alert.severity == "high"
    assert alert.details["services"] == ["svc_backup", "svc_sql", "svc_web"]
    assert alert.user == "eve" and alert.src_ip == "10.0.0.5"


def test_two_rc4_services_is_below_threshold():
    assert ids(parse(tgs("svc_sql"), tgs("svc_web", 0.1))) == []


def test_same_service_requested_repeatedly_is_not_kerberoasting():
    assert ids(parse(*[tgs("svc_legacy", i) for i in range(6)])) == []


@pytest.mark.parametrize("services", [["FILE01$", "SQL01$", "WEB01$"], ["krbtgt", "KRBTGT", "DC01$"]])
def test_computer_accounts_and_krbtgt_are_ignored(services):
    assert ids(parse(*[tgs(s, i * 0.1) for i, s in enumerate(services)])) == []


def test_aes_tickets_are_ignored():
    assert ids(parse(*[tgs(s, i * 0.1, enc="0x12") for i, s in enumerate(["a", "b", "c", "d"])])) == []


def test_failed_ticket_requests_are_ignored():
    assert ids(parse(*[tgs(s, i * 0.1, status="0x1b") for i, s in enumerate(["a", "b", "c"])])) == []


def test_rc4_requests_spread_over_hours_are_quiet():
    assert ids(parse(tgs("a", 0), tgs("b", 60), tgs("c", 120))) == []


# --- KERB-002 AS-REP roasting -----------------------------------------------

def asrep(user, minutes=0.0, pre="0", ip="::ffff:10.0.0.5"):
    return win(4768, minutes, TargetUserName=user, IpAddress=ip, PreAuthType=pre, TicketEncryptionType="0x17", Status="0x0")


def test_single_account_without_preauth_is_medium():
    (alert,) = run_all(parse(asrep("legacy-app")))
    assert alert.rule_id == "KERB-002" and alert.severity == "medium"


def test_several_accounts_from_one_source_is_high():
    (alert,) = run_all(parse(asrep("legacy-app"), asrep("svc-scanner", 0.1)))
    assert alert.severity == "high" and alert.details["accounts"] == ["legacy-app", "svc-scanner"]


def test_normal_preauth_tgt_is_quiet():
    assert ids(parse(asrep("bob", pre="2"), asrep("alice", pre="15"))) == []


# --- spraying regression ----------------------------------------------------

def test_low_and_slow_spray_one_guess_per_account_is_detected():
    # 6 accounts, one guess each: never reaches the brute force count of 10
    events = [Event(T0 + timedelta(seconds=i * 10), "test", ev.AUTH_FAILURE, "DC01", f"user{i}", "10.0.0.5", "x")
              for i in range(6)]
    assert ids(events) == ["AUTH-002"]


def test_spray_needs_distinct_accounts_inside_the_window():
    # 6 accounts but 10 minutes apart: no 5 inside any 5-minute window
    events = [Event(T0 + timedelta(minutes=i * 10), "test", ev.AUTH_FAILURE, "DC01", f"user{i}", "10.0.0.5", "x")
              for i in range(6)]
    assert ids(events) == []


# --- sample and CLI ---------------------------------------------------------

def test_dc_sample_scenario():
    alerts = run_all(parse_file(SAMPLES / "dc01_security.jsonl"))
    assert sorted(a.rule_id for a in alerts) == ["AUTH-002", "KERB-001", "KERB-002"]
    spray = next(a for a in alerts if a.rule_id == "AUTH-002")
    assert spray.src_ip == "10.20.4.17" and spray.count == 8


def test_cli_kerberoast_threshold(tmp_path):
    out = tmp_path / "a.json"
    sample = str(SAMPLES / "dc01_security.jsonl")
    main(["scan", sample, "--output", "json", "--out-file", str(out)])
    assert "KERB-001" in out.read_text(encoding="utf-8")
    main(["scan", sample, "--output", "json", "--out-file", str(out), "--kerb-services", "5"])
    assert "KERB-001" not in out.read_text(encoding="utf-8")
