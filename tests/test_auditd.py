from datetime import datetime, timezone
from pathlib import Path

from soc_triage import events as ev
from soc_triage.detections import run_all
from soc_triage.parsers import detect_format, parse_audit_log, parse_file

SAMPLES = Path(__file__).resolve().parent.parent / "sample_logs"

FAILED_AUTH = ("type=USER_AUTH msg=audit(1794282000.123:501): pid=1 uid=0 auid=4294967295 ses=4294967295 "
               "msg='op=PAM:authentication grantors=? acct=\"root\" exe=\"/usr/sbin/sshd\" "
               "hostname=203.0.113.5 addr=203.0.113.5 terminal=ssh res=failed'")
FAILED_LOGIN = FAILED_AUTH.replace("USER_AUTH", "USER_LOGIN").replace("op=PAM:authentication grantors=? ", "op=login ")
OK_LOGIN = FAILED_LOGIN.replace("res=failed", "res=success")


def test_failed_auth_is_one_failure_not_two():
    events = list(parse_audit_log([FAILED_AUTH, FAILED_LOGIN]))
    assert [e.event_type for e in events] == [ev.AUTH_FAILURE]
    e = events[0]
    assert (e.user, e.src_ip, e.source) == ("root", "203.0.113.5", "linux-auditd")
    assert e.timestamp == datetime.fromtimestamp(1794282000.123, tz=timezone.utc)


def test_successful_login_and_node_prefix():
    (e,) = parse_audit_log(["node=web09 " + OK_LOGIN])
    assert e.event_type == ev.AUTH_SUCCESS and e.host == "web09"


def test_hex_encoded_account_is_decoded():
    line = ("type=ADD_USER msg=audit(1794282000.000:9): pid=1 uid=0 auid=0 ses=1 "
            f"msg='op=add-user acct={'evil user'.encode().hex().upper()} exe=\"/usr/sbin/useradd\" res=success'")
    (e,) = parse_audit_log([line])
    assert e.event_type == ev.ACCOUNT_CREATED and e.user == "evil user"


def test_group_add_is_parsed_and_deduplicated():
    line = ("type=USER_MGMT msg=audit(1794282000.000:9): pid=1 uid=0 auid=0 ses=1 "
            "msg='op=add-user-to-group grp=\"sudo\" acct=\"bob\" exe=\"/usr/sbin/usermod\" res=success'")
    events = list(parse_audit_log([line, line.replace(":9)", ":10)")]))
    assert len(events) == 1
    assert events[0].event_type == ev.GROUP_MEMBER_ADDED and events[0].extra["group"] == "sudo"


def test_failed_account_changes_and_other_records_are_ignored():
    lines = [
        "type=ADD_USER msg=audit(1794282000.000:9): msg='op=add-user acct=\"x\" res=failed'",
        "type=SYSCALL msg=audit(1794282000.000:9): arch=c000003e syscall=59 success=yes",
        "not an audit line",
    ]
    assert list(parse_audit_log(lines)) == []


def test_enriched_format_suffix_is_ignored():
    (e,) = parse_audit_log([FAILED_AUTH + '\x1dUID="root" AUID="unset"'])
    assert e.user == "root"


def test_auto_detects_auditd(tmp_path):
    assert detect_format(Path("audit.log"), "type=USER_AUTH msg=audit(1:1): x") == "auditd"
    assert detect_format(Path("audit.log"), "node=a type=USER_AUTH msg=audit(1:1): x") == "auditd"
    assert detect_format(Path("auth.log"), "Nov 10 08:00:01 web01 sshd[1]: x") == "auth-log"


def test_auditd_sample_scenario_existing_rules_work_unchanged():
    alerts = run_all(parse_file(SAMPLES / "audit.log"))
    assert sorted(a.rule_id for a in alerts) == ["ACCT-001", "ACCT-003", "AUTH-001", "AUTH-003"]
    new_admin = next(a for a in alerts if a.rule_id == "ACCT-003")
    assert new_admin.user == "systemd-sync" and new_admin.host == "web02"
    brute = next(a for a in alerts if a.rule_id == "AUTH-001")
    assert brute.count == 14  # not 28: USER_LOGIN failures are not double counted
