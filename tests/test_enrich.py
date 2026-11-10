from datetime import datetime, timedelta, timezone

import pytest

from soc_triage import events as ev
from soc_triage.cli import main
from soc_triage.detections import run_all
from soc_triage.enrich import ip_scope, is_allowed, parse_allow_list
from soc_triage.events import Event

T0 = datetime(2026, 11, 10, 8, 0, tzinfo=timezone.utc)


def _auth(kind, ip, user, s):
    return Event(T0 + timedelta(seconds=s), "test", kind, "h", user, ip, f"{kind} {user} {ip}")


def brute(ip, n=12, user="root"):
    return [_auth(ev.AUTH_FAILURE, ip, user, i) for i in range(n)]


@pytest.mark.parametrize("ip,scope", [
    ("10.1.2.3", "internal"), ("172.20.0.5", "internal"), ("192.168.1.1", "internal"),
    ("100.64.0.9", "internal"), ("127.0.0.1", "internal"), ("fe80::1", "internal"), ("fd00::5", "internal"),
    ("203.0.113.45", "external"), ("8.8.8.8", "external"), ("2001:db8::1", "external"),
    ("172.32.0.1", "external"), ("::ffff:10.0.0.1", "internal"), ("not-an-ip", ""), ("", ""),
])
def test_ip_scope(ip, scope):
    assert ip_scope(ip) == scope


def test_allow_list_parses_cidrs_comments_and_blank_lines():
    nets = parse_allow_list(["# scanners", "198.51.100.0/24", "", "192.0.2.10  # jump host", "2001:db8::/32"])
    assert is_allowed("198.51.100.77", nets)
    assert is_allowed("192.0.2.10", nets)
    assert not is_allowed("192.0.2.11", nets)
    assert is_allowed("2001:db8::5", nets)
    assert not is_allowed("", nets)


def test_allow_list_rejects_bad_entry_with_line_number():
    with pytest.raises(ValueError, match="line 2"):
        parse_allow_list(["10.0.0.0/8", "10.0.0.300"])


def test_allowed_source_suppresses_auth_alerts_only():
    events = brute("198.51.100.7")
    assert [a.rule_id for a in run_all(events)] == ["AUTH-001"]
    assert run_all(events, allow=parse_allow_list(["198.51.100.0/24"])) == []


def test_scope_is_recorded_on_alert():
    (alert,) = run_all(brute("10.0.0.8"))
    assert alert.details["src_ip_scope"] == "internal"


def test_external_success_after_failures_is_always_critical():
    # failures against other accounts, then success: normally "high"
    events = [_auth(ev.AUTH_FAILURE, "10.0.0.8", f"u{i}", i) for i in range(6)] + [_auth(ev.AUTH_SUCCESS, "10.0.0.8", "bob", 10)]
    internal = [a for a in run_all(events) if a.rule_id == "AUTH-003"][0]
    assert internal.severity == "high"

    events = [_auth(ev.AUTH_FAILURE, "203.0.113.8", f"u{i}", i) for i in range(6)] + [_auth(ev.AUTH_SUCCESS, "203.0.113.8", "bob", 10)]
    external = [a for a in run_all(events) if a.rule_id == "AUTH-003"][0]
    assert external.severity == "critical"
    assert "external" in external.description


def test_cli_allow_file(tmp_path, capsys):
    log = tmp_path / "auth.log"
    log.write_text("".join(
        f"Nov 10 08:00:{i:02d} web01 sshd[1]: Failed password for root from 198.51.100.9 port 1 ssh2\n"
        for i in range(12)), encoding="utf-8")
    allow = tmp_path / "allow.txt"
    allow.write_text("198.51.100.9  # internal scanner\n", encoding="utf-8")

    assert main(["scan", str(log), "--year", "2026", "--fail-on", "medium"]) == 1
    assert main(["scan", str(log), "--year", "2026", "--fail-on", "medium", "--allow-file", str(allow)]) == 0
    assert main(["scan", str(log), "--year", "2026", "--allow-ip", "300.1.1.1"]) == 2
