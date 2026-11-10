from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from soc_triage import events as ev
from soc_triage.cli import main
from soc_triage.detections import decode_url, run_all
from soc_triage.enrich import parse_allow_list
from soc_triage.parsers import detect_format, parse_file, parse_web_log

SAMPLES = Path(__file__).resolve().parent.parent / "sample_logs"
T0 = datetime(2026, 11, 10, 9, 0, tzinfo=timezone.utc)
BROWSER = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"


def line(target="/", status=200, size=512, ip="203.0.113.7", agent=BROWSER, seconds=0, method="GET"):
    ts = T0 + timedelta(seconds=seconds)
    return f'{ip} - - [{ts:%d/%b/%Y:%H:%M:%S} +0000] "{method} {target} HTTP/1.1" {status} {size} "-" "{agent}"'


def scan(*lines):
    return run_all(list(parse_web_log(lines)))


def ids(*lines):
    return sorted(a.rule_id for a in scan(*lines))


# --- parser ----------------------------------------------------------------

def test_combined_format_fields():
    (e,) = parse_web_log([line("/index.php?id=7", 404, 196)])
    assert e.event_type == ev.HTTP_REQUEST and e.src_ip == "203.0.113.7"
    assert e.timestamp == T0
    assert e.extra["path"] == "/index.php" and e.extra["query"] == "id=7"
    assert (e.extra["status"], e.extra["size"], e.extra["user_agent"]) == (404, 196, BROWSER)


def test_timezone_offset_is_converted_to_utc():
    (e,) = parse_web_log(['192.0.2.1 - - [10/Nov/2026:11:00:00 +0200] "GET / HTTP/1.1" 200 1 "-" "x"'])
    assert e.timestamp == T0 + timedelta(hours=0)  # 11:00 +02:00 is 09:00 UTC


def test_common_format_without_referrer_and_agent():
    (e,) = parse_web_log(['192.0.2.1 - alice [10/Nov/2026:09:00:00 +0000] "GET / HTTP/1.0" 200 -'])
    assert e.user == "alice" and e.extra["size"] == 0 and e.extra["user_agent"] == ""


def test_escaped_quote_in_user_agent():
    (e,) = parse_web_log(['192.0.2.1 - - [10/Nov/2026:09:00:00 +0000] "GET / HTTP/1.1" 200 1 "-" "a \\"b\\" c"'])
    assert e.extra["user_agent"] == 'a \\"b\\" c'


def test_junk_request_line_and_garbage_lines():
    events = list(parse_web_log([
        '192.0.2.1 - - [10/Nov/2026:09:00:00 +0000] "\\x16\\x03\\x01" 400 157 "-" "-"',
        "not a log line",
        '192.0.2.1 - - [99/Nov/2026:09:00:00 +0000] "GET / HTTP/1.1" 200 1 "-" "-"',  # bad date
    ]))
    assert len(events) == 1 and events[0].extra["method"] == "" and events[0].extra["status"] == 400


def test_format_auto_detection():
    assert detect_format(Path("access.log"), line()) == "web-access"
    assert detect_format(Path("auth.log"), "Nov 10 08:00:01 web01 sshd[1]: x") == "auth-log"


# --- WEB-001 404 flood --------------------------------------------------------

def test_404_flood_alerts_and_lists_what_was_found():
    lines = [line(f"/word{i}", 404, 153, seconds=i) for i in range(25)] + [line("/admin", 301, 0, seconds=12)]
    (alert,) = scan(*lines)
    assert alert.rule_id == "WEB-001" and alert.count == 25
    assert alert.details["found"] == ["301 /admin"]


def test_few_404s_are_quiet():
    assert ids(*[line(f"/missing{i}", 404, seconds=i * 30) for i in range(5)]) == []


def test_404s_spread_over_a_day_are_quiet():
    assert ids(*[line(f"/missing{i}", 404, seconds=i * 900) for i in range(30)]) == []


def test_404_threshold_is_tunable(tmp_path):
    log = tmp_path / "access.log"
    log.write_text("\n".join(line(f"/w{i}", 404, seconds=i) for i in range(12)) + "\n", encoding="utf-8")
    assert main(["scan", str(log), "--fail-on", "medium"]) == 0
    assert main(["scan", str(log), "--fail-on", "medium", "--web-404", "10"]) == 1


# --- WEB-002 path traversal -----------------------------------------------------

@pytest.mark.parametrize("target", [
    "/download.php?file=../../etc/passwd",
    "/download.php?file=..%2f..%2fetc%2fpasswd",
    "/download.php?file=%2e%2e%2f%2e%2e%2fsecret.txt",
    "/download.php?file=%252e%252e%252fwin.ini",          # double encoded
    "/download.php?file=..\\..\\windows\\system32\\drivers\\etc\\hosts",
    "/view?page=php://filter/convert.base64-encode/resource=index.php",
    "/static/..%5c..%5cweb.config",
    "/cgi-bin/x?f=/proc/self/environ",
])
def test_traversal_and_lfi_variants_are_detected(target):
    assert ids(line(target, 404)) == ["WEB-002"]


@pytest.mark.parametrize("target", [
    "/files/report..final.pdf",
    "/search?q=what+is+..+in+regex",
    "/blog/2026/11/etc-passwd-explained",
    "/",
])
def test_lookalikes_are_not_traversal(target):
    assert ids(line(target)) == []


def test_traversal_with_content_returned_is_critical():
    (alert,) = scan(line("/dl?f=../../etc/passwd", 200, 1789), line("/dl?f=../../etc/shadow", 403, 10, seconds=5))
    assert alert.severity == "critical" and alert.details["served"] == 1
    assert "/dl?f=../../etc/passwd" in alert.details["decoded_targets"]


def test_traversal_blocked_is_high():
    (alert,) = scan(line("/dl?f=../../etc/passwd", 403, 10))
    assert alert.severity == "high"


def test_decode_url_stops_when_stable():
    assert decode_url("%25252e") == "."
    assert decode_url("plain") == "plain"


# --- WEB-003 scanner user agents ---------------------------------------------------

@pytest.mark.parametrize("agent,tool", [
    ("sqlmap/1.8.11#stable (https://sqlmap.org)", "sqlmap"),
    ("Mozilla/5.00 (Nikto/2.5.0) (Evasions:None)", "nikto"),
    ("gobuster/3.6", "gobuster"),
    ("Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)", "nmap"),
])
def test_scanner_agents_are_detected(agent, tool):
    (alert,) = scan(line(agent=agent))
    assert alert.rule_id == "WEB-003" and alert.details["tools"] == [tool]


def test_one_alert_per_scanner_source():
    alerts = scan(*[line(f"/p{i}", agent="sqlmap/1.8", seconds=i) for i in range(10)])
    assert [a.rule_id for a in alerts] == ["WEB-003"] and alerts[0].count == 10


def test_normal_browsers_and_tools_are_quiet():
    assert ids(line(agent=BROWSER), line(agent="curl/8.5.0"), line(agent="python-requests/2.32")) == []


# --- allow-list and samples ---------------------------------------------------------

def test_allow_listed_scanner_is_suppressed():
    events = list(parse_web_log([line("/x?f=../../etc/passwd", 404, agent="nikto/2.5", ip="10.9.9.9")]))
    assert run_all(events, allow=parse_allow_list(["10.9.9.0/24"])) == []


def test_web_sample_scenario():
    alerts = run_all(parse_file(SAMPLES / "web_access.log"))
    assert sorted(a.rule_id for a in alerts) == ["WEB-001", "WEB-002", "WEB-003", "WEB-003"]
    lfi = next(a for a in alerts if a.rule_id == "WEB-002")
    assert lfi.src_ip == "203.0.113.99" and lfi.severity == "critical"
