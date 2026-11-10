import json
from pathlib import Path

import pytest

from soc_triage import events as ev
from soc_triage.detections import run_all
from soc_triage.parsers import parse_file, parse_windows_json

SAMPLES = Path(__file__).resolve().parent.parent / "sample_logs"
WORD = "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"
PS = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"


def sysmon(event_id, **fields):
    record = {"EventID": event_id, "Channel": "Microsoft-Windows-Sysmon/Operational",
              "Computer": "WS1", "UtcTime": "2026-11-10 09:00:00.000", "User": "CORP\\u", **fields}
    return list(parse_windows_json(json.dumps(record)))


def ids(events):
    return sorted(a.rule_id for a in run_all(events))


def test_sysmon_process_create_is_parsed():
    (e,) = sysmon(1, Image=PS, ParentImage=WORD, CommandLine="powershell -c x")
    assert e.event_type == ev.PROCESS_CREATED and e.source == "windows-sysmon"
    assert e.user == "u"  # domain stripped
    assert e.extra["parent_image"] == WORD


def test_sysmon_detected_without_channel_when_image_present():
    record = {"EventID": 3, "UtcTime": "2026-11-10 09:00:00", "Image": PS, "DestinationIp": "203.0.113.9"}
    (e,) = parse_windows_json(json.dumps(record))
    assert e.event_type == ev.NETWORK_CONNECTION


def test_security_1102_is_not_mistaken_for_sysmon():
    (e,) = parse_windows_json(json.dumps({"EventID": 1102, "TimeCreated": "2026-11-10T09:00:00Z"}))
    assert e.event_type == ev.LOG_CLEARED


@pytest.mark.parametrize("child", ["powershell.exe", "cmd.exe", "mshta.exe", "wscript.exe", "rundll32.exe"])
def test_office_spawning_script_host_alerts(child):
    assert ids(sysmon(1, Image=f"C:\\Windows\\System32\\{child}", ParentImage=WORD, CommandLine=child)) == ["EXEC-002"]


def test_office_spawning_normal_child_is_quiet():
    assert ids(sysmon(1, Image="C:\\Windows\\splwow64.exe", ParentImage=WORD, CommandLine="splwow64 8192")) == []


def test_cmd_from_explorer_is_quiet():
    assert ids(sysmon(1, Image="C:\\Windows\\System32\\cmd.exe", ParentImage="C:\\Windows\\explorer.exe")) == []


def test_powershell_to_external_ip_alerts_and_groups():
    events = sysmon(3, Image=PS, DestinationIp="198.51.100.23", DestinationPort=80) * 3
    alerts = run_all(events)
    assert [a.rule_id for a in alerts] == ["NET-001"]
    assert alerts[0].count == 3


def test_powershell_to_internal_ip_is_quiet():
    assert ids(sysmon(3, Image=PS, DestinationIp="10.0.0.5", DestinationPort=5985)) == []


def test_browser_to_external_ip_is_quiet():
    assert ids(sysmon(3, Image="C:\\Program Files\\Edge\\msedge.exe", DestinationIp="198.51.100.23")) == []


def test_office_dropping_script_is_high():
    (alert,) = run_all(sysmon(11, Image=WORD, TargetFilename="C:\\Users\\u\\AppData\\Local\\Temp\\a.vbs"))
    assert alert.rule_id == "FILE-001" and alert.severity == "high"


def test_powershell_dropping_exe_is_medium():
    (alert,) = run_all(sysmon(11, Image=PS, TargetFilename="C:\\Users\\u\\AppData\\Local\\Temp\\update.exe"))
    assert alert.rule_id == "FILE-001" and alert.severity == "medium"


@pytest.mark.parametrize("target", ["C:\\Users\\u\\Documents\\budget.docx", "C:\\Users\\u\\Recent\\x.lnk",
                                    "C:\\Temp\\noextension"])
def test_office_saving_documents_is_quiet(target):
    assert ids(sysmon(11, Image=WORD, TargetFilename=target)) == []


def test_sysmon_sample_scenario():
    alerts = ids(parse_file(SAMPLES / "sysmon.jsonl"))
    assert alerts == sorted(["EXEC-001", "EXEC-002", "NET-001", "FILE-001", "FILE-001"])
