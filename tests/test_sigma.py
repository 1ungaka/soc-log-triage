"""Keep sigma/ in step with the Python detections (no YAML dependency needed).

Full Sigma validation and Splunk conversion run in CI with sigma-cli.
"""

import re
from datetime import datetime, timezone
from pathlib import Path

from soc_triage import events as ev
from soc_triage.detections import run_all
from soc_triage.events import Event
from soc_triage.parsers import parse_file

ROOT = Path(__file__).resolve().parent.parent
SIGMA_FILES = sorted((ROOT / "sigma").rglob("*.yml"))
MARKER = re.compile(r"soc-log-triage rule ([A-Z]+-\d{3})")
TAG = re.compile(r"^\s*- attack\.(t\d{4}(?:\.\d{3})?)\s*$", re.M)
UUID = re.compile(r"^id: ([0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$", re.M)


def sigma_docs():
    for path in SIGMA_FILES:
        for doc in path.read_text(encoding="utf-8").split("\n---\n"):
            yield path, doc


def python_techniques() -> dict[str, set[str]]:
    events = []
    for sample in sorted((ROOT / "sample_logs").iterdir()):
        events += parse_file(sample, year=2026)
    # ACCT-002 (existing account made admin) is not in the samples
    events.append(Event(datetime(2026, 1, 1, tzinfo=timezone.utc), "test", ev.GROUP_MEMBER_ADDED,
                        "h", "sam", "", "x", {"group": "Administrators"}))
    mapping: dict[str, set[str]] = {}
    for alert in run_all(events):
        mapping.setdefault(alert.rule_id, set()).update(tid.lower() for tid, _ in alert.mitre)
    return mapping


def test_sigma_folder_is_not_empty():
    assert len(SIGMA_FILES) >= 9


def test_every_sigma_rule_has_unique_uuid():
    ids = [m for _, doc in sigma_docs() for m in UUID.findall(doc)]
    docs = list(sigma_docs())
    assert len(ids) == len(docs), "every Sigma document needs a v4 UUID id"
    assert len(set(ids)) == len(ids)


def test_sigma_tags_match_python_rule_techniques():
    py = python_techniques()
    covered = set()
    for path, doc in sigma_docs():
        m = MARKER.search(doc)
        if not m:
            continue  # base rules used only by correlations
        rule_id = m.group(1)
        covered.add(rule_id)
        assert rule_id in py, f"{path.name} refers to unknown rule {rule_id}"
        assert set(TAG.findall(doc)) == py[rule_id], f"{path.name} ATT&CK tags differ from {rule_id}"
    # Rules that need cross-event sequencing are documented as not expressible in Sigma
    assert set(py) - covered == {"AUTH-003", "ACCT-003"}
