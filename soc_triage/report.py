"""Render alerts as terminal text, JSON, or a Markdown triage report."""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone

from .detections import Alert

_COLORS = {"critical": "\033[1;41m", "high": "\033[1;31m", "medium": "\033[33m", "low": "\033[36m"}
_RESET = "\033[0m"


def _ip(a: Alert) -> str:
    scope = a.details.get("src_ip_scope")
    return f"{a.src_ip} ({scope})" if a.src_ip and scope else a.src_ip


def to_text(alerts: list[Alert], color: bool = False) -> str:
    if not alerts:
        return "No alerts."
    lines = []
    for a in alerts:
        sev = a.severity.upper()
        if color:
            sev = f"{_COLORS[a.severity]}{sev}{_RESET}"
        mitre = ", ".join(tid for tid, _ in a.mitre)
        lines.append(f"[{sev}] {a.rule_id} {a.title}  ({mitre})")
        lines.append(f"    when : {a.first_seen:%Y-%m-%d %H:%M:%S} -> {a.last_seen:%H:%M:%S} UTC  x{a.count}")
        who = "  ".join(f"{k}={v}" for k, v in (("host", a.host), ("user", a.user), ("src_ip", _ip(a))) if v)
        if who:
            lines.append(f"    who  : {who}")
        lines.append(f"    what : {a.description}")
        if a.details.get("decoded_command"):
            lines.append(f"    decoded: {a.details['decoded_command']}")
        lines.append("")
    counts = Counter(a.severity for a in alerts)
    lines.append("Summary: " + ", ".join(f"{counts[s]} {s}" for s in ("critical", "high", "medium", "low") if counts[s]))
    return "\n".join(lines)


def to_json(alerts: list[Alert]) -> str:
    return json.dumps([a.to_dict() for a in alerts], indent=2)


def to_markdown(alerts: list[Alert], sources: list[str], event_count: int) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    counts = Counter(a.severity for a in alerts)
    out = [
        "# Log triage report",
        "",
        f"Generated {now} from {event_count} security events in: {', '.join(f'`{s}`' for s in sources)}",
        "",
        "| Severity | Alerts |",
        "|---|---|",
        *[f"| {s} | {counts[s]} |" for s in ("critical", "high", "medium", "low")],
        "",
    ]
    if not alerts:
        out.append("No alerts were raised.")
        return "\n".join(out) + "\n"

    techniques = Counter((tid, name) for a in alerts for tid, name in a.mitre)
    out += ["## MITRE ATT&CK coverage", "", "| Technique | Name | Alerts |", "|---|---|---|"]
    out += [f"| [{tid}](https://attack.mitre.org/techniques/{tid.replace('.', '/')}/) | {name} | {n} |"
            for (tid, name), n in sorted(techniques.items())]
    out += ["", "## Alerts", ""]
    for i, a in enumerate(alerts, 1):
        out += [
            f"### {i}. [{a.severity.upper()}] {a.title} ({a.rule_id})",
            "",
            f"- **Time:** {a.first_seen:%Y-%m-%d %H:%M:%S} to {a.last_seen:%Y-%m-%d %H:%M:%S} UTC ({a.count} events)",
        ]
        for label, value in (("Host", a.host), ("User", a.user), ("Source IP", a.src_ip)):
            if value:
                scope = a.details.get("src_ip_scope") if label == "Source IP" else ""
                out.append(f"- **{label}:** `{value}`" + (f" ({scope})" if scope else ""))
        out.append(f"- **ATT&CK:** {', '.join(f'{tid} {name}' for tid, name in a.mitre)}")
        out += ["", a.description, ""]
        if a.details.get("decoded_command"):
            out += ["Decoded command:", "", "```powershell", a.details["decoded_command"], "```", ""]
        if a.evidence:
            out += ["<details><summary>Evidence</summary>", "", "```", *a.evidence, "```", "", "</details>", ""]
    return "\n".join(out) + "\n"
