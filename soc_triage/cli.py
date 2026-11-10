"""Command line entry point: python -m soc_triage scan <files...>"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .detections import SEVERITY_ORDER, Thresholds, run_all
from .enrich import load_allow_file, parse_allow_list
from .parsers import FORMATS, parse_file
from .report import to_json, to_markdown, to_text


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="soc-triage", description="Triage auth and endpoint logs into ATT&CK-mapped alerts.")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan one or more log files")
    scan.add_argument("files", nargs="+", type=Path)
    scan.add_argument("--format", choices=["auto", *FORMATS], default="auto",
                      help="input format (default: guess from file)")
    scan.add_argument("--year", type=int, help="year for classic syslog timestamps (default: current year)")
    scan.add_argument("--output", choices=["text", "json", "markdown"], default="text")
    scan.add_argument("--out-file", type=Path, help="write the report here instead of stdout")
    scan.add_argument("--min-severity", choices=list(SEVERITY_ORDER), default="low")
    scan.add_argument("--fail-on", choices=list(SEVERITY_ORDER),
                      help="exit with code 1 if any alert is at or above this severity (for CI/automation)")
    scan.add_argument("--allow-ip", action="append", default=[], metavar="IP_OR_CIDR",
                      help="trusted source to suppress auth alerts for (repeatable)")
    scan.add_argument("--allow-file", type=Path, help="file of trusted IPs/CIDRs, one per line, # comments")
    t = Thresholds()
    scan.add_argument("--bf-count", type=int, default=t.brute_force_count, help="failures that count as brute force")
    scan.add_argument("--bf-window", type=int, default=t.brute_force_window_min, help="brute force window in minutes")
    scan.add_argument("--spray-users", type=int, default=t.spray_distinct_users,
                      help="distinct users that make a burst password spraying")
    scan.add_argument("--kerb-services", type=int, default=t.kerberoast_services,
                      help="distinct RC4 service tickets from one account that count as Kerberoasting")
    scan.add_argument("--web-404", type=int, default=t.web_404_count,
                      help="404 responses to one source in 5 minutes that count as directory brute forcing")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    events = []
    for f in args.files:
        if not f.is_file():
            print(f"error: {f} is not a file", file=sys.stderr)
            return 2
        try:
            events += parse_file(f, args.format, args.year)
        except (ValueError, OSError) as exc:
            print(f"error: could not parse {f}: {exc}", file=sys.stderr)
            return 2

    thresholds = Thresholds(brute_force_count=args.bf_count, brute_force_window_min=args.bf_window,
                            spray_distinct_users=args.spray_users, kerberoast_services=args.kerb_services,
                            web_404_count=args.web_404)
    try:
        allow = parse_allow_list(args.allow_ip)
        if args.allow_file:
            allow += load_allow_file(args.allow_file)
    except (ValueError, OSError) as exc:
        print(f"error: allow-list: {exc}", file=sys.stderr)
        return 2

    floor = SEVERITY_ORDER[args.min_severity]
    alerts = [a for a in run_all(events, thresholds, allow) if SEVERITY_ORDER[a.severity] >= floor]

    if args.output == "json":
        rendered = to_json(alerts)
    elif args.output == "markdown":
        rendered = to_markdown(alerts, [f.as_posix() for f in args.files], len(events))
    else:
        rendered = to_text(alerts, color=args.out_file is None and sys.stdout.isatty())

    if args.out_file:
        args.out_file.write_text(rendered, encoding="utf-8")
        print(f"{len(alerts)} alerts from {len(events)} events written to {args.out_file}")
    else:
        print(rendered)

    if args.fail_on and any(SEVERITY_ORDER[a.severity] >= SEVERITY_ORDER[args.fail_on] for a in alerts):
        return 1
    return 0
