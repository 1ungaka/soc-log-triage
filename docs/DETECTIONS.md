# Detection rules

ATT&CK IDs follow ATT&CK v20.1. Sigma versions of these rules are in [../sigma](../sigma/README.md).

Every rule works on normalized events (see `soc_triage/events.py`), so the same logic covers Linux `sshd` and `auditd` logs, Windows Security events and Sysmon.

| ID | Rule | Severity | ATT&CK | Data sources |
|---|---|---|---|---|
| AUTH-001 | Brute force against account(s) | medium | T1110.001 | sshd `Failed password`, auditd `USER_AUTH`, Windows 4625, DC 4771 (0x18) |
| AUTH-002 | Password spraying from single source | high | T1110.003 | sshd `Failed password`, auditd `USER_AUTH`, Windows 4625, DC 4771 (0x18) |
| AUTH-003 | Successful login after repeated failures | high / critical | T1110, T1078 | failures + sshd `Accepted`, auditd `USER_LOGIN`, Windows 4624 |
| ACCT-001 | Local account created | medium | T1136.001 | `useradd`, auditd `ADD_USER`, Windows 4720 |
| ACCT-002 | Account added to privileged group | high | T1098 | `usermod`/`gpasswd`, auditd `USER_MGMT`, Windows 4728/4732/4756 |
| ACCT-003 | Newly created account added to privileged group | critical | T1098, T1136.001 | correlation of ACCT-001 + ACCT-002 |
| EXEC-001 | Encoded PowerShell command | medium / high | T1059.001, T1027 | Windows 4688 with command line auditing, Sysmon 1 |
| EXEC-002 | Office application spawned a shell or script host | high | T1204.002, T1566.001 | Windows 4688, Sysmon 1 |
| NET-001 | Script host connected to external address | medium | T1105, T1071.001 | Sysmon 3 |
| FILE-001 | Executable or script written by Office or a script host | medium / high | T1105, T1204.002 | Sysmon 11 |
| KERB-001 | Possible Kerberoasting | high | T1558.003 | DC 4769 |
| KERB-002 | Kerberos TGT issued without pre-authentication | medium / high | T1558.004 | DC 4768 |
| EVADE-001 | Security event log cleared | high | T1685.005 | Windows 1102 |

## Logic and tuning

**AUTH-001 / AUTH-002.** Failures are grouped per source IP into bursts (a new burst starts after a gap longer than the window). A burst alerts when at least `--bf-count` failures (default 10) fall inside any `--bf-window` minute window (default 5). Spraying is judged separately on **distinct accounts**: if at least `--spray-users` usernames (default 5) are tried inside one window it is AUTH-002, however few attempts there were. A careful sprayer makes one guess per account to stay under lockout, so a volume threshold alone misses them (this was a real gap, found while adding Kerberos, and is now covered by a regression test).

Kerberos pre-authentication failures with status `0x18` (wrong password, event 4771) count as auth failures, so spraying against a domain controller is caught even though it never writes a 4625.

*False positives:* a misconfigured service retrying an old password; vulnerability scanners. *Gaps:* slow, distributed attacks from many IPs (low and slow) will not reach the per-IP threshold.

**AUTH-003.** A successful logon from an IP that produced at least 5 failures in the previous 30 minutes. Critical when the failures targeted the same account that then logged in. This is the alert to escalate first: it suggests the guessing worked.

*False positives:* a user who forgot their password and then got it right from a shared NAT IP. Five failures is a deliberately high bar for that.

**Allow-lists and source scope.** Auth alerts (AUTH-*) from sources in `--allow-ip` / `--allow-file` are dropped, which is how you stop a vulnerability scanner or a jump host from paging the SOC every night. Account and process alerts are never suppressed by IP. Every source IP is tagged internal or external using an explicit range list (not Python's `is_private`, which also counts documentation ranges as private). AUTH-003 from an external source is always critical.

**ACCT-001 to ACCT-003.** Any new account is worth a look; an account that becomes a member of a privileged group (Administrators, Domain Admins, sudo, wheel and others in `PRIVILEGED_GROUPS`) within 60 minutes of being created is a classic attacker persistence step and is raised as critical.

*False positives:* IT onboarding scripts. Allow-list the provisioning account in your SIEM rather than lowering severity.

**EXEC-001.** `powershell.exe` or `pwsh.exe` started with any abbreviation of `-EncodedCommand` (`-e`, `-en`, `-enc`, ..., plus `-ec`). The regex intentionally does not match `-ex` (`-ExecutionPolicy`). The Base64 payload is decoded from UTF-16LE and shown to the analyst; severity goes to high if the decoded script contains download or execution keywords such as `DownloadString`, `IEX`, `Net.WebClient` or `-nop`.

*False positives:* some management agents (SCCM, some RMM tools) use encoded commands. Check the parent process.
*Requirement:* Windows "Include command line in process creation events" must be enabled, or 4688 has no command line.

**EXEC-002.** The parent is an Office app (Word, Excel, PowerPoint, Outlook, Access, Publisher, OneNote, Visio) and the child is a shell, script host or common LOLBin (`cmd`, `powershell`, `pwsh`, `wscript`, `cscript`, `mshta`, `rundll32`, `regsvr32`, `certutil`, `bitsadmin`, `msiexec`). This is one of the highest-value endpoint detections for phishing.

*False positives:* some legacy add-ins and macros used by finance teams. Allow-list by command line, not by parent.

**NET-001.** A script host or LOLBin from the list above makes a network connection to an external address (see source scope above). Connections are grouped per host, process, destination and port, so a beaconing process produces one alert with a count rather than hundreds.

*False positives:* admin scripts that call public APIs or package feeds. *Gaps:* malware that injects into a browser or other allowed process will not be seen by image name.

**FILE-001.** Sysmon 11 shows an Office app or script host writing a file with an executable or script extension (`.exe`, `.dll`, `.ps1`, `.vbs`, `.js`, `.hta`, `.bat`, `.msi` and others). High when the writer is Office, because documents dropping scripts is almost never legitimate; medium for script hosts, which installers and admin tooling also do.

**KERB-001.** Successful 4769 service tickets with RC4 encryption (`0x17` or `0x18`) for at least `--kerb-services` (default 3) distinct services, requested by one account within 10 minutes. RC4 tickets are encrypted with the service account's password hash and can be cracked offline, which is why attackers request them in bulk. Computer accounts (`$`) and `krbtgt` are excluded: their passwords are random and long, and their tickets are requested constantly.

*False positives:* legacy applications that only support RC4. The real fix is to set those service accounts to AES only. *Gaps:* an attacker who requests AES tickets, or one ticket at a time over days, will not trip the threshold; pair this with honeypot service accounts.

**KERB-002.** Successful 4768 TGTs with `PreAuthType` 0, grouped per source IP; high when one source collects two or more such accounts. Accounts with "Do not require Kerberos pre-authentication" set return a reply that can be cracked offline without any password.

*False positives:* the few legacy accounts that genuinely need pre-auth disabled. List them, and every other hit is worth a look.

**EVADE-001.** Event 1102 means the Security log was cleared. Legitimate clears are rare and should be change-managed, so every one is worth an analyst's time. Look at what happened on the host just before it.
