# Detection rules

Every rule works on normalized events (see `soc_triage/events.py`), so the same logic covers Linux `sshd` logs and Windows Security events.

| ID | Rule | Severity | ATT&CK | Data sources |
|---|---|---|---|---|
| AUTH-001 | Brute force against account(s) | medium | T1110.001 | sshd `Failed password`, Windows 4625 |
| AUTH-002 | Password spraying from single source | high | T1110.003 | sshd `Failed password`, Windows 4625 |
| AUTH-003 | Successful login after repeated failures | high / critical | T1110, T1078 | failures + sshd `Accepted`, Windows 4624 |
| ACCT-001 | Local account created | medium | T1136.001 | `useradd`, Windows 4720 |
| ACCT-002 | Account added to privileged group | high | T1098 | `usermod`/`gpasswd`, Windows 4728/4732/4756 |
| ACCT-003 | Newly created account added to privileged group | critical | T1098, T1136.001 | correlation of ACCT-001 + ACCT-002 |
| EXEC-001 | Encoded PowerShell command | medium / high | T1059.001, T1027 | Windows 4688 with command line auditing |
| EVADE-001 | Security event log cleared | high | T1070.001 | Windows 1102 |

## Logic and tuning

**AUTH-001 / AUTH-002.** Failures are grouped per source IP into bursts (a new burst starts after a gap longer than the window). A burst alerts when at least `--bf-count` failures (default 10) fall inside any `--bf-window` minute window (default 5). If the burst hits `--spray-users` distinct usernames (default 5) it is reported as spraying instead, because many accounts with a few guesses each is designed to stay under per-account lockout.

*False positives:* a misconfigured service retrying an old password; vulnerability scanners. *Gaps:* slow, distributed attacks from many IPs (low and slow) will not reach the per-IP threshold.

**AUTH-003.** A successful logon from an IP that produced at least 5 failures in the previous 30 minutes. Critical when the failures targeted the same account that then logged in. This is the alert to escalate first: it suggests the guessing worked.

*False positives:* a user who forgot their password and then got it right from a shared NAT IP. Five failures is a deliberately high bar for that.

**Allow-lists and source scope.** Auth alerts (AUTH-*) from sources in `--allow-ip` / `--allow-file` are dropped, which is how you stop a vulnerability scanner or a jump host from paging the SOC every night. Account and process alerts are never suppressed by IP. Every source IP is tagged internal or external using an explicit range list (not Python's `is_private`, which also counts documentation ranges as private). AUTH-003 from an external source is always critical.

**ACCT-001 to ACCT-003.** Any new account is worth a look; an account that becomes a member of a privileged group (Administrators, Domain Admins, sudo, wheel and others in `PRIVILEGED_GROUPS`) within 60 minutes of being created is a classic attacker persistence step and is raised as critical.

*False positives:* IT onboarding scripts. Allow-list the provisioning account in your SIEM rather than lowering severity.

**EXEC-001.** `powershell.exe` or `pwsh.exe` started with any abbreviation of `-EncodedCommand` (`-e`, `-en`, `-enc`, ..., plus `-ec`). The regex intentionally does not match `-ex` (`-ExecutionPolicy`). The Base64 payload is decoded from UTF-16LE and shown to the analyst; severity goes to high if the decoded script contains download or execution keywords such as `DownloadString`, `IEX`, `Net.WebClient` or `-nop`.

*False positives:* some management agents (SCCM, some RMM tools) use encoded commands. Check the parent process.
*Requirement:* Windows "Include command line in process creation events" must be enabled, or 4688 has no command line.

**EVADE-001.** Event 1102 means the Security log was cleared. Legitimate clears are rare and should be change-managed, so every one is worth an analyst's time. Look at what happened on the host just before it.
