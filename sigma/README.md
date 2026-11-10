# Sigma rules

The detections from `soc_triage/detections.py`, published in [Sigma](https://github.com/SigmaHQ/sigma-specification) so they can be converted for Splunk, Elastic, Microsoft Sentinel, QRadar and other SIEMs.

| File | Rule | ATT&CK |
|---|---|---|
| `windows/proc_creation_win_powershell_encoded_command.yml` | EXEC-001 | T1059.001, T1027 |
| `windows/proc_creation_win_office_spawn_script_host.yml` | EXEC-002 | T1204.002, T1566.001 |
| `windows/net_connection_win_script_host_external.yml` | NET-001 | T1105, T1071.001 |
| `windows/file_event_win_office_drop_executable.yml` | FILE-001 (Office writer) | T1204.002, T1105 |
| `windows/win_security_local_account_created.yml` | ACCT-001 | T1136.001 |
| `windows/win_security_privileged_group_member_added.yml` | ACCT-002 | T1098 |
| `windows/win_security_log_cleared.yml` | EVADE-001 | T1685.005 |
| `windows/win_security_failed_logon_correlations.yml` | AUTH-001, AUTH-002 (Sigma correlation rules) | T1110.001, T1110.003 |
| `linux/lnx_auditd_user_added.yml` | ACCT-001 | T1136.001 |
| `linux/lnx_auditd_user_added_to_privileged_group.yml` | ACCT-002 | T1098 |

**Not in Sigma:** AUTH-003 (login *after* N failures) and ACCT-003 (account created *then* made admin) need ordered, cross-event logic with different field names on each side. They stay in the Python engine.

Tags follow MITRE ATT&CK v20.1, where Defense Evasion was split into Stealth and Defense Impairment, and clearing Windows event logs moved from T1070.001 to T1685.005.

## Use them

```bash
pip install sigma-cli
sigma plugin install splunk
sigma check sigma/
sigma convert -t splunk --without-pipeline sigma/
```

For Sysmon data in Splunk use `-p sysmon` in place of `--without-pipeline`; for Elastic, install the `elasticsearch` plugin and use `-t lucene` or `-t eql`.

CI runs `sigma check --fail-on-issues` and a Splunk conversion on every push, so a broken rule fails the build. `tests/test_sigma.py` checks that each Sigma rule's ATT&CK tags match the Python rule it mirrors.
