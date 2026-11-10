"""Normalized event model shared by every parser and detection."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

# Normalized event types
AUTH_FAILURE = "auth_failure"
AUTH_SUCCESS = "auth_success"
ACCOUNT_CREATED = "account_created"
GROUP_MEMBER_ADDED = "group_member_added"
PROCESS_CREATED = "process_created"
LOG_CLEARED = "log_cleared"
NETWORK_CONNECTION = "network_connection"
FILE_CREATED = "file_created"
TGS_REQUEST = "kerberos_tgs_request"  # 4769 service ticket
TGT_REQUEST = "kerberos_tgt_request"  # 4768 ticket granting ticket


@dataclass(frozen=True)
class Event:
    timestamp: datetime
    source: str  # "linux-auth" or "windows-security"
    event_type: str
    host: str = ""
    user: str = ""
    src_ip: str = ""
    raw: str = ""
    extra: dict = field(default_factory=dict, hash=False, compare=False)
