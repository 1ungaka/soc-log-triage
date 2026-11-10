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
