"""
SentinelShield - Threat Detection Models
Data structures for threat classification, rule matching, and security decisions.
"""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional, Dict, Any
from datetime import datetime, timezone
import uuid


class RuleCategory(str, Enum):
    SQL_INJECTION = "SQL Injection (SQLi)"
    XSS = "Cross-Site Scripting (XSS)"
    LFI = "Local File Inclusion / Path Traversal"
    COMMAND_INJECTION = "Remote Command Injection (RCE)"
    SCANNER_PROBE = "Automated Scanner / Reconnaissance"
    RATE_LIMIT_EXCEEDED = "Rate Limiting / Abusive Traffic"
    ANOMALOUS_REQUEST = "Anomalous Request Structure"


class DecisionAction(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    RATE_LIMIT_BLOCK = "RATE_LIMIT_BLOCK"
    FLAG = "FLAG"


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class SecurityAlert:
    alert_id: str = field(default_factory=lambda: f"ALRT-{uuid.uuid4().hex[:8].upper()}")
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    client_ip: str = "127.0.0.1"
    method: str = "GET"
    path: str = "/"
    target_component: str = "query"  # query, header, body, path
    trigger_value: str = ""
    rule_id: str = "GENERIC-000"
    rule_name: str = "Unknown Rule"
    category: str = RuleCategory.ANOMALOUS_REQUEST.value
    severity: str = Severity.MEDIUM.value
    action: str = DecisionAction.BLOCK.value
    http_status: int = 403
    extra_details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class InspectionResult:
    allowed: bool
    action: DecisionAction
    http_status: int = 200
    alert: Optional[SecurityAlert] = None
    message: str = "Request clean and authorized."

    def to_dict(self) -> Dict[str, Any]:
        return {
            "allowed": self.allowed,
            "action": self.action.value,
            "http_status": self.http_status,
            "message": self.message,
            "alert": self.alert.to_dict() if self.alert else None
        }
