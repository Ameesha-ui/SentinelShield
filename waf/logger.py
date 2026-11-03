"""
SentinelShield - Security Event Logging System
Handles dual-format logging (Human-readable audit log & JSON Lines),
event persistence, aggregation, and querying for the SOC dashboard.
"""

import os
import json
import logging
from typing import List, Dict, Any, Optional
from collections import Counter
from datetime import datetime

from .models import SecurityAlert


class SecurityLogger:
    def __init__(self, log_dir: str):
    try:
        os.makedirs(log_dir, exist_ok=True)
        test_file = os.path.join(log_dir, ".write_test")
        with open(test_file, "w", encoding="utf-8"):
            pass
        os.remove(test_file)
    except OSError:
        log_dir = os.path.join("/tmp", "sentinelshield_logs")
        os.makedirs(log_dir, exist_ok=True)

    self.log_dir = log_dir
    self.json_log_path = os.path.join(log_dir, "sentinel_alerts.jsonl")
    self.audit_log_path = os.path.join(log_dir, "sentinel_security.log")
    self.stats_file_path = os.path.join(log_dir, "sentinel_stats.json")


        # In-memory buffer of recent alerts for fast UI updates (max 500)
        self.recent_alerts: List[Dict[str, Any]] = []
        self.total_inspections = 0
        self.total_allowed = 0
        self.total_blocked = 0

        # Setup standard Python file logger for the audit trail
        self.audit_logger = logging.getLogger("SentinelSecurityAudit")
        self.audit_logger.setLevel(logging.INFO)
        # Avoid duplicate handlers if re-instantiated
        if not self.audit_logger.handlers:
            try:
    file_handler = logging.FileHandler(self.audit_log_path, encoding="utf-8")
except OSError:
    file_handler = logging.StreamHandler()
            formatter = logging.Formatter(
                "[%(asctime)s] [%(levelname)s] [SentinelShield] %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S"
            )
            file_handler.setFormatter(formatter)
            self.audit_logger.addHandler(file_handler)

        # Load existing alerts into memory if file exists
        self._load_existing_alerts()

    def _load_existing_alerts(self):
        if os.path.exists(self.json_log_path):
            try:
                with open(self.json_log_path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            try:
                                alert = json.loads(line)
                                self.recent_alerts.append(alert)
                                self.total_blocked += 1
                                self.total_inspections += 1
                            except json.JSONDecodeError:
                                pass
                # Keep last 500
                if len(self.recent_alerts) > 500:
                    self.recent_alerts = self.recent_alerts[-500:]
            except Exception as e:
                print(f"[Warning] Could not load prior logs: {e}")

    def log_clean_request(self, ip: str, method: str, path: str):
        """Records a benign allowed request."""
        self.total_inspections += 1
        self.total_allowed += 1

    def log_security_alert(self, alert: SecurityAlert):
        """Persists a detected threat / blocked request in both JSONL and formatted text."""
        alert_dict = alert.to_dict()
        self.total_inspections += 1
        self.total_blocked += 1

        # 1. Update in-memory buffer
        self.recent_alerts.append(alert_dict)
        if len(self.recent_alerts) > 500:
            self.recent_alerts.pop(0)

        # 2. Append to JSONL file
        try:
            with open(self.json_log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(alert_dict) + "\n")
        except Exception as e:
            print(f"[Logger Error] Failed writing to JSON log: {e}")

        # 3. Write structured audit line
        # Format: [TIMESTAMP] [SEVERITY] IP - ACTION - CATEGORY - RULE_ID - PATH - PAYLOAD
        sanitized_payload = alert.trigger_value.replace("\n", "\\n").replace("\r", "\\r")[:120]
        audit_msg = (
            f"ACTION={alert.action} | SEVERITY={alert.severity} | CLIENT_IP={alert.client_ip} | "
            f"METHOD={alert.method} | PATH={alert.path} | RULE={alert.rule_id} ({alert.rule_name}) | "
            f"CATEGORY='{alert.category}' | TARGET={alert.target_component} | PAYLOAD='{sanitized_payload}'"
        )
        self.audit_logger.warning(audit_msg)

    def get_summary_statistics(self) -> Dict[str, Any]:
        """Calculates real-time aggregation metrics for dashboards and reports."""
        category_counts = Counter(a.get("category", "Unknown") for a in self.recent_alerts)
        severity_counts = Counter(a.get("severity", "Unknown") for a in self.recent_alerts)
        ip_counts = Counter(a.get("client_ip", "Unknown") for a in self.recent_alerts)

        top_ips = [{"ip": ip, "count": count} for ip, count in ip_counts.most_common(5)]
        categories = [{"category": cat, "count": count} for cat, count in category_counts.most_common()]

        block_rate = (self.total_blocked / self.total_inspections * 100) if self.total_inspections > 0 else 0.0

        return {
            "total_inspections": self.total_inspections,
            "total_allowed": self.total_allowed,
            "total_blocked": self.total_blocked,
            "block_rate_percentage": round(block_rate, 2),
            "category_distribution": dict(category_counts),
            "severity_distribution": dict(severity_counts),
            "categories_breakdown": categories,
            "top_flagged_ips": top_ips,
            "recent_alert_count": len(self.recent_alerts)
        }

    def get_recent_alerts(self, limit: int = 50, category: Optional[str] = None, ip: Optional[str] = None) -> List[Dict[str, Any]]:
        """Returns filtered list of recent alerts, newest first."""
        results = list(reversed(self.recent_alerts))
        if category:
            results = [a for a in results if a.get("category") == category]
        if ip:
            results = [a for a in results if a.get("client_ip") == ip]
        return results[:limit]

    def clear_logs(self):
        """Resets all log data and counters."""
        self.recent_alerts.clear()
        self.total_inspections = 0
        self.total_allowed = 0
        self.total_blocked = 0
        if os.path.exists(self.json_log_path):
            open(self.json_log_path, "w", encoding="utf-8").close()
        if os.path.exists(self.audit_log_path):
            open(self.audit_log_path, "w", encoding="utf-8").close()

