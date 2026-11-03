"""
SentinelShield - Security Event Logging System
Stores inspection statistics and security alerts in Supabase.
"""

import os
import json
import logging
from typing import List, Dict, Any, Optional
from collections import Counter

from supabase import create_client
from .models import SecurityAlert


class SecurityLogger:

    def __init__(self, log_dir: str):
        self.log_dir = log_dir

        try:
            os.makedirs(log_dir, exist_ok=True)
        except OSError:
            self.log_dir = "/tmp/sentinelshield_logs"
            os.makedirs(self.log_dir, exist_ok=True)

        self.json_log_path = os.path.join(
            self.log_dir, "sentinel_alerts.jsonl"
        )
        self.audit_log_path = os.path.join(
            self.log_dir, "sentinel_security.log"
        )

        self.recent_alerts = []
        self.total_inspections = 0
        self.total_allowed = 0
        self.total_blocked = 0

        # Connect to Supabase using Vercel environment variables
        self.supabase = None

        url = os.getenv("SUPABASE_URL")
        key = os.getenv("SUPABASE_KEY")

        if url and key:
            try:
                self.supabase = create_client(url, key)
                print("[SentinelShield] Supabase connected")
            except Exception as e:
                print(f"[Supabase connection error] {e}")

        # Audit logger
        self.audit_logger = logging.getLogger("SentinelSecurityAudit")
        self.audit_logger.setLevel(logging.INFO)

        if not self.audit_logger.handlers:
            try:
                handler = logging.FileHandler(
                    self.audit_log_path, encoding="utf-8"
                )
            except OSError:
                handler = logging.StreamHandler()

            handler.setFormatter(logging.Formatter(
                "[%(asctime)s] [%(levelname)s] [SentinelShield] %(message)s"
            ))
            self.audit_logger.addHandler(handler)

    def _save_event(self, event):
        """Save an inspection event to Supabase."""
        if not self.supabase:
            return False

        try:
            self.supabase.table(
                "waf_inspection_events"
            ).insert(event).execute()
            return True
        except Exception as e:
            print(f"[Supabase save error] {e}")
            return False

    def log_clean_request(self, ip: str, method: str, path: str):
        """Records an allowed request."""

        self.total_inspections += 1
        self.total_allowed += 1

        self._save_event({
            "allowed": True,
            "category": "Allowed",
            "client_ip": ip,
            "method": method,
            "path": path,
            "action": "ALLOW"
        })

    def log_security_alert(self, alert: SecurityAlert):
        """Records a blocked security request."""

        alert_dict = alert.to_dict()

        self.total_inspections += 1
        self.total_blocked += 1

        self.recent_alerts.append(alert_dict)
        self.recent_alerts = self.recent_alerts[-500:]

        event = {
            "allowed": False,
            "category": alert_dict.get("category"),
            "client_ip": alert_dict.get("client_ip"),
            "method": alert_dict.get("method"),
            "path": alert_dict.get("path"),
            "severity": alert_dict.get("severity"),
            "action": alert_dict.get("action"),
            "rule_id": alert_dict.get("rule_id"),
            "rule_name": alert_dict.get("rule_name"),
            "target_component": alert_dict.get("target_component"),
            "trigger_value": str(
                alert_dict.get("trigger_value", "")
            )[:120]
        }

        self._save_event(event)

        try:
            with open(self.json_log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(alert_dict) + "\n")
        except OSError:
            pass

        self.audit_logger.warning(
            f"BLOCKED | IP={event['client_ip']} | "
            f"PATH={event['path']} | CATEGORY={event['category']}"
        )

    def get_summary_statistics(self) -> Dict[str, Any]:
        """Gets persistent statistics from Supabase."""

        if self.supabase:
            try:
                table = self.supabase.table("waf_inspection_events")

                total = table.select(
                    "id", count="exact"
                ).execute().count or 0

                allowed = table.select(
                    "id", count="exact"
                ).eq("allowed", True).execute().count or 0

                blocked = table.select(
                    "id", count="exact"
                ).eq("allowed", False).execute().count or 0

                response = table.select("*").eq(
                    "allowed", False
                ).order(
                    "created_at", desc=True
                ).limit(500).execute()

                alerts = response.data or []

                category_counts = Counter(
                    a.get("category") or "Unknown" for a in alerts
                )
                severity_counts = Counter(
                    a.get("severity") or "Unknown" for a in alerts
                )
                ip_counts = Counter(
                    a.get("client_ip") or "Unknown" for a in alerts
                )

                return {
                    "total_inspections": total,
                    "total_allowed": allowed,
                    "total_blocked": blocked,
                    "block_rate_percentage": round(
                        blocked / total * 100, 2
                    ) if total else 0.0,
                    "category_distribution": dict(category_counts),
                    "severity_distribution": dict(severity_counts),
                    "categories_breakdown": [
                        {"category": k, "count": v}
                        for k, v in category_counts.most_common()
                    ],
                    "top_flagged_ips": [
                        {"ip": k, "count": v}
                        for k, v in ip_counts.most_common(5)
                    ],
                    "recent_alert_count": len(alerts)
                }

            except Exception as e:
                print(f"[Supabase statistics error] {e}")

        # Local fallback
        return {
            "total_inspections": self.total_inspections,
            "total_allowed": self.total_allowed,
            "total_blocked": self.total_blocked,
            "block_rate_percentage": round(
                self.total_blocked / self.total_inspections * 100, 2
            ) if self.total_inspections else 0.0,
            "category_distribution": {},
            "severity_distribution": {},
            "categories_breakdown": [],
            "top_flagged_ips": [],
            "recent_alert_count": len(self.recent_alerts)
        }

    def get_recent_alerts(
        self,
        limit: int = 50,
        category: Optional[str] = None,
        ip: Optional[str] = None
    ) -> List[Dict[str, Any]]:

        if self.supabase:
            try:
                query = self.supabase.table(
                    "waf_inspection_events"
                ).select("*").eq(
                    "allowed", False
                ).order(
                    "created_at", desc=True
                ).limit(limit)

                if category:
                    query = query.eq("category", category)

                if ip:
                    query = query.eq("client_ip", ip)

                return query.execute().data or []

            except Exception as e:
                print(f"[Supabase alerts error] {e}")

        results = list(reversed(self.recent_alerts))

        if category:
            results = [
                a for a in results
                if a.get("category") == category
            ]

        if ip:
            results = [
                a for a in results
                if a.get("client_ip") == ip
            ]

        return results[:limit]

    def clear_logs(self):
        """Clears local counters and recent alerts."""

        self.recent_alerts.clear()
        self.total_inspections = 0
        self.total_allowed = 0
        self.total_blocked = 0
