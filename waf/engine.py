"""
SentinelShield - Core Inspection and Rule Engine
Implements request normalization, multi-vector regex pattern matching,
rate limit evaluation, and detection decision logic.
"""

import os
import re
import urllib.parse
from typing import Dict, Any, Optional, List, Tuple

from .models import SecurityAlert, InspectionResult, RuleCategory, DecisionAction, Severity
from .rate_limiter import RateLimiter
from .logger import SecurityLogger
import json


class WAFEngine:
    def __init__(
        self,
        rules_path: Optional[str] = None,
        logger: Optional[SecurityLogger] = None,
        rate_limiter: Optional[RateLimiter] = None,
        mode: str = "BLOCKING"  # BLOCKING (IPS) or MONITORING (IDS)
    ):
        self.mode = mode.upper()  # BLOCKING or MONITORING
        self.waf_enabled = True
        self.rate_limiting_enabled = True

        # Resolve paths
        base_dir = os.path.dirname(os.path.abspath(__file__))
        self.rules_path = rules_path or os.path.join(base_dir, "rules.json")

        log_dir = os.path.join(os.path.dirname(base_dir), "logs")
        self.logger = logger or SecurityLogger(log_dir)
        self.rate_limiter = rate_limiter or RateLimiter(max_requests=12, window_seconds=10, ban_duration_seconds=30)

        # Compiled rules cache
        self.rules: List[Dict[str, Any]] = []
        self._load_and_compile_rules()

    def _load_and_compile_rules(self):
        """Loads signature rules from JSON and compiles regular expressions."""
        if not os.path.exists(self.rules_path):
            raise FileNotFoundError(f"Rules file not found at {self.rules_path}")

        with open(self.rules_path, "r", encoding="utf-8") as f:
            raw_rules = json.load(f)

        compiled = []
        for r in raw_rules:
            try:
                pattern = re.compile(r["pattern"])
                compiled.append({
                    "id": r["id"],
                    "name": r["name"],
                    "category": r["category"],
                    "severity": r.get("severity", "HIGH"),
                    "description": r.get("description", ""),
                    "compiled_pattern": pattern,
                    "target_components": set(r.get("target_components", ["query", "body"]))
                })
            except re.error as err:
                print(f"[WAF Config Error] Invalid regex for rule {r.get('id')}: {err}")

        self.rules = compiled

    def normalize_input(self, value: Any) -> str:
        """
        Multi-stage payload normalization:
        1. Convert non-strings to string representation
        2. Unquote URL encoding (including double-decoding attempts)
        3. Remove NULL bytes (%00, \x00)
        4. Normalize whitespace
        """
        if value is None:
            return ""
        if isinstance(value, (dict, list)):
            value = json.dumps(value)
        elif not isinstance(value, str):
            value = str(value)

        # First pass URL decode
        normalized = urllib.parse.unquote_plus(value)
        # Second pass URL decode (catch double-encoding attacks e.g., %252e%252e)
        if "%" in normalized:
            try:
                second_pass = urllib.parse.unquote_plus(normalized)
                if second_pass != normalized:
                    normalized = second_pass
            except Exception:
                pass

        # Strip null bytes
        normalized = normalized.replace("\x00", "").replace("%00", "")
        return normalized

    def inspect_request(
        self,
        client_ip: str,
        method: str,
        path: str,
        headers: Dict[str, str],
        query_params: Dict[str, Any],
        body_data: Any
    ) -> InspectionResult:
        """
        Core request inspection pipeline:
        1. Bypass if WAF disabled
        2. Behavioral Rate Limit check
        3. Static Header inspection (e.g. Scanner User-Agents)
        4. Path & Endpoint traversal inspection
        5. Query parameters inspection
        6. Request body inspection (Form / JSON / Text)
        """
        if not self.waf_enabled:
            return InspectionResult(allowed=True, action=DecisionAction.ALLOW, message="WAF disabled.")

        # --- Phase 1: Behavior & Rate Limiting ---
        if self.rate_limiting_enabled:
            allowed, limit_msg, req_count = self.rate_limiter.record_and_evaluate(client_ip)
            if not allowed:
                alert = SecurityAlert(
                    client_ip=client_ip,
                    method=method,
                    path=path,
                    target_component="traffic_rate",
                    trigger_value=f"Request count: {req_count} in sliding window",
                    rule_id="SEC-RATE-001",
                    rule_name="Rate Limit Threshold Exceeded",
                    category=RuleCategory.RATE_LIMIT_EXCEEDED.value,
                    severity=Severity.HIGH.value,
                    action=DecisionAction.RATE_LIMIT_BLOCK.value,
                    http_status=429,
                    extra_details={"message": limit_msg}
                )
                self.logger.log_security_alert(alert)
                return InspectionResult(
                    allowed=False,
                    action=DecisionAction.RATE_LIMIT_BLOCK,
                    http_status=429,
                    alert=alert,
                    message=f"Rate Limit Block: {limit_msg}"
                )

        # Prepare normalized targets
        norm_path = self.normalize_input(path)

        # --- Phase 2: Target Inspection Pipeline ---
        # Component 1: Headers (User-Agent, etc.)
        for hdr_name, hdr_val in headers.items():
            norm_val = self.normalize_input(hdr_val)
            match_res = self._match_rules(norm_val, "header")
            if match_res:
                return self._build_block_decision(
                    match_res, client_ip, method, path,
                    target=f"header:{hdr_name}", trigger=norm_val
                )

        # Component 2: Request Path
        path_match = self._match_rules(norm_path, "path")
        if path_match:
            return self._build_block_decision(
                path_match, client_ip, method, path,
                target="path", trigger=norm_path
            )

        # Component 3: Query Parameters (both key and value)
        for q_key, q_val in query_params.items():
            norm_key = self.normalize_input(q_key)
            norm_val = self.normalize_input(q_val)

            key_match = self._match_rules(norm_key, "query")
            if key_match:
                return self._build_block_decision(
                    key_match, client_ip, method, path,
                    target=f"query_key:{q_key}", trigger=norm_key
                )

            val_match = self._match_rules(norm_val, "query")
            if val_match:
                return self._build_block_decision(
                    val_match, client_ip, method, path,
                    target=f"query_param:{q_key}", trigger=norm_val
                )

        # Component 4: Request Body (JSON or Form)
        if body_data:
            if isinstance(body_data, dict):
                for b_key, b_val in body_data.items():
                    norm_k = self.normalize_input(b_key)
                    norm_v = self.normalize_input(b_val)

                    k_match = self._match_rules(norm_k, "body")
                    if k_match:
                        return self._build_block_decision(
                            k_match, client_ip, method, path,
                            target=f"body_field_key:{b_key}", trigger=norm_k
                        )

                    v_match = self._match_rules(norm_v, "body")
                    if v_match:
                        return self._build_block_decision(
                            v_match, client_ip, method, path,
                            target=f"body_field:{b_key}", trigger=norm_v
                        )
            else:
                norm_body = self.normalize_input(body_data)
                body_match = self._match_rules(norm_body, "body")
                if body_match:
                    return self._build_block_decision(
                        body_match, client_ip, method, path,
                        target="raw_body", trigger=norm_body
                    )

        # If clean:
        self.logger.log_clean_request(client_ip, method, path)
        return InspectionResult(
            allowed=True,
            action=DecisionAction.ALLOW,
            http_status=200,
            message="Request passed all security inspection checks."
        )

    def _match_rules(self, text: str, component: str) -> Optional[Dict[str, Any]]:
        """Evaluates normalized string against active rules targeting the specified component."""
        if not text:
            return None

        for rule in self.rules:
            if component in rule["target_components"]:
                if rule["compiled_pattern"].search(text):
                    return rule
        return None

    def _build_block_decision(
        self,
        rule: Dict[str, Any],
        client_ip: str,
        method: str,
        path: str,
        target: str,
        trigger: str
    ) -> InspectionResult:
        """Constructs security alert and determines whether to block or log based on operational mode."""
        is_blocking = (self.mode == "BLOCKING")
        action = DecisionAction.BLOCK if is_blocking else DecisionAction.FLAG

        alert = SecurityAlert(
            client_ip=client_ip,
            method=method,
            path=path,
            target_component=target,
            trigger_value=trigger,
            rule_id=rule["id"],
            rule_name=rule["name"],
            category=rule["category"],
            severity=rule["severity"],
            action=action.value,
            http_status=403 if is_blocking else 200,
            extra_details={"description": rule["description"]}
        )

        self.logger.log_security_alert(alert)

        return InspectionResult(
            allowed=(not is_blocking),
            action=action,
            http_status=403 if is_blocking else 200,
            alert=alert,
            message=f"Threat Detected: {rule['name']} [{rule['id']}]"
        )

