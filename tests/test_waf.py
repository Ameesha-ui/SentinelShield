"""
Unit and Integration Tests for SentinelShield WAF Engine
Can be run with `pytest` inside the project directory.
"""

import os
import pytest
from waf.engine import WAFEngine
from waf.rate_limiter import RateLimiter
from waf.models import DecisionAction, RuleCategory


@pytest.fixture
def waf_engine(tmp_path):
    log_dir = str(tmp_path / "test_logs")
    from waf.logger import SecurityLogger
    logger = SecurityLogger(log_dir)
    limiter = RateLimiter(max_requests=5, window_seconds=2, ban_duration_seconds=5)
    engine = WAFEngine(logger=logger, rate_limiter=limiter, mode="BLOCKING")
    return engine


def test_benign_requests_pass(waf_engine):
    res = waf_engine.inspect_request(
        client_ip="192.168.1.10",
        method="GET",
        path="/api/search",
        headers={"User-Agent": "Mozilla/5.0"},
        query_params={"q": "wireless ergonomic mouse"},
        body_data=None
    )
    assert res.allowed is True
    assert res.action == DecisionAction.ALLOW
    assert res.http_status == 200


def test_sqli_tautology_blocked(waf_engine):
    res = waf_engine.inspect_request(
        client_ip="192.168.1.50",
        method="GET",
        path="/api/search",
        headers={"User-Agent": "Mozilla/5.0"},
        query_params={"q": "' OR '1'='1"},
        body_data=None
    )
    assert res.allowed is False
    assert res.action == DecisionAction.BLOCK
    assert res.http_status == 403
    assert res.alert is not None
    assert "SQL Injection" in res.alert.category


def test_xss_script_injection_blocked(waf_engine):
    res = waf_engine.inspect_request(
        client_ip="192.168.1.51",
        method="POST",
        path="/api/feedback",
        headers={"User-Agent": "Mozilla/5.0"},
        query_params={},
        body_data={"comment": "<script>alert(1)</script>"}
    )
    assert res.allowed is False
    assert res.action == DecisionAction.BLOCK
    assert res.http_status == 403
    assert "Cross-Site Scripting" in res.alert.category


def test_lfi_directory_traversal_blocked(waf_engine):
    res = waf_engine.inspect_request(
        client_ip="192.168.1.52",
        method="GET",
        path="/api/file",
        headers={"User-Agent": "Mozilla/5.0"},
        query_params={"name": "../../../../etc/passwd"},
        body_data=None
    )
    assert res.allowed is False
    assert res.action == DecisionAction.BLOCK
    assert "Local File Inclusion" in res.alert.category


def test_command_injection_blocked(waf_engine):
    res = waf_engine.inspect_request(
        client_ip="192.168.1.53",
        method="GET",
        path="/api/system/ping",
        headers={"User-Agent": "Mozilla/5.0"},
        query_params={"host": "127.0.0.1; whoami"},
        body_data=None
    )
    assert res.allowed is False
    assert res.action == DecisionAction.BLOCK
    assert "Remote Command Injection" in res.alert.category


def test_scanner_user_agent_blocked(waf_engine):
    res = waf_engine.inspect_request(
        client_ip="192.168.1.54",
        method="GET",
        path="/api/search",
        headers={"User-Agent": "sqlmap/1.5.2#stable"},
        query_params={"q": "test"},
        body_data=None
    )
    assert res.allowed is False
    assert res.alert.rule_id == "SEC-PROBE-001"


def test_rate_limiting_sliding_window(waf_engine):
    ip = "192.168.1.99"
    # Max requests is configured as 5 in fixture
    for i in range(5):
        res = waf_engine.inspect_request(
            client_ip=ip,
            method="GET",
            path="/api/search",
            headers={"User-Agent": "Mozilla/5.0"},
            query_params={"q": f"item_{i}"},
            body_data=None
        )
        assert res.allowed is True, f"Request {i+1} should be allowed"

    # 6th request must trigger rate limit
    res6 = waf_engine.inspect_request(
        client_ip=ip,
        method="GET",
        path="/api/search",
        headers={"User-Agent": "Mozilla/5.0"},
        query_params={"q": "item_6"},
        body_data=None
    )
    assert res6.allowed is False
    assert res6.http_status == 429
    assert res6.action == DecisionAction.RATE_LIMIT_BLOCK


def test_monitoring_mode_does_not_block(waf_engine):
    waf_engine.mode = "MONITORING"
    res = waf_engine.inspect_request(
        client_ip="192.168.1.77",
        method="GET",
        path="/api/search",
        headers={"User-Agent": "Mozilla/5.0"},
        query_params={"q": "' OR '1'='1"},
        body_data=None
    )
    # In monitoring (IDS) mode, alerts are logged but allowed=True and status=200
    assert res.allowed is True
    assert res.action == DecisionAction.FLAG
    assert res.alert is not None

