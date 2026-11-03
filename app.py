"""
SentinelShield - Web Application Firewall & Security Operations Center
Protects endpoints with the WAFEngine, handles request filtering,
and exposes the SOC Dashboard for threat monitoring and analysis.
"""

import os
from flask import Flask, request, jsonify, render_template, Response
from waf.engine import WAFEngine
from waf.models import DecisionAction

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["SECRET_KEY"] = "sentinel-shield-student-lab-key"

# Initialize SentinelShield Engine
waf = WAFEngine()


def get_client_ip() -> str:
    """Extracts client IP, honoring X-Forwarded-For if present."""
    if request.headers.get("X-Forwarded-For"):
        return request.headers.get("X-Forwarded-For").split(",")[0].strip()
    return request.remote_addr or "127.0.0.1"


@app.before_request
def waf_interceptor():
    """
    SentinelShield Request Interception Middleware.
    Inspects all requests except internal SOC dashboard routes and static files.
    """
    path = request.path

    # Whitelist SOC dashboard routes and static assets so management is never locked out
    if path.startswith("/dashboard") or path.startswith("/api/waf") or path.startswith("/static"):
        return None

    client_ip = get_client_ip()
    headers = dict(request.headers)
    query_params = dict(request.args)

    # Extract body content (JSON, Form data, or raw string)
    body_data = None
    if request.is_json:
        try:
            body_data = request.get_json(silent=True)
        except Exception:
            body_data = request.get_data(as_text=True)
    elif request.form:
        body_data = dict(request.form)
    else:
        body_data = request.get_data(as_text=True)

    # Execute SentinelShield WAF Inspection Pipeline
    inspection = waf.inspect_request(
        client_ip=client_ip,
        method=request.method,
        path=path,
        headers=headers,
        query_params=query_params,
        body_data=body_data
    )

    if not inspection.allowed:
        # Determine if caller wants JSON or HTML
        wants_json = (
            request.is_json or
            "application/json" in request.headers.get("Accept", "") or
            "curl" in request.headers.get("User-Agent", "").lower() or
            path.startswith("/api/")
        )

        resp = None
        if wants_json:
            response_payload = {
                "error": "Request Intercepted by SentinelShield WAF",
                "status": inspection.http_status,
                "action": inspection.action.value,
                "message": inspection.message,
                "incident_id": inspection.alert.alert_id if inspection.alert else None,
                "category": inspection.alert.category if inspection.alert else None,
                "rule_id": inspection.alert.rule_id if inspection.alert else None
            }
            resp = jsonify(response_payload)
        else:
            resp = Response(
                render_template("blocked.html", alert=inspection.alert),
                mimetype="text/html"
            )

        resp.status_code = inspection.http_status
        if inspection.alert:
            resp.headers["X-Sentinel-Incident"] = inspection.alert.alert_id
            resp.headers["X-Sentinel-Action"] = inspection.action.value
            resp.headers["X-Sentinel-Rule"] = inspection.alert.rule_id
            resp.headers["X-Sentinel-Category"] = inspection.alert.category
        return resp

    return None


# -------------------------------------------------------------
# Protected Application Endpoints (Simulated Targets)
# -------------------------------------------------------------

@app.route("/")
def home():
    return jsonify({
        "status": "online",
        "service": "Acme Protected Corporate Application",
        "waf_protection": "SentinelShield Active",
        "soc_dashboard_url": "/dashboard",
        "available_endpoints": [
            {"method": "GET", "path": "/api/search?q=...", "desc": "Product search endpoint"},
            {"method": "GET", "path": "/api/file?name=...", "desc": "Document retrieval endpoint"},
            {"method": "POST", "path": "/api/login", "desc": "User authentication endpoint"},
            {"method": "GET", "path": "/api/system/ping?host=...", "desc": "Network diagnostic endpoint"},
            {"method": "POST", "path": "/api/feedback", "desc": "Customer feedback form"}
        ]
    })


@app.route("/api/search")
def search_endpoint():
    query = request.args.get("q", "")
    return jsonify({
        "status": "success",
        "endpoint": "/api/search",
        "query": query,
        "results": [
            {"id": 101, "name": f"Product matching '{query}'", "inventory": 42}
        ]
    })


@app.route("/api/file")
def file_endpoint():
    filename = request.args.get("name", "sample.txt")
    return jsonify({
        "status": "success",
        "endpoint": "/api/file",
        "filename": filename,
        "content": f"[Simulated file content for {filename}]"
    })


@app.route("/api/login", methods=["POST"])
def login_endpoint():
    data = request.get_json(silent=True) or request.form
    username = data.get("username", "")
    return jsonify({
        "status": "error",
        "endpoint": "/api/login",
        "message": f"Authentication failed for user '{username}' (invalid credentials)"
    }), 401


@app.route("/api/system/ping")
def ping_endpoint():
    host = request.args.get("host", "127.0.0.1")
    return jsonify({
        "status": "success",
        "endpoint": "/api/system/ping",
        "target": host,
        "output": f"Pinging {host} with 32 bytes of data: Reply from {host}: bytes=32 time<1ms TTL=128"
    })


@app.route("/api/feedback", methods=["POST"])
def feedback_endpoint():
    data = request.get_json(silent=True) or request.form
    comment = data.get("comment", "")
    return jsonify({
        "status": "success",
        "endpoint": "/api/feedback",
        "message": "Feedback received successfully",
        "comment_length": len(comment)
    })


# -------------------------------------------------------------
# Security Operations Center (SOC) & Telemetry API
# -------------------------------------------------------------

@app.route("/dashboard")
def dashboard_view():
    return render_template("dashboard.html")


@app.route("/api/waf/stats")
def waf_stats():
    summary = waf.logger.get_summary_statistics()
    recent = waf.logger.get_recent_alerts(limit=25)
    tracked_ips = waf.rate_limiter.get_tracked_ips()

    return jsonify({
        "stats": summary,
        "recent_alerts": recent,
        "tracked_ips": tracked_ips,
        "engine_status": {
            "enabled": waf.waf_enabled,
            "mode": waf.mode,
            "rate_limiting": waf.rate_limiting_enabled,
            "rules_count": len(waf.rules)
        }
    })


@app.route("/api/waf/logs")
def waf_logs():
    category = request.args.get("category")
    ip = request.args.get("ip")
    limit = int(request.args.get("limit", 50))
    alerts = waf.logger.get_recent_alerts(limit=limit, category=category, ip=ip)
    return jsonify({"count": len(alerts), "alerts": alerts})


@app.route("/api/waf/rules")
def waf_rules():
    rules_data = [
        {
            "id": r["id"],
            "name": r["name"],
            "category": r["category"],
            "severity": r["severity"],
            "description": r["description"],
            "components": list(r["target_components"])
        }
        for r in waf.rules
    ]
    return jsonify({"total_rules": len(rules_data), "rules": rules_data})


@app.route("/api/waf/unban", methods=["POST"])
def waf_unban():
    data = request.get_json(silent=True) or {}
    ip = data.get("ip")
    if not ip:
        return jsonify({"error": "Missing IP parameter"}), 400
    existed = waf.rate_limiter.unban_ip(ip)
    return jsonify({"status": "success", "ip": ip, "unbanned": existed})


@app.route("/api/waf/toggle", methods=["POST"])
def waf_toggle():
    # Rotate mode: BLOCKING -> MONITORING -> DISABLED -> BLOCKING
    if waf.waf_enabled and waf.mode == "BLOCKING":
        waf.mode = "MONITORING"
    elif waf.waf_enabled and waf.mode == "MONITORING":
        waf.waf_enabled = False
    else:
        waf.waf_enabled = True
        waf.mode = "BLOCKING"

    return jsonify({
        "waf_enabled": waf.waf_enabled,
        "mode": waf.mode
    })


@app.route("/api/waf/reset", methods=["POST"])
def waf_reset():
    waf.logger.clear_logs()
    waf.rate_limiter.reset()
    return jsonify({"status": "success", "message": "Telemetry & logs reset."})


@app.route("/api/waf/test-payload", methods=["POST"])
def waf_test_payload():
    """Interactive sandbox test endpoint for students."""
    data = request.get_json(silent=True) or {}
    component = data.get("component", "query")
    payload = data.get("payload", "")

    # Normalize
    norm = waf.normalize_input(payload)
    matched_rule = waf._match_rules(norm, component)

    if matched_rule:
        return jsonify({
            "allowed": False,
            "message": f"Threat Detected: {matched_rule['name']}",
            "alert": {
                "rule_id": matched_rule["id"],
                "rule_name": matched_rule["name"],
                "category": matched_rule["category"],
                "severity": matched_rule["severity"],
                "extra_details": {"description": matched_rule["description"]}
            }
        })
    else:
        return jsonify({
            "allowed": True,
            "message": "No malicious signatures matched. Request payload is deemed clean."
        })


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
