"""
SentinelShield - Attack Simulator & Test Suite
Executes a comprehensive battery of benign requests and multi-category cyber attack vectors
to evaluate WAF detection accuracy, rate-limiting behavior, and false positive/negative rates.
Supports both live HTTP execution (via requests) and in-process execution (via Flask test_client).
"""

import sys
import os
import time
from typing import List, Dict, Any, Optional, Tuple

# Allow importing app from parent dir
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests


class AttackTestSuite:
    def __init__(self, base_url: Optional[str] = "http://127.0.0.1:5000", use_test_client: bool = False):
        self.base_url = (base_url or "http://127.0.0.1:5000").rstrip("/")
        self.use_test_client = use_test_client
        self.session = requests.Session()
        self.client = None

        if self.use_test_client:
            from app import app
            self.client = app.test_client()

    def get_test_cases(self) -> List[Dict[str, Any]]:
        """Returns standard catalog of benign and attack test cases."""
        return [
            # --- 1. Benign Requests (Expected to be ALLOWED) ---
            {
                "id": "BENIGN-01",
                "name": "Benign Search Query",
                "is_attack": False,
                "expected_category": None,
                "method": "GET",
                "path": "/api/search",
                "params": {"q": "wireless keyboard and mouse bundle"},
                "headers": {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "X-Forwarded-For": "203.0.113.10"},
                "data": None
            },
            {
                "id": "BENIGN-02",
                "name": "Benign Document Download",
                "is_attack": False,
                "expected_category": None,
                "method": "GET",
                "path": "/api/file",
                "params": {"name": "annual_financial_report_2026.pdf"},
                "headers": {"User-Agent": "Mozilla/5.0", "X-Forwarded-For": "203.0.113.11"},
                "data": None
            },
            {
                "id": "BENIGN-03",
                "name": "Benign Standard Login",
                "is_attack": False,
                "expected_category": None,
                "method": "POST",
                "path": "/api/login",
                "params": {},
                "headers": {"Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "X-Forwarded-For": "203.0.113.12"},
                "data": {"username": "alex.turner", "password": "SecretPassword2026!"}
            },
            {
                "id": "BENIGN-04",
                "name": "Benign Host Ping Request",
                "is_attack": False,
                "expected_category": None,
                "method": "GET",
                "path": "/api/system/ping",
                "params": {"host": "8.8.8.8"},
                "headers": {"User-Agent": "Mozilla/5.0", "X-Forwarded-For": "203.0.113.13"},
                "data": None
            },
            {
                "id": "BENIGN-05",
                "name": "Benign Feedback Form Submission",
                "is_attack": False,
                "expected_category": None,
                "method": "POST",
                "path": "/api/feedback",
                "params": {},
                "headers": {"Content-Type": "application/json", "X-Forwarded-For": "203.0.113.14"},
                "data": {"comment": "Great cybersecurity practical lab! Everything works smoothly.", "email": "student@university.edu"}
            },

            # --- 2. SQL Injection (SQLi) Attacks (Expected to be BLOCKED) ---
            {
                "id": "ATK-SQLI-01",
                "name": "SQLi: Classic Boolean Tautology",
                "is_attack": True,
                "expected_category": "SQL Injection (SQLi)",
                "method": "GET",
                "path": "/api/search",
                "params": {"q": "' OR '1'='1"},
                "headers": {"User-Agent": "Mozilla/5.0", "X-Forwarded-For": "198.51.100.21"},
                "data": None
            },
            {
                "id": "ATK-SQLI-02",
                "name": "SQLi: Numeric Tautology with Comment",
                "is_attack": True,
                "expected_category": "SQL Injection (SQLi)",
                "method": "GET",
                "path": "/api/search",
                "params": {"q": "admin' OR 1=1 --"},
                "headers": {"User-Agent": "Mozilla/5.0", "X-Forwarded-For": "198.51.100.22"},
                "data": None
            },
            {
                "id": "ATK-SQLI-03",
                "name": "SQLi: UNION SELECT Exfiltration",
                "is_attack": True,
                "expected_category": "SQL Injection (SQLi)",
                "method": "GET",
                "path": "/api/search",
                "params": {"q": "1 UNION SELECT username, password FROM users"},
                "headers": {"User-Agent": "Mozilla/5.0", "X-Forwarded-For": "198.51.100.23"},
                "data": None
            },
            {
                "id": "ATK-SQLI-04",
                "name": "SQLi: Destructive DROP TABLE via Body",
                "is_attack": True,
                "expected_category": "SQL Injection (SQLi)",
                "method": "POST",
                "path": "/api/login",
                "params": {},
                "headers": {"Content-Type": "application/json", "X-Forwarded-For": "198.51.100.24"},
                "data": {"username": "admin'; DROP TABLE users; --", "password": "xyz"}
            },

            # --- 3. Cross-Site Scripting (XSS) Attacks (Expected to be BLOCKED) ---
            {
                "id": "ATK-XSS-01",
                "name": "XSS: Explicit Inline <script> Injection",
                "is_attack": True,
                "expected_category": "Cross-Site Scripting (XSS)",
                "method": "GET",
                "path": "/api/search",
                "params": {"q": "<script>alert('XSS-PWNED')</script>"},
                "headers": {"User-Agent": "Mozilla/5.0", "X-Forwarded-For": "198.51.100.31"},
                "data": None
            },
            {
                "id": "ATK-XSS-02",
                "name": "XSS: HTML Image Element with Onerror Handler",
                "is_attack": True,
                "expected_category": "Cross-Site Scripting (XSS)",
                "method": "POST",
                "path": "/api/feedback",
                "params": {},
                "headers": {"Content-Type": "application/json", "X-Forwarded-For": "198.51.100.32"},
                "data": {"comment": "<img src=x onerror=alert(document.cookie)>", "email": "test@evil.com"}
            },
            {
                "id": "ATK-XSS-03",
                "name": "XSS: Javascript Pseudoprotocol URI",
                "is_attack": True,
                "expected_category": "Cross-Site Scripting (XSS)",
                "method": "GET",
                "path": "/api/search",
                "params": {"q": "javascript:alert(1)"},
                "headers": {"User-Agent": "Mozilla/5.0", "X-Forwarded-For": "198.51.100.33"},
                "data": None
            },

            # --- 4. Local File Inclusion (LFI) & Path Traversal (Expected to be BLOCKED) ---
            {
                "id": "ATK-LFI-01",
                "name": "LFI: Linux /etc/passwd Extraction Attempt",
                "is_attack": True,
                "expected_category": "Local File Inclusion / Path Traversal",
                "method": "GET",
                "path": "/api/file",
                "params": {"name": "../../../../etc/passwd"},
                "headers": {"User-Agent": "Mozilla/5.0", "X-Forwarded-For": "198.51.100.41"},
                "data": None
            },
            {
                "id": "ATK-LFI-02",
                "name": "LFI: Windows win.ini Traversal Attempt",
                "is_attack": True,
                "expected_category": "Local File Inclusion / Path Traversal",
                "method": "GET",
                "path": "/api/file",
                "params": {"name": "..\\..\\..\\windows\\win.ini"},
                "headers": {"User-Agent": "Mozilla/5.0", "X-Forwarded-For": "198.51.100.42"},
                "data": None
            },
            {
                "id": "ATK-LFI-03",
                "name": "LFI: URL-Encoded Path Traversal (%2e%2e%2f)",
                "is_attack": True,
                "expected_category": "Local File Inclusion / Path Traversal",
                "method": "GET",
                "path": "/api/file",
                "params": {"name": "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"},
                "headers": {"User-Agent": "Mozilla/5.0", "X-Forwarded-For": "198.51.100.43"},
                "data": None
            },

            # --- 5. Remote Command Injection (RCE) (Expected to be BLOCKED) ---
            {
                "id": "ATK-RCE-01",
                "name": "RCE: Semicolon Command Chaining (; whoami)",
                "is_attack": True,
                "expected_category": "Remote Command Injection (RCE)",
                "method": "GET",
                "path": "/api/system/ping",
                "params": {"host": "127.0.0.1; whoami"},
                "headers": {"User-Agent": "Mozilla/5.0", "X-Forwarded-For": "198.51.100.51"},
                "data": None
            },
            {
                "id": "ATK-RCE-02",
                "name": "RCE: Pipe Separator (| ls)",
                "is_attack": True,
                "expected_category": "Remote Command Injection (RCE)",
                "method": "GET",
                "path": "/api/system/ping",
                "params": {"host": "127.0.0.1 | ls"},
                "headers": {"User-Agent": "Mozilla/5.0", "X-Forwarded-For": "198.51.100.52"},
                "data": None
            },
            {
                "id": "ATK-RCE-03",
                "name": "RCE: Command Substitution $(cat /etc/hosts)",
                "is_attack": True,
                "expected_category": "Remote Command Injection (RCE)",
                "method": "GET",
                "path": "/api/system/ping",
                "params": {"host": "$(id)"},
                "headers": {"User-Agent": "Mozilla/5.0", "X-Forwarded-For": "198.51.100.53"},
                "data": None
            },

            # --- 6. Reconnaissance & Scanner Probing (Expected to be BLOCKED) ---
            {
                "id": "ATK-SCAN-01",
                "name": "Recon: Vulnerability Scanner User-Agent (Nikto)",
                "is_attack": True,
                "expected_category": "Automated Scanner / Reconnaissance",
                "method": "GET",
                "path": "/api/search",
                "params": {"q": "product"},
                "headers": {"User-Agent": "Mozilla/5.0 (compatible; Nikto/2.1.6)", "X-Forwarded-For": "198.51.100.61"},
                "data": None
            },
            {
                "id": "ATK-SCAN-02",
                "name": "Recon: Exposed Sensitive Repository Probing (.git/config)",
                "is_attack": True,
                "expected_category": "Automated Scanner / Reconnaissance",
                "method": "GET",
                "path": "/.git/config",
                "params": {},
                "headers": {"User-Agent": "Mozilla/5.0", "X-Forwarded-For": "198.51.100.62", "Accept": "application/json"},
                "data": None
            }
        ]

    def _execute_request(self, method: str, path: str, params: dict, headers: dict, data: Any) -> Tuple[int, dict]:
        """Dispatches request via test_client or requests."""
        if self.use_test_client:
            if method == "GET":
                res = self.client.get(path, query_string=params, headers=headers)
            else:
                res = self.client.post(path, json=data, query_string=params, headers=headers)
            json_body = res.get_json(silent=True) or {}
            if not json_body and "X-Sentinel-Rule" in res.headers:
                json_body = {
                    "rule_id": res.headers.get("X-Sentinel-Rule"),
                    "category": res.headers.get("X-Sentinel-Category"),
                    "incident_id": res.headers.get("X-Sentinel-Incident")
                }
            return res.status_code, json_body
        else:
            full_url = f"{self.base_url}{path}"
            if method == "GET":
                res = self.session.get(full_url, params=params, headers=headers, timeout=5)
            else:
                res = self.session.post(full_url, json=data, params=params, headers=headers, timeout=5)
            try:
                json_body = res.json()
            except Exception:
                json_body = {}
            if not json_body and "X-Sentinel-Rule" in res.headers:
                json_body = {
                    "rule_id": res.headers.get("X-Sentinel-Rule"),
                    "category": res.headers.get("X-Sentinel-Category"),
                    "incident_id": res.headers.get("X-Sentinel-Incident")
                }
            return res.status_code, json_body

    def run_tests(self) -> Dict[str, Any]:
        """Executes all catalog test cases and compiles evaluation statistics."""
        # Auto-detect if live server is reachable, otherwise use test_client
        if not self.use_test_client:
            try:
                self.session.get(f"{self.base_url}/", timeout=1)
            except Exception:
                print(f"[*] Live server not reachable at {self.base_url}. Switching to in-process test runner...")
                from app import app
                self.client = app.test_client()
                self.use_test_client = True

        test_cases = self.get_test_cases()
        results = []

        tp = 0  # Attack blocked
        tn = 0  # Benign allowed
        fp = 0  # Benign blocked
        fn = 0  # Attack allowed

        for tc in test_cases:
            headers = tc.get("headers", {})
            status_code, alert_info = self._execute_request(
                tc["method"], tc["path"], tc["params"], headers, tc["data"]
            )
            is_blocked = (status_code in [403, 429])

            # Evaluate classification metrics
            if tc["is_attack"]:
                if is_blocked:
                    tp += 1
                    verdict = "CORRECT_BLOCK (TP)"
                else:
                    fn += 1
                    verdict = "MISSED_ATTACK (FN)"
            else:
                if not is_blocked:
                    tn += 1
                    verdict = "CORRECT_ALLOW (TN)"
                else:
                    fp += 1
                    verdict = "FALSE_ALARM (FP)"

            results.append({
                "id": tc["id"],
                "name": tc["name"],
                "is_attack": tc["is_attack"],
                "status_code": status_code,
                "blocked": is_blocked,
                "verdict": verdict,
                "alert_category": alert_info.get("category", "N/A"),
                "rule_id": alert_info.get("rule_id", "N/A")
            })

        total = len(test_cases)
        accuracy = ((tp + tn) / total * 100) if total > 0 else 0
        precision = (tp / (tp + fp) * 100) if (tp + fp) > 0 else 0
        recall = (tp / (tp + fn) * 100) if (tp + fn) > 0 else 0

        summary = {
            "total_tests": total,
            "true_positives": tp,
            "true_negatives": tn,
            "false_positives": fp,
            "false_negatives": fn,
            "detection_accuracy": round(accuracy, 2),
            "precision": round(precision, 2),
            "recall": round(recall, 2),
            "test_details": results
        }
        return summary

    def run_rate_limiting_test(self, burst_count: int = 16) -> Dict[str, Any]:
        """Simulates rapid brute-force / flood traffic to trigger rate limiter."""
        print(f"\n[*] Simulating {burst_count} rapid consecutive requests to trigger rate limiting...")
        history = []
        blocked_count = 0

        for i in range(1, burst_count + 1):
            status_code, _ = self._execute_request(
                "GET", "/api/search", {"q": f"flood_probe_{i}"}, {"User-Agent": "Mozilla/5.0"}, None
            )
            is_limited = (status_code == 429)
            if is_limited:
                blocked_count += 1
            history.append({
                "request_num": i,
                "status_code": status_code,
                "rate_limited": is_limited
            })
            time.sleep(0.01)

        return {
            "burst_total": burst_count,
            "blocked_by_rate_limiter": blocked_count,
            "rate_limiter_triggered": blocked_count > 0,
            "history": history
        }


if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:5000"
    suite = AttackTestSuite(base_url=url)
    print(f"==================================================")
    print(f"SentinelShield Security Attack & Validation Suite")
    print(f"Target: {url}")
    print(f"==================================================")

    results = suite.run_tests()
    if results:
        print(f"\n[+] Total Test Cases: {results['total_tests']}")
        print(f"    - True Positives  (Attacks correctly blocked): {results['true_positives']}")
        print(f"    - True Negatives  (Benign correctly allowed): {results['true_negatives']}")
        print(f"    - False Positives (Benign mistakenly blocked): {results['false_positives']}")
        print(f"    - False Negatives (Attacks missed):           {results['false_negatives']}")
        print(f"[+] Detection Accuracy: {results['detection_accuracy']}%")
        print(f"[+] Precision:          {results['precision']}%")
        print(f"[+] Recall (Coverage):  {results['recall']}%\n")

        print(f"{'ID':<12} | {'Status':<6} | {'Verdict':<20} | {'Category / Rule':<35}")
        print("-" * 80)
        for t in results["test_details"]:
            cat_rule = f"{t['alert_category']} ({t['rule_id']})" if t['blocked'] else "N/A"
            print(f"{t['id']:<12} | {t['status_code']:<6} | {t['verdict']:<20} | {cat_rule:<35}")
