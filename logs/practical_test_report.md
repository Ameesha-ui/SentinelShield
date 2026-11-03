# SentinelShield Practical Work Execution Report
**Generated:** 2026-10-30 21:03:15 UTC  
**Target Environment:** Localhost Web Application Firewall (SentinelShield)  
**Evaluator:** Student Practical Testing Harness

---

## 1. Executive Summary & Core Metrics

The automated test battery evaluated the SentinelShield Web Application Firewall (WAF) against a comprehensive spectrum of benign requests and common web application attack vectors (OWASP Top 10 categories including SQL Injection, Cross-Site Scripting, Local File Inclusion, Remote Command Injection, Automated Scanners, and Traffic Flooding).

| Metric | Measured Value | Operational Meaning |
| :--- | :--- | :--- |
| **Total Test Cases Evaluated** | `20` | Full suite of benign and malicious payloads |
| **True Positives (TP)** | `15` | Malicious attacks successfully detected and blocked (403) |
| **True Negatives (TN)** | `5` | Harmless benign requests correctly permitted (200/401) |
| **False Positives (FP)** | `0` | Benign traffic erroneously flagged/blocked |
| **False Negatives (FN)** | `0` | Malicious attack payloads missed by the rule engine |
| **Detection Accuracy** | **`100.0%`** | $\frac{TP + TN}{Total}$ |
| **Precision** | **`100.0%`** | $\frac{TP}{TP + FP}$ |
| **Recall / Sensitivity** | **`100.0%`** | $\frac{TP}{TP + FN}$ |

---

## 2. Test Execution Breakdown

| Test ID | Scenario / Payload Name | Traffic Type | HTTP Status | Action Taken | Evaluation Verdict | Matched Rule / Category |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `BENIGN-01` | Benign Search Query | Benign Request | `200` | ALLOWED | CORRECT_ALLOW (TN) | *None (Passed)* |
| `BENIGN-02` | Benign Document Download | Benign Request | `200` | ALLOWED | CORRECT_ALLOW (TN) | *None (Passed)* |
| `BENIGN-03` | Benign Standard Login | Benign Request | `401` | ALLOWED | CORRECT_ALLOW (TN) | *None (Passed)* |
| `BENIGN-04` | Benign Host Ping Request | Benign Request | `200` | ALLOWED | CORRECT_ALLOW (TN) | *None (Passed)* |
| `BENIGN-05` | Benign Feedback Form Submission | Benign Request | `200` | ALLOWED | CORRECT_ALLOW (TN) | *None (Passed)* |
| `ATK-SQLI-01` | SQLi: Classic Boolean Tautology | Malicious Attack | `403` | **BLOCKED** | CORRECT_BLOCK (TP) | `SEC-SQLI-001`: SQL Injection (SQLi) |
| `ATK-SQLI-02` | SQLi: Numeric Tautology with Comment | Malicious Attack | `403` | **BLOCKED** | CORRECT_BLOCK (TP) | `SEC-SQLI-001`: SQL Injection (SQLi) |
| `ATK-SQLI-03` | SQLi: UNION SELECT Exfiltration | Malicious Attack | `403` | **BLOCKED** | CORRECT_BLOCK (TP) | `SEC-SQLI-002`: SQL Injection (SQLi) |
| `ATK-SQLI-04` | SQLi: Destructive DROP TABLE via Body | Malicious Attack | `403` | **BLOCKED** | CORRECT_BLOCK (TP) | `SEC-SQLI-003`: SQL Injection (SQLi) |
| `ATK-XSS-01` | XSS: Explicit Inline <script> Injection | Malicious Attack | `403` | **BLOCKED** | CORRECT_BLOCK (TP) | `SEC-XSS-001`: Cross-Site Scripting (XSS) |
| `ATK-XSS-02` | XSS: HTML Image Element with Onerror Handler | Malicious Attack | `403` | **BLOCKED** | CORRECT_BLOCK (TP) | `SEC-XSS-002`: Cross-Site Scripting (XSS) |
| `ATK-XSS-03` | XSS: Javascript Pseudoprotocol URI | Malicious Attack | `403` | **BLOCKED** | CORRECT_BLOCK (TP) | `SEC-XSS-003`: Cross-Site Scripting (XSS) |
| `ATK-LFI-01` | LFI: Linux /etc/passwd Extraction Attempt | Malicious Attack | `403` | **BLOCKED** | CORRECT_BLOCK (TP) | `SEC-LFI-001`: Local File Inclusion / Path Traversal |
| `ATK-LFI-02` | LFI: Windows win.ini Traversal Attempt | Malicious Attack | `403` | **BLOCKED** | CORRECT_BLOCK (TP) | `SEC-LFI-001`: Local File Inclusion / Path Traversal |
| `ATK-LFI-03` | LFI: URL-Encoded Path Traversal (%2e%2e%2f) | Malicious Attack | `403` | **BLOCKED** | CORRECT_BLOCK (TP) | `SEC-LFI-001`: Local File Inclusion / Path Traversal |
| `ATK-RCE-01` | RCE: Semicolon Command Chaining (; whoami) | Malicious Attack | `403` | **BLOCKED** | CORRECT_BLOCK (TP) | `SEC-RCE-001`: Remote Command Injection (RCE) |
| `ATK-RCE-02` | RCE: Pipe Separator (| ls) | Malicious Attack | `403` | **BLOCKED** | CORRECT_BLOCK (TP) | `SEC-RCE-001`: Remote Command Injection (RCE) |
| `ATK-RCE-03` | RCE: Command Substitution $(cat /etc/hosts) | Malicious Attack | `403` | **BLOCKED** | CORRECT_BLOCK (TP) | `SEC-RCE-002`: Remote Command Injection (RCE) |
| `ATK-SCAN-01` | Recon: Vulnerability Scanner User-Agent (Nikto) | Malicious Attack | `403` | **BLOCKED** | CORRECT_BLOCK (TP) | `SEC-PROBE-001`: Automated Scanner / Reconnaissance |
| `ATK-SCAN-02` | Recon: Exposed Sensitive Repository Probing (.git/config) | Malicious Attack | `403` | **BLOCKED** | CORRECT_BLOCK (TP) | `SEC-PROBE-002`: Automated Scanner / Reconnaissance |

---

## 3. Behavior Monitoring & Rate Limiting Verification

To evaluate SentinelShield's sliding window rate-limiting algorithm, a rapid burst of `16` requests was issued within a 1-second interval from a single client IP.

* **Rate Limiting Engine Status:** ACTIVATED (Triggered Successfully)
* **Burst Requests Submitted:** `16`
* **Excess Requests Blocked (HTTP 429 Too Many Requests):** `4`
* **Temporary Ban Enforcement:** Confirmed (Subsequent requests return HTTP 429 with Retry-After header)

---

## 4. Analysis of Detection Accuracy & False Positives/Negatives

### Detection Accuracy Assessment
SentinelShield achieved a detection accuracy of **100.0%** and a recall of **100.0%**. All high-risk attacks across the tested categories (SQLi, XSS, LFI, and RCE) were intercepted before reaching vulnerable application controllers.

### False Positives (FP) Analysis
* **Observed Count:** `0`
* **Impact:** In production environments, false positives disrupt legitimate users. The rules in `waf/rules.json` utilize strict word boundaries and contextual token matching to prevent common harmless strings from triggering alerts.

### False Negatives (FN) Analysis
* **Observed Count:** `0`
* **Impact:** False negatives represent evasions. Potential evasions can arise from novel obfuscations or alternate character encodings that bypass normalizer unquoting.

---

## 5. Security Recommendations for Rule Tuning
1. **Double-Encoding & Base64 Inspection:** Integrate automatic base64 payload unpacking for body parameters.
2. **Behavioral Heuristics:** Implement adaptive scoring where multiple low-severity alerts from the same IP escalate to a block.
3. **Regex Optimization:** Re-evaluate high-overhead regexes to avoid catastrophic backtracking (ReDoS).
