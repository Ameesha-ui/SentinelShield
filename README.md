# SentinelShield 🛡️

**Intrusion Detection & Web Application Firewall (WAF) Practical Lab System**

SentinelShield is a lightweight, educational Web Application Firewall and Intrusion Detection/Prevention System (IDS/IPS) built in Python. Designed for cybersecurity students and practitioners, it simulates realistic threat detection, request inspection, rate limiting, security event logging, and Security Operations Center (SOC) dashboard analysis.

---

## 🌟 Key Capabilities

1. **Multi-Vector Request Inspection Pipeline:**
   * Normalizes incoming inputs (unquoting single and double URL encodings, stripping null-bytes, folding case).
   * Simultaneously inspects URL paths, query parameters, HTTP headers (`User-Agent`, `Referer`), and request bodies (`JSON`, `x-www-form-urlencoded`, raw text).
2. **Signature-Based Rule Engine (`waf/rules.json`):**
   * Predefined, tested regular expressions targeting:
     * **SQL Injection (SQLi):** Tautologies, UNION exfiltration, destructive SQL commands, comment truncations.
     * **Cross-Site Scripting (XSS):** Script tags, inline event attributes (`onerror=`), javascript URIs.
     * **Local File Inclusion (LFI):** Directory traversal (`../`, `..\`, `%2e%2e%2f`), sensitive OS targets (`/etc/passwd`, `win.ini`).
     * **Remote Command Injection (RCE):** Semicolon/pipe chaining, subshells (`$(id)`).
     * **Reconnaissance & Scanners:** Automated scanner signatures (`nikto`, `sqlmap`), sensitive repository probes (`.git/config`, `.env`).
3. **Behavioral Rate Limiter & Sliding Window Monitor (`waf/rate_limiter.py`):**
   * Implements an in-memory sliding window algorithm (12 requests / 10-second window).
   * Automatically isolates flooding/brute-force IPs and enforces temporary bans (HTTP 429).
4. **Dual-Format Incident Logging (`waf/logger.py`):**
   * **JSON Lines (`logs/sentinel_alerts.jsonl`):** Machine-readable telemetry for SIEM and API consumption.
   * **Audit Log (`logs/sentinel_security.log`):** Formatted syslog-style audit trail with sanitized payloads.
5. **Interactive SOC Dashboard (`/dashboard`):**
   * Dark-mode Security Operations Center console.
   * Live KPI telemetry (Total Inspected, Allowed, Threats Blocked, Block Rate %).
   * Attack distribution visualization.
   * Real-time security incident stream.
   * Sliding-window IP reputation monitor with manual one-click unban.
   * Interactive WAF Sandbox Inspector to test custom payloads in the browser.
6. **Automated Attack Simulator & Report Generator (`simulator/`):**
   * Battery of 20 categorized test cases (benign vs malicious attacks).
   * Calculates Detection Accuracy, Precision, Recall, False Positives, and False Negatives.
   * Generates a complete Markdown report in `logs/practical_test_report.md`.

---

## 📁 Repository Structure

```text
sentinelshield/
├── app.py                      # Protected Web Application & SOC Dashboard Server
├── run.py                      # Multi-command launcher (server, test, simulate)
├── waf/                        # Core Web Application Firewall Engine
│   ├── engine.py               # Request inspection pipeline & normalization
│   ├── rules.json              # Predefined attack signature database
│   ├── rate_limiter.py         # Sliding window rate limiter & ban manager
│   ├── logger.py               # Dual-format security event logging system
│   └── models.py               # Dataclasses & enums (SecurityAlert, etc.)
├── simulator/                  # Attack Simulation & Student Evaluation
│   ├── attack_suite.py         # 20-scenario benign and attack test suite
│   └── generate_report.py      # Automated practical test report generator
├── logs/                       # Generated logs and test artifacts
│   ├── sentinel_alerts.jsonl   # Real-time JSON Lines alerts
│   ├── sentinel_security.log   # Formatted audit trail
│   └── practical_test_report.md# Quantitative evaluation report
├── docs/                       # Student Practical Lab Documentation
│   ├── ARCHITECTURE.md         # System architecture & threat lifecycle
│   ├── PRACTICAL_WORK_GUIDE.md # Step 1 to Step 6 laboratory manual
│   ├── STUDENT_JOURNAL_TEMPLATE.md # Pre-formatted student lab journal
│   └── FINAL_REPORT_TEMPLATE.md# Academic report template with metrics
├── templates/                  # Frontend HTML Templates
│   ├── dashboard.html          # Interactive SOC Operations Console
│   └── blocked.html            # 403 Forbidden security interception page
└── tests/                      # Automated Verification
    └── test_waf.py             # Pytest suite for WAF inspection & rules
```

---

## 🚀 Quick Start Guide

### 1. Launch the Protected Application & SOC Dashboard
```powershell
python app.py
# Or using the launcher:
python run.py
```
* **Protected Web Portal:** `http://127.0.0.1:5000`
* **SOC Operations Dashboard:** `http://127.0.0.1:5000/dashboard`

### 2. Run the Attack Simulation & Generate Report
```powershell
python simulator/generate_report.py
```
This executes the 20 attack scenarios, verifies rate limiting, and writes `logs/practical_test_report.md`.

### 3. Run Unit Tests with Pytest
```powershell
python -m pytest tests -v
```

---

## 📖 Practical Work Workflow for Students

1. **Step 1: System Architecture** — Review [ARCHITECTURE.md](docs/ARCHITECTURE.md) and understand the inline WAF reverse-proxy inspection flow.
2. **Step 2: Review Attack Signatures** — Inspect [rules.json](waf/rules.json) and examine regex patterns for SQLi, XSS, LFI, and RCE.
3. **Step 3: Simulate HTTP Requests** — Follow [PRACTICAL_WORK_GUIDE.md](docs/PRACTICAL_WORK_GUIDE.md) using `curl` or PowerShell to issue benign, malicious, and high-frequency flood requests.
4. **Step 4: Observe Detection Behavior** — Open the SOC Dashboard (`/dashboard`) to monitor live alerts and test custom strings in the Sandbox Inspector.
5. **Step 5: Examine Security Logs** — Analyze `logs/sentinel_security.log` and `logs/sentinel_alerts.jsonl` using terminal queries.
6. **Step 6: Document & Submit** — Fill out [STUDENT_JOURNAL_TEMPLATE.md](docs/STUDENT_JOURNAL_TEMPLATE.md) and generate your final evaluation report using [FINAL_REPORT_TEMPLATE.md](docs/FINAL_REPORT_TEMPLATE.md).

