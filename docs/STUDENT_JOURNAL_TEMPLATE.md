# SentinelShield Practical Work Journal

**Student Name:** [Your Name / Student ID]  
**Course / Module:** Cybersecurity & Web Defense Operations  
**Date of Execution:** [YYYY-MM-DD]  
**System Evaluated:** SentinelShield Web Application Firewall (WAF) & IDS  

---

## 1. Purpose of the Experiment
*Explain in your own words the objectives of this laboratory session, focusing on how WAFs inspect requests, pattern-based detection, rate limiting, and incident logging.*

> **Student Notes:**  
> [Write 1-2 paragraphs detailing the objective here...]

---

## 2. Tools & Environment Used
List all tools, operating environments, and programming utilities utilized during the practical work:

| Tool / Technology | Version / Specification | Purpose in Lab |
| :--- | :--- | :--- |
| **Operating System** | Windows 10/11 / Linux | Host environment |
| **Python** | 3.12+ | WAF Engine & Protected Flask Application |
| **cURL / PowerShell** | curl.exe | Crafting and issuing manual HTTP requests |
| **Web Browser** | Chrome / Firefox / Edge | Interacting with SOC Dashboard & Web Portal |
| **SentinelShield Engine** | v1.0 | Pattern matcher, rate limiter, and audit logger |

---

## 3. Step-by-Step Practical Execution

### Task 1: System Baseline & Benign Traffic Testing
*Document your test with harmless queries. Show the HTTP status and confirm that normal user functionality is unimpeded.*

* **Command Executed:**
  ```powershell
  curl.exe -i "http://127.0.0.1:5000/api/search?q=wireless+keyboard"
  ```
* **Observed Response (Headers & Status Code):**
  ```text
  [Insert terminal output here]
  ```
* **Outcome:** ALLOWED (HTTP 200 OK)

---

### Task 2: SQL Injection (SQLi) Testing
*Test boolean tautology and UNION SELECT injection payloads.*

* **Command Executed:**
  ```powershell
  curl.exe -i "http://127.0.0.1:5000/api/search?q='%20OR%20'1'='1"
  ```
* **Observed Response:**
  ```text
  [Insert terminal output here]
  ```
* **Rule Triggered:** `SEC-SQLI-001` (SQL Injection: Boolean Tautology / OR Clause)
* **Outcome:** BLOCKED (HTTP 403 Forbidden)

---

### Task 3: Cross-Site Scripting (XSS) Testing
*Test inline script tags and HTML event handlers.*

* **Command Executed:**
  ```powershell
  curl.exe -i "http://127.0.0.1:5000/api/search?q=%3Cscript%3Ealert('pwned')%3C/script%3E"
  ```
* **Rule Triggered:** `SEC-XSS-001` (Cross-Site Scripting)
* **Outcome:** BLOCKED (HTTP 403 Forbidden)

---

### Task 4: Local File Inclusion (LFI) & Path Traversal Testing
*Test traversal sequences attempting to reach sensitive operating system files.*

* **Command Executed:**
  ```powershell
  curl.exe -i "http://127.0.0.1:5000/api/file?name=../../../../etc/passwd"
  ```
* **Rule Triggered:** `SEC-LFI-001` (Directory Traversal Sequences)
* **Outcome:** BLOCKED (HTTP 403 Forbidden)

---

### Task 5: Remote Command Injection (RCE) Testing
*Test shell metacharacter chaining.*

* **Command Executed:**
  ```powershell
  curl.exe -i "http://127.0.0.1:5000/api/system/ping?host=127.0.0.1;%20whoami"
  ```
* **Rule Triggered:** `SEC-RCE-001` (Command Injection)
* **Outcome:** BLOCKED (HTTP 403 Forbidden)

---

### Task 6: Behavior Monitoring & Flooding (Rate Limiting)
*Test rapid consecutive requests from a single client IP.*

* **Execution Method:** Loop of 15 requests within 2 seconds.
* **Observed Behavior:**
  * Requests 1 to 12 returned `HTTP 200`.
  * Request 13 onwards returned `HTTP 429 Too Many Requests`.
  * The IP status changed to `BANNED` for 45 seconds.

---

## 4. Observations & Dashboard Screenshots

*Insert screenshots or descriptions of the SentinelShield SOC Dashboard (`http://127.0.0.1:5000/dashboard`).*

### Screenshot 1: SOC Dashboard KPIs & Threat Distribution
> *[Insert screenshot of the KPI stat cards (Total Inspected, Allowed, Blocked, Block Rate) and the Attack Category breakdown]*

### Screenshot 2: Security Incident Stream & Rate Limit Monitor
> *[Insert screenshot of the real-time alert log table showing Alert IDs, timestamps, IPs, and matched rules]*

---

## 5. Security Log File Examination & Interpretation

Examine `logs/sentinel_security.log` and `logs/sentinel_alerts.jsonl`. Paste 3 distinct alert entries below and explain each field:

```text
[2026-10-31 02:33:15] [WARNING] [SentinelShield] ACTION=BLOCK | SEVERITY=CRITICAL | CLIENT_IP=198.51.100.21 | METHOD=GET | PATH=/api/search | RULE=SEC-SQLI-001 (SQL Injection: Boolean Tautology / OR Clause) | CATEGORY='SQL Injection (SQLi)' | TARGET=query_param:q | PAYLOAD='' OR '1'='1'
```

### Interpretation of Log Fields:
1. **Timestamp:** Indicates the exact second the request reached the interceptor. Useful for event correlation in SIEM.
2. **Client IP:** Identifies the originating address for IP reputation and geolocation tracking.
3. **Action:** Shows whether the system operated in `BLOCK` (prevention) or `FLAG` (monitoring) mode.
4. **Target & Payload:** Pinpoints the exact parameter (`query_param:q`) and malicious string, enabling security analysts to triage whether the incident is a false alarm or a genuine exploitation attempt.

---

## 6. Student Conclusions & Learning Takeaways
*Summarize key insights gained regarding Web Application Firewalls, regular expression rules, and sliding-window rate limiting.*

> **Student Notes:**  
> [Write conclusion here...]

