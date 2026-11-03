# SentinelShield - Student Practical Work Manual & Lab Guide

This manual guides students through hands-on practical exercises using **SentinelShield**, a lightweight Web Application Firewall (WAF) and Intrusion Detection System (IDS).

---

## Lab Prerequisites & Quick Start

### 1. Launching the SentinelShield Protected Server
Open a terminal in the project directory (`C:\Users\hp\.gemini\antigravity\scratch\sentinelshield`) and start the application:

```powershell
python app.py
```

* The protected web application is hosted at: `http://127.0.0.1:5000`
* The real-time SOC Dashboard is hosted at: `http://127.0.0.1:5000/dashboard`

---

## Step 1: Understanding the System Architecture

1. Review the architecture specification in [ARCHITECTURE.md](file:///C:/Users/hp/.gemini/antigravity/scratch/sentinelshield/docs/ARCHITECTURE.md).
2. Trace the request flow:
   $$\text{Client Request} \longrightarrow \text{Normalizer} \longrightarrow \text{Rate Limiter} \longrightarrow \text{Rule Engine} \longrightarrow \text{Logger} \longrightarrow \text{App Controller}$$
3. Open your web browser and navigate to:
   * Portal home: `http://127.0.0.1:5000/`
   * SOC Dashboard: `http://127.0.0.1:5000/dashboard`

---

## Step 2: Reviewing Predefined Attack Rules

Open and inspect [rules.json](file:///C:/Users/hp/.gemini/antigravity/scratch/sentinelshield/waf/rules.json). Examine the signature structure:

```json
{
  "id": "SEC-SQLI-001",
  "name": "SQL Injection: Boolean Tautology / OR Clause",
  "category": "SQL Injection (SQLi)",
  "severity": "CRITICAL",
  "pattern": "(?i)(\\b(or|and)\\b\\s+['\"\\d]+\\s*=\\s*['\"\\d]+)...",
  "target_components": ["query", "body", "path"]
}
```

### Questions to reflect on:
* Why is the regex prefixed with `(?i)`? *(It forces case-insensitivity, matching `OR`, `or`, and `oR`)*.
* Why are word boundaries (`\b`) essential? *(To prevent legitimate words like `ordinary` or `mentor` from triggering an SQLi false positive)*.

---

## Step 3: Simulating HTTP Requests (Manual & Automated)

Students will submit benign requests, followed by active attack payloads using `curl` or PowerShell.

### A. Benign Baseline Traffic (Expected: HTTP 200 OK)
Run these commands to confirm that normal, legitimate user traffic is permitted:

```powershell
# 1. Benign Search
curl.exe -i "http://127.0.0.1:5000/api/search?q=wireless+keyboard"

# 2. Benign Document Retrieval
curl.exe -i "http://127.0.0.1:5000/api/file?name=project_charter.pdf"

# 3. Benign System Ping
curl.exe -i "http://127.0.0.1:5000/api/system/ping?host=8.8.8.8"
```
*Expected Outcome:* Status `200 OK`. The request reaches the backend handler.

---

### B. Simulating SQL Injection (SQLi)
```powershell
# 1. Classic Boolean Tautology
curl.exe -i "http://127.0.0.1:5000/api/search?q='%20OR%20'1'='1"

# 2. UNION SELECT Data Exfiltration
curl.exe -i "http://127.0.0.1:5000/api/search?q=1%20UNION%20SELECT%20username,password%20FROM%20users"

# 3. Destructive Command Injection in Body
curl.exe -i -X POST "http://127.0.0.1:5000/api/login" `
  -H "Content-Type: application/json" `
  -d "{\"username\": \"admin'; DROP TABLE users; --\", \"password\": \"test\"}"
```
*Expected Outcome:* HTTP `403 Forbidden` with header `X-Sentinel-Rule: SEC-SQLI-*`.

---

### C. Simulating Cross-Site Scripting (XSS)
```powershell
# 1. Inline Script Tag
curl.exe -i "http://127.0.0.1:5000/api/search?q=%3Cscript%3Ealert('pwned')%3C/script%3E"

# 2. Event Handler Injection (onerror)
curl.exe -i -X POST "http://127.0.0.1:5000/api/feedback" `
  -H "Content-Type: application/json" `
  -d "{\"comment\": \"<img src=x onerror=alert(document.cookie)>\"}"
```
*Expected Outcome:* HTTP `403 Forbidden` with category `Cross-Site Scripting (XSS)`.

---

### D. Simulating Local File Inclusion (LFI) & Path Traversal
```powershell
# 1. Linux /etc/passwd extraction
curl.exe -i "http://127.0.0.1:5000/api/file?name=../../../../etc/passwd"

# 2. Windows win.ini extraction
curl.exe -i "http://127.0.0.1:5000/api/file?name=..\..\..\windows\win.ini"

# 3. Double/URL-Encoded Directory Traversal
curl.exe -i "http://127.0.0.1:5000/api/file?name=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
```
*Expected Outcome:* HTTP `403 Forbidden` with rule `SEC-LFI-001`.

---

### E. Simulating Remote Command Injection (RCE)
```powershell
# 1. Shell command chaining via semicolon
curl.exe -i "http://127.0.0.1:5000/api/system/ping?host=127.0.0.1;%20whoami"

# 2. Subshell command substitution
curl.exe -i "http://127.0.0.1:5000/api/system/ping?host=%24(id)"
```
*Expected Outcome:* HTTP `403 Forbidden` with category `Remote Command Injection (RCE)`.

---

### F. Simulating Scanner Probes & Reconnaissance
```powershell
# 1. Nikto Scanner User-Agent Probing
curl.exe -i "http://127.0.0.1:5000/api/search?q=test" -H "User-Agent: Nikto/2.1.6"

# 2. Exposed Sensitive Repository File Probing
curl.exe -i "http://127.0.0.1:5000/.git/config"
```
*Expected Outcome:* HTTP `403 Forbidden` with rule `SEC-PROBE-001` or `SEC-PROBE-002`.

---

### G. Simulating Traffic Flooding & Rate Limiting
Execute a rapid loop of 15 requests within 2 seconds:

```powershell
1..15 | ForEach-Object {
    curl.exe -s -o /dev/null -w "%{http_code}`n" "http://127.0.0.1:5000/api/search?q=ping_$_"
}
```
*Expected Outcome:* The first 12 requests return `200`. Subsequent requests return `429 Too Many Requests`. The client IP is banned for 45 seconds.

---

## Step 4: Observing Detection Behavior in the SOC Dashboard

1. Open `http://127.0.0.1:5000/dashboard` in your browser.
2. Observe the KPI cards: Total Inspected, Allowed, Blocked, and Block Rate %.
3. Inspect the **Security Incident Stream** table:
   * Identify the Alert ID, Timestamp, Category, Severity, and Trigger Payload.
4. Check the **IP Reputation & Traffic Behavior Tracking** table:
   * View the active request count in the sliding window.
   * Notice any IP in `BANNED` status. Test the `Unban` button to restore access.
5. Use the **Request Sandbox Inspector** in the sidebar:
   * Enter a custom payload (e.g. `' OR 1=1 --`) and evaluate it interactively.

---

## Step 5: Security Log File Examination

SentinelShield generates two log formats inside `logs/`:
1. `sentinel_alerts.jsonl` (JSON Lines for automated ingestion)
2. `sentinel_security.log` (Formatted security audit trail)

### PowerShell Analysis Commands

```powershell
# View the last 10 security alerts in the audit trail:
Get-Content logs\sentinel_security.log -Tail 10

# Count attacks by category:
Get-Content logs\sentinel_alerts.jsonl | ConvertFrom-Json | Group-Object category -NoElement

# Identify top offender client IPs:
Get-Content logs\sentinel_alerts.jsonl | ConvertFrom-Json | Group-Object client_ip | Sort-Object Count -Descending
```

---

## Step 6: Automated Testing & Report Generation

To execute the entire 20-scenario battery automatically and generate the student evaluation report:

```powershell
python simulator/generate_report.py
```

The tool writes a complete markdown analysis to `logs/practical_test_report.md`.  
Students should review the generated metrics:
* **Detection Accuracy:** $\frac{\text{True Positives} + \text{True Negatives}}{\text{Total Tests}}$
* **Precision:** $\frac{\text{True Positives}}{\text{True Positives} + \text{False Positives}}$
* **Recall:** $\frac{\text{True Positives}}{\text{True Positives} + \text{False Negatives}}$

