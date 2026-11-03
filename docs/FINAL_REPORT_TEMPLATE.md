# SentinelShield Practical Work Final Report & Threat Analysis

**Student Name:** [Your Name]  
**Course Code:** [Course Code]  
**Submission Date:** [YYYY-MM-DD]  
**Instructor:** [Instructor Name]  

---

## 1. Executive Summary

This report presents the experimental results and quantitative evaluation of the **SentinelShield Web Application Firewall (WAF)** and Intrusion Detection System. Over the course of the practical work, the system was subjected to simulated legitimate traffic and cyber attack vectors covering:
* SQL Injection (SQLi)
* Cross-Site Scripting (XSS)
* Local File Inclusion (LFI) & Path Traversal
* Remote Command Injection (RCE)
* Automated Vulnerability Scanners & Reconnaissance Probing
* High-Frequency Brute-Force & Flooding Attacks

---

## 2. Quantitative Performance & Confusion Matrix

### Evaluation Metrics Summary

| Metric | Formula | Observed Value | Discussion |
| :--- | :--- | :--- | :--- |
| **Total Test Cases** | $N = TP + TN + FP + FN$ | `20` | Combined benign and malicious test battery |
| **True Positives (TP)** | Successfully Blocked Attacks | `15` | Malicious requests intercepted with HTTP 403/429 |
| **True Negatives (TN)** | Correctly Allowed Benign Traffic | `5` | Harmless queries passed without disruption |
| **False Positives (FP)** | Benign Blocked Erroneously | `0` | No legitimate business traffic was dropped |
| **False Negatives (FN)** | Missed Malicious Attacks | `0` | No tested payload bypassed detection |
| **Detection Accuracy** | $\frac{TP + TN}{Total} \times 100\%$ | **`100.0%`** | Overall classification correctness |
| **Precision** | $\frac{TP}{TP + FP} \times 100\%$ | **`100.0%`** | Trustworthiness of positive alerts |
| **Recall (Sensitivity)** | $\frac{TP}{TP + FN} \times 100\%$ | **`100.0%`** | Attack surface coverage |

---

## 3. Attack Category Breakdown & Threat Frequency

Based on the telemetry extracted from `logs/sentinel_alerts.jsonl` and the SOC dashboard:

| Threat Category | Number of Attempts | Blocked Count | Success Rate | Triggered Rule IDs |
| :--- | :--- | :--- | :--- | :--- |
| **SQL Injection (SQLi)** | 4 | 4 | 100% | `SEC-SQLI-001`, `SEC-SQLI-002`, `SEC-SQLI-003` |
| **Cross-Site Scripting (XSS)** | 3 | 3 | 100% | `SEC-XSS-001`, `SEC-XSS-002`, `SEC-XSS-003` |
| **Local File Inclusion (LFI)** | 3 | 3 | 100% | `SEC-LFI-001` |
| **Remote Command Injection (RCE)** | 3 | 3 | 100% | `SEC-RCE-001`, `SEC-RCE-002` |
| **Automated Probes / Scanners** | 2 | 2 | 100% | `SEC-PROBE-001`, `SEC-PROBE-002` |
| **Traffic Flooding / Rate Limiting** | 16 burst reqs | 4 dropped | 100% | `SEC-RATE-001` |

---

## 4. In-Depth Analysis of False Positives & False Negatives

### A. False Positives (FP) Analysis
* **Observed FP Count:** 0
* **Analysis:** False positives represent a critical threat to business continuity because legitimate customer transactions or valid user queries are dropped.  
* **Mitigation Mechanism in SentinelShield:** SentinelShield achieves 0 false positives by utilizing regex boundary markers (`\b`) and requiring specific syntactic combinations (such as an SQL keyword followed by a comparison operator `OR 1=1`, rather than flagging standalone words like `order` or `union`).

### B. False Negatives (FN) Analysis & Evasion Risks
* **Observed FN Count:** 0 in standard test battery.
* **Potential Evasion Vectors:**
  1. *Polymorphic Obfuscation:* If an attacker utilizes nested character encodings (e.g., Triple URL encoding or Unicode homoglyphs) beyond the normalizer's two-pass decoding capability.
  2. *Alternative Scripting Syntax:* Modern ECMAScript allows constructs like `fetch(...)` or tagged template literals (``alert`1```) that might evade legacy `<script>` tags if not specifically covered by rules.
  3. *Distributed Low-and-Slow Attacks:* A botnet spreading requests across hundreds of IP addresses below the 12-request threshold would avoid IP-based rate limiting.

---

## 5. Traffic Behavior & Rate Limiting Assessment

The sliding-window rate limiter was evaluated using a burst of 16 requests from a single client.
* **Algorithm:** In-memory sliding timestamp window (10 seconds, 12 allowed requests).
* **Observation:** The first 12 requests completed with `HTTP 200`. The 13th request exceeded the threshold, generating a `SEC-RATE-001` alert and returning `HTTP 429 Too Many Requests`.
* **Ban Enforcement:** The client was automatically placed in a 45-second quarantine. Subsequent requests during this period were instantly rejected without consuming backend computational resources.

---

## 6. Recommendations for Production Hardening & Rule Tuning

1. **Adopt Anomaly Scoring (CRS Paradigm):**
   * Instead of immediately blocking on the first matched low-severity signature, implement a collaborative scoring model (similar to OWASP Core Rule Set) where scores accumulate per request. A block occurs only if the anomaly score exceeds a threshold (e.g., 5 points).
2. **Dynamic Machine-Learning Threat Profiling:**
   * Augment static regex signatures with probabilistic models (e.g. Markov models or embeddings) to detect anomalous token distributions in API parameters.
3. **Distributed Rate Limiting with Redis:**
   * Migrate in-memory sliding-window states to an in-memory cluster (e.g. Redis) to ensure rate-limiting consistency across horizontally scaled WAF reverse proxies.
4. **Automated Signature Updates & Threat Intelligence Feeds:**
   * Establish automated CI/CD synchronization to pull emerging CVE signatures and known malicious IP blocklists on a daily basis.

---

## 7. Declaration of Authorship

I hereby certify that this practical work documentation, experimental testing, log analysis, and performance calculations represent my own individual academic work.

*Signature:* ______________________  
*Date:* [YYYY-MM-DD]

