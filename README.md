# Python Security Automation & Log Triage Toolkit

**Author:** Rajat Rupam  
**Focus:** SOC Tier 1 Log Triage, Access Control Automation, and Indicator Extraction  

## 1. Overview

This repository combines and expands two earlier security scripting projects into a single toolkit built with the Python Standard Library:

1. **IP Allowlist Updater (`tools/ip_allowlist_updater.py`):** Expands on my [automated-ip-allowlist-algorithm](https://github.com/root06-rr/automated-ip-allowlist-algorithm) repository by reading both the authorized IP file and the revocation file directly from disk, removing matching entries, and writing the updated list back to disk.
2. **Log IOC Extractor (`tools/log_ioc_extractor.py`):** Expands on my [brute-force-failed-login-detector](https://github.com/root06-rr/brute-force-failed-login-detector) repository by adding regular expression indicator extraction (`re.findall()`), set-based deduplication, and threshold-based failed login counting to generate a structured alert report.

## 2. Scope and Boundaries

* **Local File Processing:** `ip_allowlist_updater.py` updates local text-based access lists and prints an audit summary. It does not push rules to a live network firewall.
* **Threshold-Based Log Triage:** `log_ioc_extractor.py` counts total `FAILED` events per source IP across the supplied log file and flags IPs meeting or exceeding the configured threshold (default: `3`). It does not calculate sliding time windows or block live traffic.

## 3. Requirements

* Python 3.8 or higher
* Uses only built-in Python modules (`re`). No external packages are required.

## 4. Usage

Clone the repository and run either tool from the project root directory:

```bash
git clone https://github.com/root06-rr/python-security-automation-log-triage-toolkit.git
cd python-security-automation-log-triage-toolkit

# Run Tool 1: Sanitize the IP allowlist using remove_list.txt
python tools/ip_allowlist_updater.py

# Run Tool 2: Parse auth_events.log, extract IOCs, and generate the incident report
python tools/log_ioc_extractor.py
```

## 5. Example Output

Running `python tools/ip_allowlist_updater.py` outputs:

```text
[*] IP Allowlist Update Summary
    Initial authorized entries : 8
    Revoked entries removed    : 3 -> ['192.168.1.105', '10.0.0.45', '172.16.0.12']
    Revoked entries not found  : 1 -> ['203.0.113.50']
    Remaining authorized count : 5
```

Running `python tools/log_ioc_extractor.py` writes `reports/security_incident_report.txt` and prints the flagged source IPs (`203.0.113.42` with 4 failures and `198.51.100.77` with 3 failures) along with unique extracted IPv4 and email indicators.

## 6. Related Repositories

* [automated-ip-allowlist-algorithm](https://github.com/root06-rr/automated-ip-allowlist-algorithm)
* [brute-force-failed-login-detector](https://github.com/root06-rr/brute-force-failed-login-detector)
