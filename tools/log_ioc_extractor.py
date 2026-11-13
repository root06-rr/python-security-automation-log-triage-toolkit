"""
Tool: Log IOC Extractor & Failed Login Triage Parser
Description: Parses authentication log entries, extracts IPv4 addresses, email
             addresses, and login-count strings using regular expressions,
             counts failed login attempts per IP using a dictionary, and writes
             a structured alert summary report.
"""

import re


def parse_auth_log(log_path):
    """Reads the raw authentication log file and splits it into individual lines."""
    with open(log_path, "r", encoding="utf-8") as log_file:
        raw_logs = log_file.read()
    return raw_logs.strip().split("\n")


def extract_iocs_and_failures(log_lines, threshold=3):
    """Extracts IOCs via regex and counts failed authentication attempts per IP."""
    ipv4_pattern = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    email_pattern = r"\w+@\w+\.\w+"
    user_count_pattern = r"\w+:\s\d+"

    all_ips = []
    all_emails = []
    user_login_counts = []
    failed_attempts_by_ip = {}

    for line in log_lines:
        if not line.strip():
            continue

        found_ips = re.findall(ipv4_pattern, line)
        found_emails = re.findall(email_pattern, line)
        found_counts = re.findall(user_count_pattern, line)

        for ip in found_ips:
            all_ips.append(ip)

        for email in found_emails:
            all_emails.append(email)

        for entry in found_counts:
            user_login_counts.append(entry)

        if "FAILED" in line.upper() and found_ips:
            source_ip = found_ips[0]
            if source_ip in failed_attempts_by_ip:
                failed_attempts_by_ip[source_ip] = failed_attempts_by_ip[source_ip] + 1
            else:
                failed_attempts_by_ip[source_ip] = 1

    flagged_ips = {}
    for ip, count in failed_attempts_by_ip.items():
        if count >= threshold:
            flagged_ips[ip] = count

    return {
        "unique_ips": sorted(set(all_ips)),
        "unique_emails": sorted(set(all_emails)),
        "user_login_counts": user_login_counts,
        "failed_attempts_by_ip": failed_attempts_by_ip,
        "flagged_ips": flagged_ips,
        "threshold": threshold,
    }


def write_alert_report(results, report_path):
    """Writes extracted indicators and threshold alerts to a summary report file."""
    lines = [
        "SECURITY INCIDENT & LOG TRIAGE REPORT",
        "=====================================",
        f"Alert Threshold: {results['threshold']} or more failed attempts per source IP",
        "",
        "1. FLAGGED SOURCE IPS (THRESHOLD EXCEEDED)",
        "------------------------------------------",
    ]

    if results["flagged_ips"]:
        for ip, count in results["flagged_ips"].items():
            lines.append(f"[ALERT] Source IP: {ip} | Failed Attempts: {count}")
    else:
        lines.append("No source IPs exceeded the failed login threshold.")

    lines.extend([
        "",
        "2. ALL FAILED LOGIN COUNTS BY IP",
        "--------------------------------",
    ])
    for ip, count in results["failed_attempts_by_ip"].items():
        lines.append(f"{ip}: {count} failed attempt(s)")

    lines.extend([
        "",
        "3. UNIQUE EXTRACTED IPV4 INDICATORS",
        "-----------------------------------",
    ])
    for ip in results["unique_ips"]:
        lines.append(f"- {ip}")

    lines.extend([
        "",
        "4. UNIQUE EXTRACTED EMAIL INDICATORS",
        "------------------------------------",
    ])
    for email in results["unique_emails"]:
        lines.append(f"- {email}")

    if results["user_login_counts"]:
        lines.extend([
            "",
            "5. EXTRACTED USER LOGIN COUNT RECORDS",
            "-------------------------------------",
        ])
        for record in results["user_login_counts"]:
            lines.append(f"- {record}")

    report_text = "\n".join(lines) + "\n"
    with open(report_path, "w", encoding="utf-8") as report_file:
        report_file.write(report_text)

    print(report_text)


if __name__ == "__main__":
    LOG_FILE = "sample_logs/auth_events.log"
    REPORT_FILE = "reports/security_incident_report.txt"
    entries = parse_auth_log(LOG_FILE)
    triage_results = extract_iocs_and_failures(entries, threshold=3)
    write_alert_report(triage_results, REPORT_FILE)
