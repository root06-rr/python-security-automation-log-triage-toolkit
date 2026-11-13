# Python Concepts Applied in This Toolkit

This document maps the core Python fundamentals used in `tools/ip_allowlist_updater.py` and `tools/log_ioc_extractor.py` to their security automation functions.

| Python Concept | Implementation Details | Security Triage Function |
| :--- | :--- | :--- |
| `with open()` | Opens files in read (`"r"`) and write (`"w"`) modes with automatic descriptor cleanup | Safely ingests `allowlist.txt`, `remove_list.txt`, and `auth_events.log` without resource leaks |
| `.read()` and `.split()` | Reads raw file text into a string and splits it into a list by whitespace or newline (`"\n"`) | Converts flat text files into structured lists of IPs and log lines |
| `.join()` and `.write()` | Joins processed Python lists back into newline-delimited strings and writes them to disk | Persists sanitized allowlists and formatted incident reports |
| `for` loops and `if` / `else` | Iterates over parsed records and evaluates membership or threshold conditions | Checks whether an IP exists in the allowlist and filters `FAILED` login lines |
| Lists and `.remove()` | Stores ordered collections and removes unauthorized IP entries safely after checking membership | Prunes revoked IP addresses from the authorized list |
| Dictionaries (`{}`) | Maps unique source IP keys to integer failure counts | Tracks failed authentication totals per IP address |
| Sets (`set()`) | Eliminates duplicate entries from extracted indicator lists | Produces deduplicated lists of unique IPv4 and email indicators |
| `re.findall()` | Applies regular expression patterns (`\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`, `\w+@\w+\.\w+`, `\w+:\s\d+`) | Extracts network and account indicators directly from unstructured log lines |
