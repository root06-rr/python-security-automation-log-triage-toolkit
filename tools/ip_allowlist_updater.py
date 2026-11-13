"""
Tool: IP Allowlist Updater
Description: Reads an authorized IP allowlist and a revocation list from disk,
             removes matching unauthorized IP addresses, writes the cleaned
             list back to disk, and prints an audit summary.
"""


def read_ip_file(file_path):
    """Reads a whitespace- or newline-separated IP file and returns a list."""
    with open(file_path, "r", encoding="utf-8") as file:
        content = file.read()
    return content.split()


def update_allowlist(allowlist_path, remove_list_path):
    """Removes revoked IPs from the allowlist file and returns an audit summary."""
    ip_addresses = read_ip_file(allowlist_path)
    revoked_ips = read_ip_file(remove_list_path)

    initial_count = len(ip_addresses)
    removed_ips = []
    skipped_ips = []

    for ip in revoked_ips:
        if ip in ip_addresses:
            while ip in ip_addresses:
                ip_addresses.remove(ip)
            removed_ips.append(ip)
        else:
            skipped_ips.append(ip)

    updated_content = "\n".join(ip_addresses) + "\n"
    with open(allowlist_path, "w", encoding="utf-8") as file:
        file.write(updated_content)

    print("[*] IP Allowlist Update Summary")
    print(f"    Initial authorized entries : {initial_count}")
    print(f"    Revoked entries removed    : {len(removed_ips)} -> {removed_ips}")
    print(f"    Revoked entries not found  : {len(skipped_ips)} -> {skipped_ips}")
    print(f"    Remaining authorized count : {len(ip_addresses)}")


if __name__ == "__main__":
    ALLOWLIST_FILE = "sample_data/allowlist.txt"
    REMOVE_LIST_FILE = "sample_data/remove_list.txt"
    update_allowlist(ALLOWLIST_FILE, REMOVE_LIST_FILE)
