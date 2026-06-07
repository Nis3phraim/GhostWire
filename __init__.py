"""
GhostWire Shared Package
========================
Shared protocol, configuration, and DGA definitions.
"""

from .protocol import (
    MSG_REGISTER, MSG_BEACON, MSG_DATA, MSG_CMDREQ,
    MSG_UPLOAD, MSG_DOWNLOAD, MSG_EXIT,
    RESP_ACK, RESP_CMD, RESP_ERR, RESP_NOOP, RESP_EXIT,
    MAX_DNS_LABEL, MAX_DNS_QUERY, DNS_PORT,
    DEFAULT_SLEEP, DEFAULT_JITTER,
    build_query, parse_query
)

from .config import (
    C2_DOMAIN, C2_IP, DNS_LISTEN_IP, DNS_LISTEN_PORT,
    DNS_UPSTREAM, BEACON_SLEEP, BEACON_JITTER,
    DNS_RESOLVERS, DGA_SEED, DGA_LENGTH, DGA_HOURS_BACK,
    LOG_LEVEL
)

from .dga import DGA
