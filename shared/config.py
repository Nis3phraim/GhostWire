"""
GhostWire Configuration
========================
Central configuration file for both server and agent.
"""

import os

# ============================================================
# C2 DOMAIN CONFIGURATION
# ============================================================
# Real red teamers use domains that look like legitimate services.
# These should be real domains you REGISTER and OWN.
# For lab testing, these point to your local DNS server.
#
# The implant tries C2_DOMAIN first.
# If no response, it tries C2_DOMAIN_BACKUP_1.
# If that fails too, it tries C2_DOMAIN_BACKUP_2.

C2_DOMAIN            = "cdn-analytics-prod.com"
C2_DOMAIN_BACKUP_1   = "api-cloud-services.net"
C2_DOMAIN_BACKUP_2   = "updates-software-sync.io"

# All C2 domains (primary + backups)
C2_DOMAINS = [C2_DOMAIN, C2_DOMAIN_BACKUP_1, C2_DOMAIN_BACKUP_2]

C2_IP          = "127.0.0.1"

# ============================================================
# DNS SERVER SETTINGS
# ============================================================

DNS_LISTEN_IP   = "0.0.0.0"
DNS_LISTEN_PORT = 5354
DNS_UPSTREAM    = ["8.8.8.8", "1.1.1.1"]

# ============================================================
# BEACON SETTINGS (Agent side)
# ============================================================

BEACON_SLEEP   = 60
BEACON_JITTER  = 30
DNS_RESOLVERS  = ["8.8.8.8", "1.1.1.1"]

# How many hours to try a backup domain before giving up
DOMAIN_RETRY_HOURS = 24

# ============================================================
# DGA (Domain Generation Algorithm) SETTINGS
# ============================================================

DGA_SEED       = "GhostWire2025SecretKey"
DGA_LENGTH     = 12
DGA_HOURS_BACK = 24
# ============================================================
# DEBUG / VERBOSE MODE
# ============================================================
# Set to True for lab testing (shows DNS queries, chunks, etc.)
# Set to False for "production" stealth mode.
DEBUG = True


# ============================================================
# ENCRYPTION SETTINGS (Phase 2)
# ============================================================

# ============================================================
# ENCRYPTION SETTINGS (Phase 2)
# ============================================================

AES_KEY_FILE   = os.path.join(os.path.dirname(__file__), "..", "keys", "rsa_priv.pem")
RSA_PUB_FILE   = os.path.join(os.path.dirname(__file__), "..", "keys", "rsa_pub.pem")
RSA_PRIV_FILE  = os.path.join(os.path.dirname(__file__), "..", "keys", "rsa_priv.pem")

# Enable/disable encryption (set to True for production)
ENCRYPTION_ENABLED = True

# ============================================================
# DATABASE SETTINGS (Server side, Phase 4)
# ============================================================

DB_PATH        = os.path.join(os.path.dirname(__file__), "..", "data", "ghostwire.db")

# ============================================================
# LOGGING
# ============================================================

LOG_LEVEL      = "INFO"
LOG_FILE       = os.path.join(os.path.dirname(__file__), "..", "logs", "ghostwire.log")
