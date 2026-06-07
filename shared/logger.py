"""
GhostWire Logger
================
Writes all C2 activity to logs/ghostwire.log.
Console output stays the same — this adds a permanent file record.
"""

import logging
import os
from shared.config import LOG_LEVEL, LOG_FILE


def setup_logger():
    """Configure the GhostWire file logger."""
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

    logger = logging.getLogger('ghostwire')
    logger.setLevel(getattr(logging, LOG_LEVEL.upper(), logging.INFO))

    # Only add handler once
    if not logger.handlers:
        file_handler = logging.FileHandler(LOG_FILE)
        file_handler.setLevel(getattr(logging, LOG_LEVEL.upper(), logging.INFO))
        formatter = logging.Formatter(
            fmt='{asctime} [{levelname}] {message}',
            style='{',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger


def log_info(message):
    logging.getLogger('ghostwire').info(message)


def log_warning(message):
    logging.getLogger('ghostwire').warning(message)


def log_error(message):
    logging.getLogger('ghostwire').error(message)


def log_debug(message):
    logging.getLogger('ghostwire').debug(message)
