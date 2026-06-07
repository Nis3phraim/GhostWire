"""
GhostWire Database Module
=========================
SQLite database for persistent storage of sessions,
commands, and results. Everything survives server restarts.
"""

import os
import sqlite3
from datetime import datetime, timezone


def get_connection(db_path):
    """Get a database connection."""
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path):
    """Create tables if they don't exist."""
    conn = get_connection(db_path)
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            session_id TEXT PRIMARY KEY,
            ip_address TEXT,
            registered_at TIMESTAMP,
            last_beacon TIMESTAMP,
            encrypted INTEGER DEFAULT 0,
            closed INTEGER DEFAULT 0
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS commands (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT,
            command TEXT,
            queued_at TIMESTAMP,
            sent_at TIMESTAMP,
            completed_at TIMESTAMP,
            status TEXT DEFAULT 'queued',
            FOREIGN KEY (session_id) REFERENCES sessions(session_id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT,
            data TEXT,
            result_type TEXT DEFAULT 'command',
            received_at TIMESTAMP,
            FOREIGN KEY (session_id) REFERENCES sessions(session_id)
        )
    ''')

    conn.commit()
    conn.close()


def save_session(db_path, session_id, ip_address, encrypted=False):
    """Save a new session."""
    conn = get_connection(db_path)
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        'INSERT OR REPLACE INTO sessions (session_id, ip_address, registered_at, last_beacon, encrypted, closed) VALUES (?, ?, ?, ?, ?, 0)',
        (session_id, ip_address, now, now, 1 if encrypted else 0)
    )
    conn.commit()
    conn.close()


def update_beacon(db_path, session_id):
    """Update last beacon timestamp."""
    conn = get_connection(db_path)
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        'UPDATE sessions SET last_beacon = ? WHERE session_id = ?',
        (now, session_id)
    )
    conn.commit()
    conn.close()


def close_session(db_path, session_id):
    """Mark a session as closed."""
    conn = get_connection(db_path)
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        'UPDATE sessions SET closed = 1, last_beacon = ? WHERE session_id = ?',
        (now, session_id)
    )
    conn.commit()
    conn.close()


def save_command(db_path, session_id, command):
    """Log a queued command."""
    conn = get_connection(db_path)
    now = datetime.now(timezone.utc).isoformat()
    cursor = conn.execute(
        'INSERT INTO commands (session_id, command, queued_at, status) VALUES (?, ?, ?, ?)',
        (session_id, command, now, 'queued')
    )
    conn.commit()
    command_id = cursor.lastrowid
    conn.close()
    return command_id


def update_command_sent(db_path, command_id):
    """Mark a command as sent to the implant."""
    conn = get_connection(db_path)
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        'UPDATE commands SET sent_at = ?, status = ? WHERE id = ?',
        (now, 'sent', command_id)
    )
    conn.commit()
    conn.close()


def update_command_completed(db_path, command_id):
    """Mark a command as completed."""
    conn = get_connection(db_path)
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        'UPDATE commands SET completed_at = ?, status = ? WHERE id = ?',
        (now, 'completed', command_id)
    )
    conn.close()


def save_result(db_path, session_id, data, result_type='command'):
    """Save a result (command output, upload, download)."""
    conn = get_connection(db_path)
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        'INSERT INTO results (session_id, data, result_type, received_at) VALUES (?, ?, ?, ?)',
        (session_id, data, result_type, now)
    )
    conn.commit()
    conn.close()


def get_results(db_path, session_id, limit=50):
    """Get results for a session."""
    conn = get_connection(db_path)
    cursor = conn.execute(
        'SELECT data, result_type, received_at FROM results WHERE session_id = ? ORDER BY received_at DESC LIMIT ?',
        (session_id, limit)
    )
    results = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return results


def get_all_sessions(db_path):
    """Get all sessions (active and closed)."""
    conn = get_connection(db_path)
    cursor = conn.execute(
        'SELECT * FROM sessions ORDER BY registered_at DESC'
    )
    sessions = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return sessions


def get_command_history(db_path, session_id, limit=50):
    """Get command history for a session."""
    conn = get_connection(db_path)
    cursor = conn.execute(
        'SELECT command, queued_at, sent_at, completed_at, status FROM commands WHERE session_id = ? ORDER BY queued_at DESC LIMIT ?',
        (session_id, limit)
    )
    commands = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return commands
