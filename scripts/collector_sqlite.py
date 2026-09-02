"""
HawkEye SIEM - SQLite Ingestion Daemon and Syslog Receiver.

Collects syslog (UDP) and JSON line logs, normalises them, stores them in an
indexed SQLite database, and checks correlation rules for alerts.
"""

from __future__ import annotations
import argparse
import json
import os
import re
import socket
import sqlite3
import sys
import time
from datetime import datetime, timezone

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    source TEXT NOT NULL,
    host TEXT,
    src_ip TEXT,
    dst_ip TEXT,
    user TEXT,
    action TEXT,
    status TEXT,
    raw TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_ts ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_source ON events(source);
CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events(src_ip);
CREATE INDEX IF NOT EXISTS idx_events_user ON events(user);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    entity TEXT NOT NULL,
    description TEXT NOT NULL,
    event_count INTEGER NOT NULL,
    mitre_id TEXT
);

CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_sev ON alerts(severity);
"""

SYSLOG_REGEX = re.compile(
    r"^(?:<(?P<pri>\d{1,3})>)?(?P<timestamp>[A-Za-z]{3}\s+\d+\s+[\d:]+|\d{4}-\d{2}-\d{2}T[\d:.]+Z?)\s+(?P<host>\S+)\s+(?P<tag>[^:\[\s]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$"
)

def init_db(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.executescript(SCHEMA)
    conn.commit()
    return conn

def parse_line(line: str) -> dict:
    line = line.strip()
    if not line:
        return {}
    
    # Try JSON
    if line.startswith("{") and line.endswith("}"):
        try:
            data = json.loads(line)
            ts = data.get("timestamp") or data.get("time") or datetime.now(timezone.utc).isoformat()
            return {
                "timestamp": ts,
                "source": data.get("source", "json"),
                "host": data.get("host") or data.get("hostname", "unknown"),
                "src_ip": data.get("src_ip") or data.get("client_ip") or data.get("ip"),
                "dst_ip": data.get("dst_ip"),
                "user": data.get("user") or data.get("username"),
                "action": data.get("action"),
                "status": data.get("status"),
                "raw": line
            }
        except Exception:
            pass

    # Try Syslog
    m = SYSLOG_REGEX.match(line)
    if m:
        gd = m.groupdict()
        msg = gd.get("message", "")
        # Extract potential IP
        ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", msg)
        user_match = re.search(r"\bfor (?:invalid user )?([a-zA-Z0-9_\-]+)", msg)
        
        status = "failure" if any(w in msg.lower() for w in ("fail", "invalid", "denied", "error", "drop")) else "success"
        action = "login" if "sshd" in (gd.get("tag") or "") else "traffic"

        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": gd.get("tag", "syslog"),
            "host": gd.get("host", "localhost"),
            "src_ip": ip_match.group(0) if ip_match else None,
            "dst_ip": None,
            "user": user_match.group(1) if user_match else None,
            "action": action,
            "status": status,
            "raw": line
        }

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": "raw",
        "host": "localhost",
        "src_ip": None,
        "dst_ip": None,
        "user": None,
        "action": None,
        "status": None,
        "raw": line
    }

def ingest_event(conn: sqlite3.Connection, evt: dict):
    if not evt or not evt.get("raw"):
        return
    cur = conn.cursor()
    cur.execute(
        """INSERT INTO events (timestamp, source, host, src_ip, dst_ip, user, action, status, raw)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            evt.get("timestamp"),
            evt.get("source", "unknown"),
            evt.get("host"),
            evt.get("src_ip"),
            evt.get("dst_ip"),
            evt.get("user"),
            evt.get("action"),
            evt.get("status"),
            evt.get("raw"),
        ),
    )
    conn.commit()
    check_correlation(conn, evt)

def check_correlation(conn: sqlite3.Connection, evt: dict):
    """Simple threshold rule engine: e.g. 5 failed logins from same src_ip within 5 mins."""
    src_ip = evt.get("src_ip")
    if not src_ip or evt.get("status") != "failure":
        return

    cur = conn.cursor()
    cur.execute(
        """SELECT COUNT(*) FROM events 
           WHERE src_ip = ? AND status = 'failure'
           AND timestamp >= datetime('now', '-5 minutes')""",
        (src_ip,)
    )
    count = cur.fetchone()[0]
    if count >= 5:
        # Check if alert already logged in last 5 mins
        cur.execute(
            """SELECT COUNT(*) FROM alerts 
               WHERE rule_id = 'brute-force' AND entity = ?
               AND timestamp >= datetime('now', '-5 minutes')""",
            (src_ip,)
        )
        if cur.fetchone()[0] == 0:
            cur.execute(
                """INSERT INTO alerts (timestamp, rule_id, severity, entity, description, event_count, mitre_id)
                   VALUES (?, 'brute-force', 'high', ?, ?, ?, 'T1110')""",
                (
                    datetime.now(timezone.utc).isoformat(),
                    src_ip,
                    f"Possible brute-force attack: {count} failed attempts from {src_ip}",
                    count
                )
            )
            conn.commit()
            print(f"[!] ALERT [high] T1110: Brute-force detected from {src_ip} ({count} failures)")

def ingest_file(conn: sqlite3.Connection, file_path: str):
    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            evt = parse_line(line)
            if evt:
                ingest_event(conn, evt)

def run_syslog_listener(conn: sqlite3.Connection, host: str, port: int):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, port))
    print(f"[*] Syslog UDP collector listening on {host}:{port}")
    try:
        while True:
            data, addr = sock.recvfrom(4096)
            msg = data.decode("utf-8", errors="replace")
            evt = parse_line(msg)
            if not evt.get("src_ip"):
                evt["src_ip"] = addr[0]
            ingest_event(conn, evt)
    except KeyboardInterrupt:
        print("\n[*] Stopping syslog listener.")
    finally:
        sock.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="HawkEye SQLite Log Collector & SIEM Ingestion Engine")
    parser.add_argument("--db", default="hawkeye.db", help="Path to SQLite database")
    parser.add_argument("--file", help="Path to JSON or Syslog file to ingest")
    parser.add_argument("--syslog", action="store_true", help="Start Syslog UDP listener")
    parser.add_argument("--host", default="0.0.0.0", help="Syslog bind address")
    parser.add_argument("--port", type=int, default=5140, help="Syslog bind port")
    args = parser.parse_args()

    conn = init_db(args.db)
    if args.file:
        print(f"[*] Ingesting log file: {args.file}")
        ingest_file(conn, args.file)
        print("[+] Ingestion complete.")
    elif args.syslog:
        run_syslog_listener(conn, args.host, args.port)
    else:
        parser.print_help()
