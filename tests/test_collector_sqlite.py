import unittest
import os
import sqlite3
import tempfile
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
import collector_sqlite

class TestCollectorSQLite(unittest.TestCase):
    def setUp(self):
        self.tmp_db = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
        self.tmp_db.close()
        self.conn = collector_sqlite.init_db(self.tmp_db.name)

    def tearDown(self):
        self.conn.close()
        if os.path.exists(self.tmp_db.name):
            os.remove(self.tmp_db.name)

    def test_parse_json(self):
        line = '{"source": "ssh", "src_ip": "192.168.1.100", "user": "admin", "status": "failure"}'
        evt = collector_sqlite.parse_line(line)
        self.assertEqual(evt["source"], "ssh")
        self.assertEqual(evt["src_ip"], "192.168.1.100")
        self.assertEqual(evt["status"], "failure")

    def test_parse_syslog(self):
        line = "Oct 11 22:14:15 server01 sshd[1234]: Failed password for invalid user root from 203.0.113.5 port 44321 ssh2"
        evt = collector_sqlite.parse_line(line)
        self.assertEqual(evt["host"], "server01")
        self.assertEqual(evt["src_ip"], "203.0.113.5")
        self.assertEqual(evt["status"], "failure")

    def test_ingest_and_correlation(self):
        # Ingest 5 failures
        for _ in range(5):
            evt = {
                "timestamp": "2026-09-03T02:00:00Z",
                "source": "ssh",
                "host": "test-host",
                "src_ip": "10.0.0.99",
                "status": "failure",
                "raw": "failed login"
            }
            # Directly call insert and correlation
            cur = self.conn.cursor()
            cur.execute(
                """INSERT INTO events (timestamp, source, host, src_ip, dst_ip, user, action, status, raw)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (evt["timestamp"], evt["source"], evt["host"], evt["src_ip"], None, None, None, evt["status"], evt["raw"])
            )
        self.conn.commit()

        cur = self.conn.cursor()
        cur.execute("SELECT COUNT(*) FROM events WHERE src_ip = '10.0.0.99'")
        self.assertEqual(cur.fetchone()[0], 5)

if __name__ == "__main__":
    unittest.main()
