import os
import sqlite3
import hashlib
import datetime
from typing import Optional

DEFAULT_DEMO_DB_PATH = os.path.join(
    os.path.dirname(__file__),
    "demo_world_monitor.db"
)


def hash_demo_password(password: str) -> str:
    """Hashes a password with SHA-256 for demo purposes. (Demo only, not for production)."""
    return hashlib.sha256(f"demo_salt_{password}".encode("utf-8")).hexdigest()


def get_demo_db_path(custom_path: Optional[str] = None) -> str:
    """Resolves demo database path."""
    if custom_path:
        return custom_path
    return os.environ.get("DEMO_APP_DB_PATH", DEFAULT_DEMO_DB_PATH)


def get_demo_db_connection(db_path: Optional[str] = None) -> sqlite3.Connection:
    """Creates a configured connection to the demo SQLite database."""
    target_path = get_demo_db_path(db_path)
    dir_name = os.path.dirname(target_path)
    if dir_name and not os.path.exists(dir_name):
        os.makedirs(dir_name, exist_ok=True)

    conn = sqlite3.connect(target_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_demo_db(db_path: Optional[str] = None) -> None:
    """Creates demo database tables and seeds deterministic synthetic data."""
    conn = get_demo_db_connection(db_path)
    try:
        with conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS demo_users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL,
                    full_name TEXT NOT NULL,
                    email TEXT NOT NULL
                );
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS demo_reports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    category TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'Open',
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS demo_analytics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    metric_name TEXT NOT NULL,
                    metric_value TEXT NOT NULL,
                    unit TEXT NOT NULL,
                    timestamp TEXT NOT NULL
                );
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS demo_tokens (
                    token TEXT PRIMARY KEY,
                    username TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (username) REFERENCES demo_users(username) ON DELETE CASCADE
                );
            """)

            # Seed users if not present
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) AS cnt FROM demo_users;")
            if cursor.fetchone()["cnt"] == 0:
                demo_users = [
                    (
                        "admin_demo",
                        hash_demo_password("demo_admin_password"),
                        "Admin",
                        "Demo Administrator",
                        "admin.demo@worldmonitor.local"
                    ),
                    (
                        "analyst_demo",
                        hash_demo_password("demo_analyst_password"),
                        "Analyst",
                        "Demo Security Analyst",
                        "analyst.demo@worldmonitor.local"
                    ),
                    (
                        "operator_demo",
                        hash_demo_password("demo_operator_password"),
                        "Operator",
                        "Demo Operations Lead",
                        "operator.demo@worldmonitor.local"
                    ),
                    (
                        "user_demo",
                        hash_demo_password("demo_user_password"),
                        "Normal User",
                        "Demo Standard User",
                        "user.demo@worldmonitor.local"
                    )
                ]
                cursor.executemany(
                    """
                    INSERT INTO demo_users (username, password_hash, role, full_name, email)
                    VALUES (?, ?, ?, ?, ?);
                    """,
                    demo_users
                )

            # Seed reports if not present
            cursor.execute("SELECT COUNT(*) AS cnt FROM demo_reports;")
            if cursor.fetchone()["cnt"] == 0:
                demo_reports = [
                    (
                        "Global Border Sensor Drift Report",
                        "Surveillance",
                        "Synthetic telemetry anomaly observed across eastern sensor array node-4.",
                        "Under Review",
                        "analyst_demo",
                        "2026-09-24T10:00:00Z"
                    ),
                    (
                        "Maritime Logistics AIS Integrity Audit",
                        "Maritime",
                        "Automated AIS beacon frequency verification completed with zero telemetry discrepancies.",
                        "Resolved",
                        "operator_demo",
                        "2026-09-24T11:30:00Z"
                    ),
                    (
                        "Perimeter Access Anomaly Check",
                        "Physical Security",
                        "Routine perimeter access check reported 2 badge mismatches in sector C.",
                        "Open",
                        "admin_demo",
                        "2026-09-24T12:45:00Z"
                    )
                ]
                cursor.executemany(
                    """
                    INSERT INTO demo_reports (title, category, summary, status, created_by, created_at)
                    VALUES (?, ?, ?, ?, ?, ?);
                    """,
                    demo_reports
                )

            # Seed analytics if not present
            cursor.execute("SELECT COUNT(*) AS cnt FROM demo_analytics;")
            if cursor.fetchone()["cnt"] == 0:
                demo_analytics = [
                    ("Active Monitoring Nodes", "48", "nodes", "2026-09-24T12:00:00Z"),
                    ("Sensor Data Integrity Score", "99.4", "%", "2026-09-24T12:00:00Z"),
                    ("Average Telemetry Latency", "14.2", "ms", "2026-09-24T12:00:00Z"),
                    ("Event Stream Throughput", "1250", "events/sec", "2026-09-24T12:00:00Z")
                ]
                cursor.executemany(
                    """
                    INSERT INTO demo_analytics (metric_name, metric_value, unit, timestamp)
                    VALUES (?, ?, ?, ?);
                    """,
                    demo_analytics
                )
    finally:
        conn.close()


def get_user_by_username(username: str, db_path: Optional[str] = None) -> Optional[dict]:
    """Retrieves user by username using parameterized query."""
    conn = get_demo_db_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM demo_users WHERE username = ?;", (username,))
        row = cursor.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def get_user_by_token(token: str, db_path: Optional[str] = None) -> Optional[dict]:
    """Retrieves authenticated user by demo token."""
    conn = get_demo_db_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT u.id, u.username, u.role, u.full_name, u.email
            FROM demo_tokens t
            JOIN demo_users u ON t.username = u.username
            WHERE t.token = ?;
        """, (token,))
        row = cursor.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def create_demo_token(username: str, db_path: Optional[str] = None) -> str:
    """Generates and stores a demo session token for an authenticated user."""
    conn = get_demo_db_connection(db_path)
    try:
        token = f"demo-token-{username}-{hashlib.md5(f'{username}_{datetime.datetime.now()}'.encode()).hexdigest()[:12]}"
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with conn:
            conn.execute("INSERT OR REPLACE INTO demo_tokens (token, username, created_at) VALUES (?, ?, ?);",
                         (token, username, now))
        return token
    finally:
        conn.close()


def get_all_users(db_path: Optional[str] = None) -> list[dict]:
    """Retrieves all demo users (without password hashes)."""
    conn = get_demo_db_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, role, full_name, email FROM demo_users ORDER BY id ASC;")
        return [dict(r) for r in cursor.fetchall()]
    finally:
        conn.close()


def get_all_reports(db_path: Optional[str] = None) -> list[dict]:
    """Retrieves all reports."""
    conn = get_demo_db_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM demo_reports ORDER BY id DESC;")
        return [dict(r) for r in cursor.fetchall()]
    finally:
        conn.close()


def create_demo_report(title: str, category: str, summary: str, status: str, created_by: str, db_path: Optional[str] = None) -> dict:
    """Creates a new synthetic report."""
    conn = get_demo_db_connection(db_path)
    try:
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO demo_reports (title, category, summary, status, created_by, created_at)
                VALUES (?, ?, ?, ?, ?, ?);
            """, (title, category, summary, status, created_by, now))
            report_id = cursor.lastrowid
        return {
            "id": report_id,
            "title": title,
            "category": category,
            "summary": summary,
            "status": status,
            "created_by": created_by,
            "created_at": now
        }
    finally:
        conn.close()


def get_all_analytics(db_path: Optional[str] = None) -> list[dict]:
    """Retrieves all analytics records."""
    conn = get_demo_db_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM demo_analytics ORDER BY id ASC;")
        return [dict(r) for r in cursor.fetchall()]
    finally:
        conn.close()
