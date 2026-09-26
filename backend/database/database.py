import os
import sqlite3
import json
import datetime
from typing import Optional, Any

DEFAULT_DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "scans.db"
)


def get_db_path(custom_path: Optional[str] = None) -> str:
    """Resolves SQLite database path from parameter, environment, or default."""
    if custom_path:
        return custom_path
    env_path = os.environ.get("WORLD_MONITOR_DB_PATH")
    if env_path:
        return env_path
    return DEFAULT_DB_PATH


def get_db_connection(db_path: Optional[str] = None) -> sqlite3.Connection:
    """Creates a configured SQLite database connection with row access."""
    target_path = get_db_path(db_path)
    dir_name = os.path.dirname(target_path)
    if dir_name and not os.path.exists(dir_name):
        os.makedirs(dir_name, exist_ok=True)

    conn = sqlite3.connect(target_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db(db_path: Optional[str] = None) -> None:
    """Safely creates database tables and indexes if they do not exist."""
    conn = get_db_connection(db_path)
    try:
        with conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT NOT NULL,
                    scanned_at TEXT NOT NULL,
                    risk_level TEXT NOT NULL,
                    total_findings INTEGER NOT NULL DEFAULT 0,
                    severity_counts TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'completed',
                    raw_results TEXT
                );
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL,
                    title TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    category TEXT NOT NULL,
                    description TEXT NOT NULL,
                    metadata TEXT,
                    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
                );
            """)

            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_findings_scan_id
                ON findings(scan_id);
            """)

            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_scans_scanned_at
                ON scans(scanned_at DESC);
            """)
    finally:
        conn.close()


def save_scan(
    target: str,
    risk_summary: dict,
    findings: list[dict],
    raw_results: Optional[dict] = None,
    status: str = "completed",
    db_path: Optional[str] = None
) -> int:
    """
    Saves a completed scan and its findings using parameterized queries.
    Returns the generated scan ID.
    """
    conn = get_db_connection(db_path)
    try:
        scanned_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
        risk_level = risk_summary.get("risk_level", "Info")
        total_findings = risk_summary.get("total_findings", len(findings))
        severity_counts_json = json.dumps(risk_summary.get("severity_counts", {}))
        raw_results_json = json.dumps(raw_results or {})

        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO scans (
                target, scanned_at, risk_level, total_findings,
                severity_counts, status, raw_results
            ) VALUES (?, ?, ?, ?, ?, ?, ?);
            """,
            (
                target,
                scanned_at,
                risk_level,
                total_findings,
                severity_counts_json,
                status,
                raw_results_json
            )
        )
        scan_id = cursor.lastrowid

        for finding in findings:
            title = finding.get("title", "Untitled Finding")
            severity = finding.get("severity", "Info")
            category = finding.get("category", "General")
            description = finding.get("description", "")

            # Store any extra metadata without altering standard schema
            metadata = {
                k: v for k, v in finding.items()
                if k not in ("title", "severity", "category", "description")
            }
            metadata_json = json.dumps(metadata) if metadata else None

            cursor.execute(
                """
                INSERT INTO findings (
                    scan_id, title, severity, category, description, metadata
                ) VALUES (?, ?, ?, ?, ?, ?);
                """,
                (
                    scan_id,
                    title,
                    severity,
                    category,
                    description,
                    metadata_json
                )
            )

        conn.commit()
        return scan_id
    finally:
        conn.close()


def get_recent_scans(
    limit: int = 50,
    db_path: Optional[str] = None
) -> list[dict]:
    """Retrieves recent scan summary records using parameterized query."""
    conn = get_db_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, target, scanned_at, risk_level, total_findings,
                   severity_counts, status
            FROM scans
            ORDER BY id DESC
            LIMIT ?;
            """,
            (limit,)
        )
        rows = cursor.fetchall()
        scans = []
        for row in rows:
            record = dict(row)
            try:
                record["severity_counts"] = json.loads(record["severity_counts"])
            except Exception:
                record["severity_counts"] = {}
            scans.append(record)
        return scans
    finally:
        conn.close()


def get_scan_by_id(
    scan_id: int,
    db_path: Optional[str] = None
) -> Optional[dict]:
    """Retrieves a full scan record and all associated findings by scan ID."""
    conn = get_db_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, target, scanned_at, risk_level, total_findings,
                   severity_counts, status, raw_results
            FROM scans
            WHERE id = ?;
            """,
            (scan_id,)
        )
        scan_row = cursor.fetchone()
        if not scan_row:
            return None

        scan_record = dict(scan_row)
        try:
            scan_record["severity_counts"] = json.loads(scan_record["severity_counts"])
        except Exception:
            scan_record["severity_counts"] = {}

        try:
            scan_record["raw_results"] = (
                json.loads(scan_record["raw_results"])
                if scan_record.get("raw_results") else {}
            )
        except Exception:
            scan_record["raw_results"] = {}

        cursor.execute(
            """
            SELECT id, scan_id, title, severity, category, description, metadata
            FROM findings
            WHERE scan_id = ?
            ORDER BY id ASC;
            """,
            (scan_id,)
        )
        finding_rows = cursor.fetchall()

        findings_list = []
        for f_row in finding_rows:
            f_dict = {
                "id": f_row["id"],
                "scan_id": f_row["scan_id"],
                "title": f_row["title"],
                "severity": f_row["severity"],
                "category": f_row["category"],
                "description": f_row["description"],
            }
            if f_row["metadata"]:
                try:
                    extra_meta = json.loads(f_row["metadata"])
                    if isinstance(extra_meta, dict):
                        f_dict.update(extra_meta)
                except Exception:
                    pass
            findings_list.append(f_dict)

        scan_record["findings"] = findings_list
        return scan_record
    finally:
        conn.close()


def get_finding_by_id(
    finding_id: int | str,
    db_path: Optional[str] = None
) -> Optional[dict]:
    """
    Retrieves a single finding record by its database ID or evidence ID string.
    Unpacks stored JSON metadata into the returned dictionary.
    """
    conn = get_db_connection(db_path)
    try:
        cursor = conn.cursor()
        finding_row = None

        if isinstance(finding_id, int) or (isinstance(finding_id, str) and finding_id.isdigit()):
            cursor.execute(
                """
                SELECT id, scan_id, title, severity, category, description, metadata
                FROM findings
                WHERE id = ?;
                """,
                (int(finding_id),)
            )
            finding_row = cursor.fetchone()

        if not finding_row and isinstance(finding_id, str):
            # Query by evidence_id inside JSON metadata
            cursor.execute(
                """
                SELECT id, scan_id, title, severity, category, description, metadata
                FROM findings
                WHERE metadata LIKE ?
                ORDER BY id DESC
                LIMIT 1;
                """,
                (f'%"evidence_id": "{finding_id}"%',)
            )
            finding_row = cursor.fetchone()

        if not finding_row:
            return None

        f_dict = {
            "id": finding_row["id"],
            "scan_id": finding_row["scan_id"],
            "title": finding_row["title"],
            "severity": finding_row["severity"],
            "category": finding_row["category"],
            "description": finding_row["description"],
        }
        if finding_row["metadata"]:
            try:
                extra_meta = json.loads(finding_row["metadata"])
                if isinstance(extra_meta, dict):
                    f_dict.update(extra_meta)
            except Exception:
                pass

        return f_dict
    finally:
        conn.close()


def save_finding_ai_analysis(
    finding_id: int | str,
    ai_analysis: dict,
    db_path: Optional[str] = None
) -> bool:
    """
    Safely updates findings.metadata JSON with the AI analysis record
    without altering the SQLite table schema or breaking existing fields.
    """
    conn = get_db_connection(db_path)
    try:
        cursor = conn.cursor()
        target_id = None
        existing_meta = {}

        # 1. Resolve finding record
        if isinstance(finding_id, int) or (isinstance(finding_id, str) and finding_id.isdigit()):
            cursor.execute("SELECT id, metadata FROM findings WHERE id = ?;", (int(finding_id),))
            row = cursor.fetchone()
        else:
            cursor.execute(
                "SELECT id, metadata FROM findings WHERE metadata LIKE ? ORDER BY id DESC LIMIT 1;",
                (f'%"evidence_id": "{finding_id}"%',)
            )
            row = cursor.fetchone()

        if not row:
            return False

        target_id = row["id"]
        if row["metadata"]:
            try:
                existing_meta = json.loads(row["metadata"])
                if not isinstance(existing_meta, dict):
                    existing_meta = {}
            except Exception:
                existing_meta = {}

        # 2. Attach ai_analysis without overwriting deterministic fields
        existing_meta["ai_analysis"] = ai_analysis
        new_meta_json = json.dumps(existing_meta)

        cursor.execute(
            "UPDATE findings SET metadata = ? WHERE id = ?;",
            (new_meta_json, target_id)
        )
        conn.commit()
        return True
    finally:
        conn.close()


def save_assessment_ai_summary(
    scan_id: int,
    ai_summary: dict,
    db_path: Optional[str] = None
) -> bool:
    """
    Safely updates scans.raw_results JSON with the assessment AI summary
    without altering the SQLite table schema or breaking existing raw results.
    """
    conn = get_db_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT raw_results FROM scans WHERE id = ?;", (scan_id,))
        row = cursor.fetchone()
        if not row:
            return False

        existing_raw = {}
        if row["raw_results"]:
            try:
                existing_raw = json.loads(row["raw_results"])
                if not isinstance(existing_raw, dict):
                    existing_raw = {}
            except Exception:
                existing_raw = {}

        existing_raw["ai_summary"] = ai_summary
        new_raw_json = json.dumps(existing_raw)

        cursor.execute(
            "UPDATE scans SET raw_results = ? WHERE id = ?;",
            (new_raw_json, scan_id)
        )
        conn.commit()
        return True
    finally:
        conn.close()

