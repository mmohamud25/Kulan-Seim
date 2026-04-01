"""
db.py — Kulan Threat Intelligence Platform
Database layer: SQLite schema, insert, query helpers.

Author: Mohamed Mohamud
Project: Kulan TIP (Threat Intelligence Platform)
"""

import sqlite3
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), "data", "kulan_tip.db")


def get_connection():
    """Return a sqlite3 connection with row_factory for dict-style access."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """
    Initialize the database schema.
    Creates all tables if they do not already exist.
    Safe to call on every startup.
    """
    conn = get_connection()
    cursor = conn.cursor()

    # ── INDICATORS OF COMPROMISE ──────────────────────────────────────────────
    # Core table. Each row is one IOC ingested from any feed.
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS iocs (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            indicator       TEXT NOT NULL,          -- IP, domain, hash, CVE ID
            ioc_type        TEXT NOT NULL,           -- ip | domain | hash | cve | url
            severity        TEXT,                    -- critical | high | medium | low
            category        TEXT,                    -- malware | phishing | ransomware | c2 | exploit | scanner
            source          TEXT,                    -- CISA_KEV | OTX | AbuseIPDB | OSINT
            description     TEXT,
            threat_score    REAL DEFAULT 0.0,        -- 0–100, calculated by score.py
            first_seen      TEXT,                    -- ISO 8601
            last_seen       TEXT,                    -- ISO 8601
            status          TEXT DEFAULT 'active',   -- active | watching | resolved
            raw_json        TEXT,                    -- original feed payload (JSON string)
            UNIQUE(indicator, source)                -- prevent duplicate IOCs from same source
        )
    """)

    # ── CISA KNOWN EXPLOITED VULNERABILITIES ─────────────────────────────────
    # Mirrors the CISA KEV catalog structure exactly.
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS cisa_kev (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id              TEXT UNIQUE NOT NULL,
            vendor_project      TEXT,
            product             TEXT,
            vulnerability_name  TEXT,
            date_added          TEXT,
            short_description   TEXT,
            required_action     TEXT,
            due_date            TEXT,
            known_ransomware    TEXT,               -- 'Known' or 'Unknown'
            threat_score        REAL DEFAULT 0.0,
            ingested_at         TEXT
        )
    """)

    # ── ALERT QUEUE ───────────────────────────────────────────────────────────
    # SOC-style alert log. Every significant event writes here.
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            title           TEXT NOT NULL,
            detail          TEXT,
            severity        TEXT,                   -- critical | high | medium | low
            category        TEXT,
            ioc_ref         TEXT,                   -- indicator this alert relates to
            source          TEXT,
            status          TEXT DEFAULT 'open',    -- open | investigating | resolved
            created_at      TEXT,
            updated_at      TEXT
        )
    """)

    # ── INGEST LOG ────────────────────────────────────────────────────────────
    # Audit trail of every feed sync run.
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ingest_log (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            feed_name       TEXT NOT NULL,
            run_at          TEXT,
            status          TEXT,                   -- success | error | partial
            records_added   INTEGER DEFAULT 0,
            records_skipped INTEGER DEFAULT 0,
            error_message   TEXT
        )
    """)

    conn.commit()
    conn.close()
    print(f"[db] Database initialized at {DB_PATH}")


# ─── IOC HELPERS ─────────────────────────────────────────────────────────────

def upsert_ioc(indicator, ioc_type, severity, category, source,
               description="", threat_score=0.0, raw_json="", status="active"):
    """
    Insert a new IOC or update last_seen + threat_score if it already exists.
    Returns: 'inserted' | 'updated' | 'error'
    """
    now = datetime.utcnow().isoformat()
    conn = get_connection()
    try:
        cursor = conn.cursor()
        # Check if IOC already exists for this source
        cursor.execute(
            "SELECT id, first_seen FROM iocs WHERE indicator=? AND source=?",
            (indicator, source)
        )
        existing = cursor.fetchone()

        if existing:
            cursor.execute("""
                UPDATE iocs
                SET last_seen=?, threat_score=?, severity=?, status=?, description=?
                WHERE indicator=? AND source=?
            """, (now, threat_score, severity, status, description, indicator, source))
            conn.commit()
            return "updated"
        else:
            cursor.execute("""
                INSERT INTO iocs
                    (indicator, ioc_type, severity, category, source, description,
                     threat_score, first_seen, last_seen, status, raw_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (indicator, ioc_type, severity, category, source, description,
                  threat_score, now, now, status, raw_json))
            conn.commit()
            return "inserted"
    except Exception as e:
        return f"error: {e}"
    finally:
        conn.close()


def get_iocs(severity=None, category=None, status=None, limit=200):
    """
    Query IOCs with optional filters.
    Returns a list of dicts sorted by threat_score DESC.
    """
    conn = get_connection()
    cursor = conn.cursor()
    query = "SELECT * FROM iocs WHERE 1=1"
    params = []

    if severity:
        query += " AND severity=?"
        params.append(severity)
    if category:
        query += " AND category=?"
        params.append(category)
    if status:
        query += " AND status=?"
        params.append(status)

    query += " ORDER BY threat_score DESC, last_seen DESC LIMIT ?"
    params.append(limit)

    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_ioc_counts():
    """Return severity counts for KPI metrics."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT severity, COUNT(*) as cnt
        FROM iocs
        WHERE status != 'resolved'
        GROUP BY severity
    """)
    rows = cursor.fetchall()
    conn.close()
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for row in rows:
        if row["severity"] in counts:
            counts[row["severity"]] = row["cnt"]
    return counts


# ─── CISA KEV HELPERS ────────────────────────────────────────────────────────

def upsert_kev(entry: dict):
    """
    Insert or update a CISA KEV entry.
    entry dict keys mirror the CISA JSON catalog fields.
    """
    now = datetime.utcnow().isoformat()
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO cisa_kev
                (cve_id, vendor_project, product, vulnerability_name,
                 date_added, short_description, required_action, due_date,
                 known_ransomware, threat_score, ingested_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(cve_id) DO UPDATE SET
                threat_score=excluded.threat_score,
                known_ransomware=excluded.known_ransomware,
                ingested_at=excluded.ingested_at
        """, (
            entry.get("cveID", ""),
            entry.get("vendorProject", ""),
            entry.get("product", ""),
            entry.get("vulnerabilityName", ""),
            entry.get("dateAdded", ""),
            entry.get("shortDescription", ""),
            entry.get("requiredAction", ""),
            entry.get("dueDate", ""),
            entry.get("knownRansomwareCampaignUse", "Unknown"),
            entry.get("threat_score", 0.0),
            now
        ))
        conn.commit()
        return "ok"
    except Exception as e:
        return f"error: {e}"
    finally:
        conn.close()


def get_kev_entries(limit=50, ransomware_only=False):
    """Return KEV entries sorted by date_added DESC."""
    conn = get_connection()
    cursor = conn.cursor()
    query = "SELECT * FROM cisa_kev"
    if ransomware_only:
        query += " WHERE known_ransomware='Known'"
    query += " ORDER BY date_added DESC, threat_score DESC LIMIT ?"
    cursor.execute(query, (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_kev_count():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) as cnt FROM cisa_kev")
    row = cursor.fetchone()
    conn.close()
    return row["cnt"] if row else 0


# ─── ALERT HELPERS ───────────────────────────────────────────────────────────

def create_alert(title, detail, severity, category, ioc_ref="", source=""):
    """Write a new alert to the queue."""
    now = datetime.utcnow().isoformat()
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO alerts (title, detail, severity, category, ioc_ref, source, status, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, 'open', ?, ?)
    """, (title, detail, severity, category, ioc_ref, source, now, now))
    conn.commit()
    conn.close()


def get_alerts(status="open", limit=20):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM alerts WHERE status=? ORDER BY created_at DESC LIMIT ?",
        (status, limit)
    )
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_alert_count(status="open"):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) as cnt FROM alerts WHERE status=?", (status,))
    row = cursor.fetchone()
    conn.close()
    return row["cnt"] if row else 0


# ─── INGEST LOG ──────────────────────────────────────────────────────────────

def log_ingest(feed_name, status, records_added=0, records_skipped=0, error_message=""):
    now = datetime.utcnow().isoformat()
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO ingest_log (feed_name, run_at, status, records_added, records_skipped, error_message)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (feed_name, now, status, records_added, records_skipped, error_message))
    conn.commit()
    conn.close()


if __name__ == "__main__":
    init_db()
