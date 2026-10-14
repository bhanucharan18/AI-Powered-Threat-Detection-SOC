"""SQLite storage. All queries are parameterized; dynamic SQL uses only fixed fragments."""
import math
import sqlite3
from datetime import datetime, timezone

import config
import detector

SCHEMA = """
CREATE TABLE IF NOT EXISTS ingestion_batches (
    id INTEGER PRIMARY KEY, filename TEXT NOT NULL, file_hash TEXT NOT NULL UNIQUE,
    uploaded_at TEXT NOT NULL, rows_processed INTEGER NOT NULL,
    rows_accepted INTEGER NOT NULL, rows_rejected INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY,
    batch_id INTEGER NOT NULL REFERENCES ingestion_batches(id) ON DELETE CASCADE,
    row_number INTEGER NOT NULL, timestamp TEXT NOT NULL, username TEXT NOT NULL,
    source_ip TEXT NOT NULL, status TEXT NOT NULL CHECK (status IN ('success','failure')),
    UNIQUE (batch_id, row_number));
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_ip ON events(source_ip);
CREATE INDEX IF NOT EXISTS idx_events_user ON events(username);
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY, dedupe_key TEXT NOT NULL UNIQUE,
    rule_id TEXT NOT NULL CHECK (rule_id IN ('A','B','C')), rule_name TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('low','medium','high','critical')),
    confidence TEXT NOT NULL CHECK (confidence IN ('low','medium','high')),
    subject_type TEXT NOT NULL, subject TEXT NOT NULL, source_ip TEXT,
    source_ips TEXT NOT NULL, usernames TEXT NOT NULL,
    first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, attempt_count INTEGER NOT NULL,
    window_seconds INTEGER NOT NULL, explanation TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'New'
        CHECK (status IN ('New','Investigating','Resolved','False Positive')),
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_alerts_first ON alerts(first_seen);
CREATE TABLE IF NOT EXISTS alert_events (
    alert_id INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
    role TEXT NOT NULL DEFAULT 'trigger', PRIMARY KEY (alert_id, event_id));
CREATE TABLE IF NOT EXISTS investigation_notes (
    id INTEGER PRIMARY KEY,
    alert_id INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    note TEXT NOT NULL, created_at TEXT NOT NULL);
"""

SEVERITY_ORDER = ("CASE a.severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 "
                  "WHEN 'medium' THEN 2 ELSE 1 END")


class DuplicateBatch(Exception):
    pass


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def connect(path):
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(conn):
    conn.executescript(SCHEMA)
    conn.commit()


# ---------------------------------------------------------------- ingestion
def import_batch(conn, filename, result):
    """Insert a batch and its events. Caller owns the transaction (use `with conn:`)."""
    if conn.execute("SELECT 1 FROM ingestion_batches WHERE file_hash=?", (result.file_hash,)).fetchone():
        raise DuplicateBatch()
    cur = conn.execute(
        "INSERT INTO ingestion_batches(filename,file_hash,uploaded_at,rows_processed,rows_accepted,rows_rejected)"
        " VALUES (?,?,?,?,?,?)",
        (filename, result.file_hash, now(), result.processed, len(result.rows), len(result.rejected)))
    batch_id = cur.lastrowid
    conn.executemany(
        "INSERT INTO events(batch_id,row_number,timestamp,username,source_ip,status) VALUES (?,?,?,?,?,?)",
        [(batch_id, r["row_number"], r["timestamp"], r["username"], r["source_ip"], r["status"])
         for r in result.rows])
    return batch_id


def run_detection(conn, rules=None):
    """Re-run detection over all stored events and upsert alerts. Idempotent.
    Existing alerts keep their status and notes. Returns (created, updated)."""
    events = [dict(r) for r in conn.execute(
        "SELECT id,timestamp,username,source_ip,status FROM events")]
    created = updated = 0
    for alert in detector.detect(events, rules):
        row = conn.execute("SELECT id FROM alerts WHERE dedupe_key=?", (alert["dedupe_key"],)).fetchone()
        fields = ("rule_id", "rule_name", "severity", "confidence", "subject_type", "subject", "source_ip",
                  "source_ips", "usernames", "first_seen", "last_seen", "attempt_count",
                  "window_seconds", "explanation")
        if row:
            alert_id = row["id"]
            conn.execute(
                "UPDATE alerts SET " + ",".join(f"{f}=?" for f in fields) + ",updated_at=? WHERE id=?",
                [alert[f] for f in fields] + [now(), alert_id])
            conn.execute("DELETE FROM alert_events WHERE alert_id=?", (alert_id,))
            updated += 1
        else:
            cur = conn.execute(
                "INSERT INTO alerts(dedupe_key," + ",".join(fields) + ",created_at,updated_at) VALUES (?" +
                ",?" * len(fields) + ",?,?)",
                [alert["dedupe_key"]] + [alert[f] for f in fields] + [now(), now()])
            alert_id = cur.lastrowid
            created += 1
        conn.executemany("INSERT INTO alert_events(alert_id,event_id,role) VALUES (?,?,?)",
                         [(alert_id, eid, role) for eid, role in alert["evidence"]])
    return created, updated


# ---------------------------------------------------------------- queries
def _paginate(conn, source, where, params, select, order, page, per_page=config.PER_PAGE):
    total = conn.execute(f"SELECT COUNT(*) FROM {source} {where}", params).fetchone()[0]
    pages = max(1, math.ceil(total / per_page))
    page = min(max(page, 1), pages)
    rows = conn.execute(
        f"SELECT {select} FROM {source} {where} ORDER BY {order} LIMIT ? OFFSET ?",
        [*params, per_page, (page - 1) * per_page]).fetchall()
    return {"rows": rows, "total": total, "page": page, "pages": pages}


def _event_where(f):
    clauses, params = [], []
    if f.get("date_from"):
        clauses.append("date(e.timestamp) >= ?"); params.append(f["date_from"])
    if f.get("date_to"):
        clauses.append("date(e.timestamp) <= ?"); params.append(f["date_to"])
    if f.get("ip"):
        clauses.append("e.source_ip = ?"); params.append(f["ip"])
    if f.get("username"):
        escaped = f["username"].replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        clauses.append("e.username LIKE ? ESCAPE '\\'"); params.append(f"%{escaped}%")
    if f.get("status"):
        clauses.append("e.status = ?"); params.append(f["status"])
    return ("WHERE " + " AND ".join(clauses) if clauses else ""), params


def list_events(conn, f, page):
    where, params = _event_where(f)
    return _paginate(conn, "events e JOIN ingestion_batches b ON b.id=e.batch_id", where, params,
                     "e.id,e.timestamp,e.username,e.source_ip,e.status,e.batch_id,b.filename",
                     "e.timestamp DESC, e.id DESC", page)


def export_events(conn, f):
    where, params = _event_where(f)
    return conn.execute(
        "SELECT e.id,e.timestamp,e.username,e.source_ip,e.status,e.batch_id FROM events e "
        f"{where} ORDER BY e.timestamp, e.id", params).fetchall()


def _alert_where(f):
    clauses, params = [], []
    for key, col in (("severity", "a.severity"), ("rule", "a.rule_id"), ("status", "a.status")):
        if f.get(key):
            clauses.append(f"{col} = ?"); params.append(f[key])
    if f.get("date_from"):
        clauses.append("date(a.first_seen) >= ?"); params.append(f["date_from"])
    if f.get("date_to"):
        clauses.append("date(a.first_seen) <= ?"); params.append(f["date_to"])
    return ("WHERE " + " AND ".join(clauses) if clauses else ""), params


def list_alerts(conn, f, page):
    where, params = _alert_where(f)
    return _paginate(conn, "alerts a", where, params, "a.*",
                     f"{SEVERITY_ORDER} DESC, a.first_seen DESC, a.id DESC", page)


def export_alerts(conn, f):
    where, params = _alert_where(f)
    return conn.execute(
        "SELECT a.id,a.rule_id,a.rule_name,a.severity,a.confidence,a.subject_type,a.subject,a.source_ips,"
        "a.usernames,a.first_seen,a.last_seen,a.attempt_count,a.status,a.explanation FROM alerts a "
        f"{where} ORDER BY a.first_seen, a.id", params).fetchall()


def get_alert(conn, alert_id):
    alert = conn.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
    if not alert:
        return None
    events = conn.execute(
        "SELECT e.id,e.timestamp,e.username,e.source_ip,e.status,ae.role FROM alert_events ae "
        "JOIN events e ON e.id=ae.event_id WHERE ae.alert_id=? ORDER BY e.timestamp,e.id",
        (alert_id,)).fetchall()
    notes = conn.execute(
        "SELECT note,created_at FROM investigation_notes WHERE alert_id=? ORDER BY id DESC",
        (alert_id,)).fetchall()
    return {"alert": alert, "events": events, "notes": notes}


def set_alert_status(conn, alert_id, status):
    with conn:
        if status not in config.STATUSES:
            return False
        cur = conn.execute("UPDATE alerts SET status=?,updated_at=? WHERE id=?",
                           (status, now(), alert_id))
    return cur.rowcount == 1


def add_note(conn, alert_id, note):
    with conn:
        conn.execute("INSERT INTO investigation_notes(alert_id,note,created_at) VALUES (?,?,?)",
                     (alert_id, note, now()))


def dashboard_data(conn):
    one = lambda sql, p=(): conn.execute(sql, p).fetchone()[0]
    sev = {r["severity"]: r["n"] for r in conn.execute(
        "SELECT severity, COUNT(*) n FROM alerts GROUP BY severity")}
    activity = conn.execute(
        "SELECT substr(timestamp,1,13) AS hour, "
        "SUM(status='success') AS ok, SUM(status='failure') AS fail FROM events "
        "GROUP BY hour ORDER BY hour").fetchall()
    return {
        "total_events": one("SELECT COUNT(*) FROM events"),
        "successes": one("SELECT COUNT(*) FROM events WHERE status='success'"),
        "failures": one("SELECT COUNT(*) FROM events WHERE status='failure'"),
        "total_alerts": one("SELECT COUNT(*) FROM alerts"),
        "severity": {s: sev.get(s, 0) for s in config.SEVERITIES},
        "activity": [{"hour": r["hour"], "success": r["ok"], "failure": r["fail"]} for r in activity],
        "top_ips": [dict(r) for r in conn.execute(
            "SELECT source_ip AS ip, COUNT(*) AS alerts, SUM(attempt_count) AS attempts FROM alerts "
            "WHERE source_ip IS NOT NULL GROUP BY source_ip ORDER BY alerts DESC, attempts DESC LIMIT 5")],
        "latest_alerts": conn.execute(
            "SELECT a.* FROM alerts a ORDER BY a.first_seen DESC, a.id DESC LIMIT 5").fetchall(),
        "batches": conn.execute(
            "SELECT * FROM ingestion_batches ORDER BY id DESC LIMIT 5").fetchall(),
    }


def report_data(conn, date_from=None, date_to=None):
    ef = {"date_from": date_from, "date_to": date_to}
    ew, ep = _event_where(ef)
    aw, ap = _alert_where(ef)
    def group(table, col, where, params):
        return {r[0]: r[1] for r in conn.execute(
            f"SELECT {col}, COUNT(*) FROM {table} {where} GROUP BY {col}", params)}
    return {
        "events": conn.execute(f"SELECT COUNT(*) FROM events e {ew}", ep).fetchone()[0],
        "by_status": group("events e", "e.status", ew, ep),
        "by_rule": group("alerts a", "a.rule_name", aw, ap),
        "by_severity": group("alerts a", "a.severity", aw, ap),
        "by_investigation": group("alerts a", "a.status", aw, ap),
        "alerts": conn.execute(f"SELECT COUNT(*) FROM alerts a {aw}", ap).fetchone()[0],
    }
