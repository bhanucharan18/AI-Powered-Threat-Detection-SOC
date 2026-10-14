from pathlib import Path

import database as db
from tests.conftest import csv_rows, post, upload

SAMPLE = Path(__file__).resolve().parent.parent / "sample_data" / "sample_auth_logs.csv"


def count(app, table):
    with app.app_context():
        c = db.connect(app.config["DATABASE"])
        n = c.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        c.close()
        return n


def test_empty_dashboard_loads(client):
    r = client.get("/")
    assert r.status_code == 200 and b"No data yet" in r.data


def test_sample_import_creates_expected_alerts(client, app):
    r = upload(client, SAMPLE.read_text(), "sample.csv")
    assert b"2 rejected" in r.data
    with app.app_context():
        c = db.connect(app.config["DATABASE"])
        found = {(a["rule_id"], a["subject"]) for a in c.execute("SELECT * FROM alerts")}
        c.close()
    assert found == {("A", "203.0.113.50"), ("C", "198.51.100.23"), ("B", "svc_backup")}


def test_dashboard_reflects_database(client, app):
    upload(client, SAMPLE.read_text())
    html = client.get("/").data.decode()
    assert "203.0.113.50" in html and "dash-data" in html


def test_duplicate_import_does_nothing(client, app):
    upload(client, SAMPLE.read_text())
    e, a = count(app, "events"), count(app, "alerts")
    r = upload(client, SAMPLE.read_text(), "again.csv")
    assert b"already imported" in r.data
    assert (count(app, "events"), count(app, "alerts")) == (e, a)


def test_rerunning_detection_creates_no_duplicate_alerts(client, app):
    upload(client, SAMPLE.read_text())
    before = count(app, "alerts")
    with app.app_context():
        c = db.connect(app.config["DATABASE"])
        with c:
            created, _ = db.run_detection(c)
        c.close()
    assert created == 0 and count(app, "alerts") == before


def test_bad_uploads_are_rejected(client, app):
    assert b"Only .csv" in upload(client, "x", "evil.exe").data
    assert b"Missing required column" in upload(client, "a,b\n1,2\n").data
    assert b"No valid rows" in upload(client, csv_rows([("bad", "u", "1.1.1.1", "failure")])).data
    assert count(app, "events") == 0


def test_alert_links_to_evidence_notes_and_status(client, app):
    upload(client, SAMPLE.read_text())
    assert count(app, "alert_events") > 0
    page = client.get("/alerts/1")
    assert page.status_code == 200 and b"Evidence timeline" in page.data
    assert b"Note added" in post(client, "/alerts/1/notes", note="Checked VPN logs <b>x</b>").data
    detail = client.get("/alerts/1").data
    assert b"&lt;b&gt;x&lt;/b&gt;" in detail and b"<b>x</b>" not in detail   # escaped
    assert b"Status changed to Investigating" in post(client, "/alerts/1/status", status="Investigating").data
    assert b"Invalid status" in post(client, "/alerts/1/status", status="Deleted").data
    assert b"between 1 and 2000" in post(client, "/alerts/1/notes", note="   ").data
    assert client.get("/alerts/9999").status_code == 404


def test_csrf_required(app):
    c = app.test_client()
    assert c.post("/alerts/1/status", data={"status": "Resolved"}).status_code == 400
    assert c.post("/upload", data={}).status_code == 400


def test_log_filters_and_validation(client):
    upload(client, SAMPLE.read_text())
    r = client.get("/logs?ip=203.0.113.50&status=failure")
    assert b"203.0.113.50" in r.data and b"192.0.2.10" not in r.data
    assert b"invalid IP" in client.get("/logs?ip=nope").data
    assert b"invalid date" in client.get("/logs?date_from=2024-99-99").data
    assert client.get("/logs?page=abc&username=%25").status_code == 200


def test_alert_filters(client):
    upload(client, SAMPLE.read_text())
    r = client.get("/alerts?rule=C").data
    assert b"198.51.100.23" in r and b"203.0.113.50" not in r
    assert client.get("/alerts?severity=bogus").status_code == 200


def test_reports_and_exports_neutralize_formulas(client):
    rows = [("2024-05-01 10:00:00", "=HYPERLINK(1)", "192.0.2.1", "success"),
            ("2024-05-01 10:00:01", "+cmd", "192.0.2.1", "success"),
            ("2024-05-01 10:00:02", "@sum", "192.0.2.1", "success")]
    upload(client, csv_rows(rows))
    out = client.get("/export/events.csv")
    assert out.mimetype == "text/csv"
    text = out.data.decode()
    assert "'=HYPERLINK(1)" in text and "'+cmd" in text and "'@sum" in text
    assert client.get("/reports?date_from=2024-05-01&date_to=2024-05-02").status_code == 200
    assert client.get("/export/alerts.csv").status_code == 200
