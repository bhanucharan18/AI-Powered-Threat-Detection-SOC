"""Flask application: routes and presentation only. Business logic lives in other modules."""
import ipaddress
import os
import secrets
from datetime import datetime

from flask import (Flask, Response, abort, flash, g, redirect, render_template, request, session,
                   url_for)
from werkzeug.utils import secure_filename

import config
import database as db
import log_parser
import report_generator as rg


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    app.config.update(
        SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),
        DATABASE=os.path.join(app.instance_path, "analyzer.db"),
        MAX_CONTENT_LENGTH=config.MAX_UPLOAD_BYTES,
        RULES=config.DEFAULT_RULES,
    )
    if test_config:
        app.config.update(test_config)
    os.makedirs(app.instance_path, exist_ok=True)
    boot = db.connect(app.config["DATABASE"])
    db.init_db(boot)
    boot.close()

    def conn():
        if "db" not in g:
            g.db = db.connect(app.config["DATABASE"])
        return g.db

    @app.teardown_appcontext
    def close_db(_exc):
        c = g.pop("db", None)
        if c is not None:
            c.close()

    # ------------------------------------------------------------ security
    @app.before_request
    def csrf_protect():
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            expected, sent = session.get("_csrf"), request.form.get("csrf_token", "")
            if not expected or not secrets.compare_digest(expected, sent):
                abort(400, "Missing or invalid CSRF token. Reload the page and try again.")

    app.jinja_env.globals["csrf_token"] = lambda: session.setdefault("_csrf", secrets.token_hex(16))
    app.jinja_env.globals["STATUSES"] = config.STATUSES

    @app.after_request
    def headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "same-origin"
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; "
            "style-src 'self'; frame-ancestors 'none'")
        return resp

    @app.errorhandler(413)
    def too_large(_e):
        flash(f"File too large. The limit is {config.MAX_UPLOAD_BYTES // 1024 // 1024} MB.", "error")
        return redirect(url_for("dashboard"))

    @app.errorhandler(400)
    def bad_request(e):
        return render_template("message.html", title="Request rejected", message=e.description), 400

    @app.errorhandler(404)
    def not_found(_e):
        return render_template("message.html", title="Not found", message="That page does not exist."), 404

    # ------------------------------------------------------------ helpers
    def arg_date(name):
        value = request.args.get(name, "").strip()
        if not value:
            return None
        try:
            datetime.strptime(value, "%Y-%m-%d")
            return value
        except ValueError:
            flash(f"Ignored invalid date for '{name}'. Use YYYY-MM-DD.", "error")
            return None

    def arg_choice(name, allowed):
        value = request.args.get(name, "").strip()
        return value if value in allowed else None

    def arg_page():
        try:
            return max(int(request.args.get("page", 1)), 1)
        except ValueError:
            return 1

    def keep_args():
        return {k: v for k, v in request.args.items() if k != "page" and v}

    # ------------------------------------------------------------ pages
    @app.get("/")
    def dashboard():
        return render_template("dashboard.html", d=db.dashboard_data(conn()))

    @app.post("/upload")
    def upload():
        file = request.files.get("file")
        if not file or not file.filename:
            flash("Choose a CSV file to import.", "error")
            return redirect(url_for("dashboard"))
        name = secure_filename(file.filename) or "upload.csv"
        if not name.lower().endswith(".csv"):
            flash("Only .csv files are accepted.", "error")
            return redirect(url_for("dashboard"))
        try:
            result = log_parser.parse_csv(file.read(config.MAX_UPLOAD_BYTES + 1))
        except log_parser.ParseError as exc:
            flash(str(exc), "error")
            return redirect(url_for("dashboard"))
        if not result.rows:
            flash(f"No valid rows found ({len(result.rejected)} rejected). Nothing was imported. "
                  f"First problem: line {result.rejected[0][0]}: {result.rejected[0][1]}", "error")
            return redirect(url_for("dashboard"))
        c = conn()
        try:
            with c:
                db.import_batch(c, name, result)
                created, updated = db.run_detection(c, app.config["RULES"])
        except db.DuplicateBatch:
            flash("This exact file was already imported. Nothing changed.", "error")
            return redirect(url_for("dashboard"))
        msg = (f"Imported {name}: {len(result.rows)} accepted, {len(result.rejected)} rejected. "
               f"Detection: {created} new alert(s), {updated} refreshed.")
        if result.rejected:
            line, reason = result.rejected[0]
            msg += f" First rejected row: line {line} ({reason})."
        flash(msg, "ok")
        return redirect(url_for("dashboard"))

    @app.get("/logs")
    def logs():
        filters = {"date_from": arg_date("date_from"), "date_to": arg_date("date_to"),
                   "username": request.args.get("username", "").strip()[:config.MAX_USERNAME_LEN] or None,
                   "status": arg_choice("status", ("success", "failure")), "ip": None}
        raw_ip = request.args.get("ip", "").strip()
        if raw_ip:
            try:
                filters["ip"] = str(ipaddress.ip_address(raw_ip))
            except ValueError:
                flash("Ignored invalid IP address filter.", "error")
        data = db.list_events(conn(), filters, arg_page())
        return render_template("logs.html", data=data, args=keep_args(), f=request.args)

    @app.get("/alerts")
    def alerts():
        filters = {"severity": arg_choice("severity", config.SEVERITIES),
                   "rule": arg_choice("rule", ("A", "B", "C")),
                   "status": arg_choice("status", config.STATUSES),
                   "date_from": arg_date("date_from"), "date_to": arg_date("date_to")}
        data = db.list_alerts(conn(), filters, arg_page())
        return render_template("alerts.html", data=data, args=keep_args(), f=request.args,
                               severities=config.SEVERITIES)

    @app.get("/alerts/<int:alert_id>")
    def alert_detail(alert_id):
        detail = db.get_alert(conn(), alert_id)
        if not detail:
            abort(404)
        rule = detail["alert"]["rule_id"]
        steps = list(config.RECOMMENDED_STEPS[rule])
        if any(e["role"] == "context" for e in detail["events"]):
            steps.insert(0, config.SUCCESS_FOLLOWUP_STEP)
        return render_template("alert_detail.html", steps=steps, **detail)

    @app.post("/alerts/<int:alert_id>/status")
    def alert_status(alert_id):
        status = request.form.get("status", "")
        if status not in config.STATUSES:
            flash("Invalid status.", "error")
        elif db.set_alert_status(conn(), alert_id, status):
            flash(f"Status changed to {status}.", "ok")
        else:
            abort(404)
        return redirect(url_for("alert_detail", alert_id=alert_id))

    @app.post("/alerts/<int:alert_id>/notes")
    def alert_note(alert_id):
        note = request.form.get("note", "").strip()
        if not db.get_alert(conn(), alert_id):
            abort(404)
        if not note or len(note) > 2000:
            flash("A note must be between 1 and 2000 characters.", "error")
        else:
            db.add_note(conn(), alert_id, note)
            flash("Note added.", "ok")
        return redirect(url_for("alert_detail", alert_id=alert_id))

    @app.get("/reports")
    def reports():
        df, dt = arg_date("date_from"), arg_date("date_to")
        return render_template("reports.html", r=db.report_data(conn(), df, dt),
                               args={k: v for k, v in (("date_from", df), ("date_to", dt)) if v},
                               f=request.args, rules=app.config["RULES"])

    def csv_response(text, filename):
        return Response(text, mimetype="text/csv",
                        headers={"Content-Disposition": f"attachment; filename={filename}"})

    @app.get("/export/events.csv")
    def export_events():
        rows = db.export_events(conn(), {"date_from": arg_date("date_from"), "date_to": arg_date("date_to")})
        return csv_response(rg.to_csv(rg.EVENT_COLUMNS, rows), "events.csv")

    @app.get("/export/alerts.csv")
    def export_alerts():
        rows = db.export_alerts(conn(), {"date_from": arg_date("date_from"), "date_to": arg_date("date_to")})
        return csv_response(rg.to_csv(rg.ALERT_COLUMNS, rows), "alerts.csv")

    @app.get("/about")
    def about():
        return render_template("about.html", rules=app.config["RULES"])

    return app


if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=5000, debug=False)
