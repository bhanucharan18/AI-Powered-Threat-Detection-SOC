"""CSV export with spreadsheet-formula neutralisation."""
import csv
import io

_DANGEROUS = ("=", "+", "-", "@", "\t", "\r", "\n")


def safe_cell(value):
    """Prefix text that a spreadsheet could interpret as a formula with an apostrophe."""
    if value is None:
        return ""
    if isinstance(value, (int, float)):
        return value
    text = str(value)
    return "'" + text if text.startswith(_DANGEROUS) else text


def to_csv(columns, rows):
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(columns)
    for row in rows:
        writer.writerow([safe_cell(row[c]) for c in columns])
    return buf.getvalue()


EVENT_COLUMNS = ["id", "timestamp", "username", "source_ip", "status", "batch_id"]
ALERT_COLUMNS = ["id", "rule_id", "rule_name", "severity", "confidence", "subject_type", "subject",
                 "source_ips", "usernames", "first_seen", "last_seen", "attempt_count", "status",
                 "explanation"]
