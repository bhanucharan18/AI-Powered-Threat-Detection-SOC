"""CSV validation and normalization. Uploaded content is treated as untrusted data."""
import csv
import hashlib
import io
import ipaddress
from dataclasses import dataclass, field
from datetime import datetime, timezone

import config

REQUIRED_COLUMNS = ["timestamp", "username", "source_ip", "status"]
STATUS_ALIASES = {
    "success": "success", "successful": "success", "ok": "success",
    "failure": "failure", "failed": "failure", "fail": "failure",
}


class ParseError(Exception):
    """File-level problem: the whole upload is rejected."""


@dataclass
class ParseResult:
    rows: list = field(default_factory=list)       # accepted, normalized rows
    rejected: list = field(default_factory=list)   # (line_number, reason)
    file_hash: str = ""

    @property
    def processed(self):
        return len(self.rows) + len(self.rejected)


def parse_timestamp(value):
    """Accept ISO-8601 'YYYY-MM-DD[ T]HH:MM:SS[.ffffff][Z|+hh:mm]'. Naive values are treated as UTC.
    Returns a normalized UTC string 'YYYY-MM-DD HH:MM:SS'."""
    value = (value or "").strip()
    if len(value) < 19 or value[10] not in "T ":
        raise ValueError("timestamp must look like 2024-05-01 13:45:00 (UTC) or ISO-8601")
    if value.endswith(("Z", "z")):
        value = value[:-1] + "+00:00"
    dt = datetime.fromisoformat(value)  # ValueError on malformed input
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def parse_ip(value):
    return str(ipaddress.ip_address((value or "").strip()))


def parse_username(value):
    value = (value or "").strip()
    if not value:
        raise ValueError("username is empty")
    if len(value) > config.MAX_USERNAME_LEN:
        raise ValueError("username too long")
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError("username contains control characters")
    return value


def parse_status(value):
    key = (value or "").strip().lower()
    if key not in STATUS_ALIASES:
        raise ValueError("status must be success or failure")
    return STATUS_ALIASES[key]


def parse_csv(data: bytes) -> ParseResult:
    if not data or not data.strip():
        raise ParseError("The file is empty.")
    if b"\x00" in data:
        raise ParseError("The file is not a text CSV file.")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise ParseError("The file must be UTF-8 encoded text.")

    reader = csv.DictReader(io.StringIO(text, newline=""))
    if not reader.fieldnames:
        raise ParseError("The file has no header row.")
    reader.fieldnames = [(h or "").strip().lower() for h in reader.fieldnames]
    missing = [c for c in REQUIRED_COLUMNS if c not in reader.fieldnames]
    if missing:
        raise ParseError("Missing required column(s): " + ", ".join(missing))

    result = ParseResult(file_hash=hashlib.sha256(data).hexdigest())
    try:
        for count, raw in enumerate(reader, start=1):
            if count > config.MAX_ROWS:
                raise ParseError(f"Too many rows (limit {config.MAX_ROWS}).")
            line = reader.line_num
            try:
                result.rows.append({
                    "row_number": count,
                    "timestamp": parse_timestamp(raw.get("timestamp")),
                    "username": parse_username(raw.get("username")),
                    "source_ip": parse_ip(raw.get("source_ip")),
                    "status": parse_status(raw.get("status")),
                })
            except ValueError as exc:
                result.rejected.append((line, str(exc)))
    except csv.Error as exc:
        raise ParseError(f"The CSV is malformed: {exc}")
    return result
