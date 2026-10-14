import io
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from app import create_app  # noqa: E402

HEADER = "timestamp,username,source_ip,status\n"


@pytest.fixture
def app(tmp_path):
    return create_app({"TESTING": True, "DATABASE": str(tmp_path / "t.db")})


@pytest.fixture
def client(app):
    c = app.test_client()
    with c.session_transaction() as s:
        s["_csrf"] = "tok"
    return c


def post(client, url, **data):
    return client.post(url, data={"csrf_token": "tok", **data}, follow_redirects=True)


def upload(client, text, name="logs.csv"):
    return client.post("/upload", data={"csrf_token": "tok", "file": (io.BytesIO(text.encode()), name)},
                       content_type="multipart/form-data", follow_redirects=True)


def csv_rows(rows):
    return HEADER + "".join(",".join(r) + "\n" for r in rows)
