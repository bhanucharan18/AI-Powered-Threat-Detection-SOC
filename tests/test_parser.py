import pytest
from log_parser import ParseError, parse_csv, parse_timestamp

H = b"timestamp,username,source_ip,status\n"


def test_valid_rows_are_normalized():
    r = parse_csv(H + b"2024-05-01T10:00:00Z,Alice ,192.0.2.1,FAILED\n2024-05-01 12:00:00+02:00,bob,2001:db8::1,success\n")
    assert [x["timestamp"] for x in r.rows] == ["2024-05-01 10:00:00", "2024-05-01 10:00:00"]
    assert r.rows[0]["username"] == "Alice" and r.rows[0]["status"] == "failure"
    assert not r.rejected


def test_missing_column_rejects_file():
    with pytest.raises(ParseError, match="source_ip"):
        parse_csv(b"timestamp,username,status\n2024-05-01 10:00:00,a,success\n")


@pytest.mark.parametrize("bad", ["yesterday", "2024-13-01 10:00:00", "2024-05-01", "01/05/2024 10:00:00"])
def test_malformed_timestamps_rejected(bad):
    r = parse_csv(H + f"{bad},a,192.0.2.1,success\n2024-05-01 10:00:00,a,192.0.2.1,success\n".encode())
    assert len(r.rows) == 1 and len(r.rejected) == 1


@pytest.mark.parametrize("ip", ["999.1.1.1", "abc", "", "1.2.3"])
def test_invalid_ip_rejected(ip):
    r = parse_csv(H + f"2024-05-01 10:00:00,a,{ip},success\n".encode())
    assert not r.rows and r.rejected


def test_bad_status_and_empty_username_rejected():
    r = parse_csv(H + b"2024-05-01 10:00:00,a,192.0.2.1,maybe\n2024-05-01 10:00:00,,192.0.2.1,success\n")
    assert len(r.rejected) == 2


@pytest.mark.parametrize("data", [b"", b"   \n", b"\x00\x01binary", b"\xff\xfe\xfa"])
def test_unusable_files(data):
    with pytest.raises(ParseError):
        parse_csv(data)


def test_timestamp_helper():
    assert parse_timestamp("2024-05-01T10:00:00.123456") == "2024-05-01 10:00:00"
