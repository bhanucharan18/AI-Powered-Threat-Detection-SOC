from datetime import datetime, timedelta

from detector import detect

T0 = datetime(2024, 5, 1, 10, 0, 0)


def mk(rows):
    """rows: (seconds_offset, user, ip, status)"""
    return [{"id": i + 1, "timestamp": (T0 + timedelta(seconds=s)).strftime("%Y-%m-%d %H:%M:%S"),
             "username": u, "source_ip": ip, "status": st} for i, (s, u, ip, st) in enumerate(rows)]


def fails(n, step, user="a", ip="192.0.2.1", start=0):
    return [(start + i * step, user, ip, "failure") for i in range(n)]


def rules(alerts):
    return [a["rule_id"] for a in alerts]


def test_rule_a_one_below_threshold():
    assert detect(mk(fails(4, 10))) == []


def test_rule_a_at_threshold():
    a = detect(mk(fails(5, 10)))
    assert rules(a) == ["A"] and a[0]["attempt_count"] == 5 and len(a[0]["evidence"]) == 5


def test_rule_a_window_boundary_is_inclusive():
    assert rules(detect(mk(fails(5, 75)))) == ["A"]       # span exactly 300 s
    assert detect(mk(fails(5, 76))) == []                 # span 304 s


def test_successes_do_not_count_as_failures():
    rows = fails(4, 10) + [(50 + i, "a", "192.0.2.1", "success") for i in range(10)]
    assert detect(mk(rows)) == []


def test_long_attack_is_one_alert():
    a = detect(mk(fails(40, 10)))
    assert rules(a) == ["A", "B"]          # same events legitimately trip the per-IP and per-account rules
    assert a[0]["attempt_count"] == 40     # but each rule yields exactly one merged alert


def test_separate_bursts_make_separate_alerts():
    a = detect(mk(fails(5, 10) + fails(5, 10, start=7200)))
    assert rules(a) == ["A", "A"]


def test_rule_b_multiple_ips_below_and_at_threshold():
    def rows(n):
        return [(i * 30, "svc", f"192.0.2.{i % 4 + 1}", "failure") for i in range(n)]
    assert detect(mk(rows(7))) == []
    a = detect(mk(rows(8)))
    assert rules(a) == ["B"] and len(a[0]["source_ips"].split(",")) == 4


def test_rule_b_window():
    assert detect(mk(fails(8, 100, user="svc", ip="x" and "192.0.2.9"))) == []  # span 700 s > 600 s


def test_rule_c_password_spraying():
    spray = [(i * 120, f"user{i}", "198.51.100.1", "failure") for i in range(5)]
    a = detect(mk(spray))
    assert rules(a) == ["C"] and "password spraying" in a[0]["explanation"]
    assert detect(mk(spray[:4])) == []


def test_rule_c_requires_distinct_usernames():
    assert "C" not in rules(detect(mk(fails(6, 100, user="same"))))


def test_rule_c_ignores_successes():
    rows = [(i * 120, f"user{i}", "198.51.100.1", "failure") for i in range(4)] + [(500, "user9", "198.51.100.1", "success")]
    assert detect(mk(rows)) == []


def test_success_after_failures_raises_severity_and_adds_context():
    plain = detect(mk(fails(5, 10)))[0]
    with_ok = detect(mk(fails(5, 10) + [(120, "a", "192.0.2.1", "success")]))[0]
    sev = ["low", "medium", "high", "critical"]
    assert sev.index(with_ok["severity"]) == sev.index(plain["severity"]) + 1
    assert ("context" in [r for _, r in with_ok["evidence"]]) and "successful login" in with_ok["explanation"]


def test_confidence_and_severity_are_separate():
    a = detect(mk(fails(5, 10)))[0]
    b = detect(mk(fails(10, 10)))[0]
    assert (a["severity"], a["confidence"]) == ("medium", "low")
    assert (b["severity"], b["confidence"]) == ("high", "high")


def test_deterministic_regardless_of_input_order():
    ev = mk(fails(6, 10) + [(i * 100, f"u{i}", "198.51.100.1", "failure") for i in range(6)])
    assert detect(ev) == detect(list(reversed(ev)))


def test_custom_thresholds():
    r = {"A": {"name": "A", "threshold": 2, "window_seconds": 60},
         "B": {"name": "B", "threshold": 99, "window_seconds": 60},
         "C": {"name": "C", "threshold": 99, "window_seconds": 60}}
    assert rules(detect(mk(fails(2, 10)), r)) == ["A"]
