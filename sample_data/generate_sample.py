"""Generate a deterministic SYNTHETIC log. Uses reserved documentation IP ranges (RFC 5737)."""
import csv
import random
from datetime import datetime, timedelta
from pathlib import Path

random.seed(42)
start = datetime(2024, 5, 1, 8, 0, 0)
users = ["alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi"]
rows = []

def add(t, user, ip, status):
    rows.append((t.strftime("%Y-%m-%d %H:%M:%S"), user, ip, status))

# Normal activity with occasional typos (should NOT alert)
for i in range(120):
    t = start + timedelta(minutes=i * 6 + random.randint(0, 5))
    u = random.choice(users)
    add(t, u, f"192.0.2.{10 + users.index(u)}", "success")
    if random.random() < 0.08:
        add(t - timedelta(seconds=20), u, f"192.0.2.{10 + users.index(u)}", "failure")

# Brute force: 14 failures in ~2 minutes from one IP, then a success (Rule A, escalated)
t0 = start + timedelta(hours=3)
for i in range(14):
    add(t0 + timedelta(seconds=i * 9), random.choice(["admin", "root", "alice"]), "203.0.113.50", "failure")
add(t0 + timedelta(minutes=3), "alice", "203.0.113.50", "success")

# Password spraying: 7 users, one attempt each, 90 s apart (Rule C only)
t1 = start + timedelta(hours=5)
for i, u in enumerate(users[:7]):
    add(t1 + timedelta(seconds=i * 90), u, "198.51.100.23", "failure")

# Account targeting: 10 failures against one service account from 5 IPs (Rule B only)
t2 = start + timedelta(hours=7)
for i in range(10):
    add(t2 + timedelta(seconds=i * 50), "svc_backup", f"192.0.2.{200 + i % 5}", "failure")

# A few malformed rows to demonstrate rejection handling
rows.sort()
out = Path(__file__).parent / "sample_auth_logs.csv"
with out.open("w", newline="") as fh:
    w = csv.writer(fh)
    w.writerow(["timestamp", "username", "source_ip", "status"])
    w.writerows(rows)
    w.writerow(["not-a-date", "mallory", "203.0.113.99", "failure"])
    w.writerow(["2024-05-01 12:00:00", "mallory", "999.1.1.1", "failure"])
print("wrote", out, len(rows) + 2, "rows")
