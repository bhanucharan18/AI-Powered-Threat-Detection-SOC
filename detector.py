"""Pure, deterministic detection logic. No database or Flask imports.

Each rule slides a window over time-ordered FAILED events. Overlapping triggered windows are
merged into one 'episode', so a long attack yields one alert instead of hundreds.
Window comparison is inclusive: events exactly `window_seconds` apart share a window.
"""
from collections import Counter, defaultdict
from datetime import datetime, timedelta

import config

TS_FORMAT = "%Y-%m-%d %H:%M:%S"


def _bump(severity):
    sev = config.SEVERITIES
    return sev[min(sev.index(severity) + 1, len(sev) - 1)]


def _episodes(seq, window, threshold, key=None):
    """Return [{'start','end','peak'}] index ranges into `seq` (sorted by time).
    Metric is the event count, or the number of distinct key(e) values when key is given."""
    episodes, current, left, counter = [], None, 0, Counter()
    for i, event in enumerate(seq):
        if key:
            counter[key(event)] += 1
        while (event["dt"] - seq[left]["dt"]).total_seconds() > window:
            if key:
                k = key(seq[left])
                counter[k] -= 1
                if counter[k] == 0:
                    del counter[k]
            left += 1
        metric = len(counter) if key else i - left + 1
        if metric >= threshold:
            if current and left <= current["end"]:
                current["end"] = i
                current["peak"] = max(current["peak"], metric)
            else:
                current = {"start": left, "end": i, "peak": metric}
                episodes.append(current)
    return episodes


def _confidence(peak, threshold):
    if peak >= 2 * threshold:
        return "high"
    if peak >= 1.5 * threshold:
        return "medium"
    return "low"


def _build(rule_id, rule, subject_type, subject, seq, ep, successes, follow):
    ev = seq[ep["start"]:ep["end"] + 1]
    first, last = ev[0]["dt"], ev[-1]["dt"]
    users = sorted({e["username"] for e in ev})
    ips = sorted({e["source_ip"] for e in ev})
    context = [
        s for s in successes
        if (s["source_ip"] == subject if subject_type == "ip" else s["username"] == subject)
        and last <= s["dt"] <= last + timedelta(seconds=follow)
    ][:10]

    window, thr, peak = rule["window_seconds"], rule["threshold"], ep["peak"]
    minutes = max(window // 60, 1)
    if rule_id == "A":
        text = (f"Suspected brute-force activity: {len(ev)} failed logins from {subject} between "
                f"{first.strftime(TS_FORMAT)} and {last.strftime(TS_FORMAT)} UTC (peak {peak} within "
                f"{minutes} minutes; rule threshold {thr}). Usernames attempted: {', '.join(users)}.")
    elif rule_id == "B":
        text = (f"Repeated failures against account '{subject}': {len(ev)} failed logins from "
                f"{len(ips)} source IP(s) between {first.strftime(TS_FORMAT)} and "
                f"{last.strftime(TS_FORMAT)} UTC (peak {peak} within {minutes} minutes; "
                f"rule threshold {thr}). Possible account targeting.")
    else:
        text = (f"Possible password spraying: {subject} failed against {peak} distinct usernames within "
                f"{minutes} minutes (rule threshold {thr}); {len(ev)} failures in total between "
                f"{first.strftime(TS_FORMAT)} and {last.strftime(TS_FORMAT)} UTC.")

    severity = "medium"
    if peak >= 2 * thr:
        severity = _bump(severity)
    if context:
        severity = _bump(severity)
        text += (f" A successful login for the same {'IP' if subject_type == 'ip' else 'account'} "
                 f"followed within {follow // 60} minutes (event IDs "
                 f"{', '.join(str(s['id']) for s in context)}); verify it was legitimate.")
    text += " This is an indicator for investigation, not confirmation of an attack."

    return {
        "rule_id": rule_id, "rule_name": rule["name"], "severity": severity,
        "confidence": _confidence(peak, thr), "subject_type": subject_type, "subject": subject,
        "source_ip": subject if subject_type == "ip" else None,
        "source_ips": ",".join(ips), "usernames": ",".join(users),
        "first_seen": first.strftime(TS_FORMAT), "last_seen": last.strftime(TS_FORMAT),
        "attempt_count": len(ev), "window_seconds": window, "explanation": text,
        "dedupe_key": f"{rule_id}|{subject}|{first.strftime(TS_FORMAT)}",
        "evidence": [(e["id"], "trigger") for e in ev] + [(s["id"], "context") for s in context],
    }


def detect(events, rules=None, success_follow_seconds=config.SUCCESS_FOLLOW_SECONDS):
    """events: dicts with id, timestamp ('YYYY-MM-DD HH:MM:SS' UTC), username, source_ip, status."""
    rules = rules or config.DEFAULT_RULES
    evs = sorted(
        ({**e, "dt": datetime.strptime(e["timestamp"], TS_FORMAT)} for e in events),
        key=lambda e: (e["dt"], e["id"]),
    )
    fails = [e for e in evs if e["status"] == "failure"]
    successes = [e for e in evs if e["status"] == "success"]
    by_ip, by_user = defaultdict(list), defaultdict(list)
    for e in fails:
        by_ip[e["source_ip"]].append(e)
        by_user[e["username"]].append(e)

    alerts = []
    ra, rb, rc = rules["A"], rules["B"], rules["C"]
    for ip in sorted(by_ip):
        for ep in _episodes(by_ip[ip], ra["window_seconds"], ra["threshold"]):
            alerts.append(_build("A", ra, "ip", ip, by_ip[ip], ep, successes, success_follow_seconds))
        for ep in _episodes(by_ip[ip], rc["window_seconds"], rc["threshold"], key=lambda e: e["username"]):
            alerts.append(_build("C", rc, "ip", ip, by_ip[ip], ep, successes, success_follow_seconds))
    for user in sorted(by_user):
        for ep in _episodes(by_user[user], rb["window_seconds"], rb["threshold"]):
            alerts.append(_build("B", rb, "username", user, by_user[user], ep, successes, success_follow_seconds))
    return sorted(alerts, key=lambda a: (a["rule_id"], a["subject"], a["first_seen"]))
