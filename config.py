"""Central configuration: detection thresholds, limits and analyst guidance.

The thresholds are EDUCATIONAL DEFAULTS for synthetic data, not security standards.
"""

DEFAULT_RULES = {
    "A": {"name": "Repeated failed logins from one source IP", "threshold": 5, "window_seconds": 300},
    "B": {"name": "Repeated failed logins against one username", "threshold": 8, "window_seconds": 600},
    "C": {"name": "Possible password spraying", "threshold": 5, "window_seconds": 600},
}

# A successful login this soon after the failures (same IP / same account) raises priority.
SUCCESS_FOLLOW_SECONDS = 600

MAX_UPLOAD_BYTES = 2 * 1024 * 1024
MAX_ROWS = 50_000
MAX_USERNAME_LEN = 128
PER_PAGE = 25

SEVERITIES = ["low", "medium", "high", "critical"]
CONFIDENCES = ["low", "medium", "high"]
STATUSES = ["New", "Investigating", "Resolved", "False Positive"]

RECOMMENDED_STEPS = {
    "A": [
        "Confirm the source IP's owner and whether it belongs to a known VPN, office or scanner.",
        "Review every username attempted from this IP in the timeline below.",
        "Check whether any attempt from this IP succeeded, before or after the failures.",
        "Compare against other logs (VPN, firewall, directory service) for the same period.",
        "Document the outcome. Follow your organisation's policy before any containment action.",
    ],
    "B": [
        "Contact the account owner to ask whether they were locked out or mistyped a password.",
        "Review the source IPs: one address, several, or a known location for this user?",
        "Check for a successful login on this account after the failures.",
        "Check whether the account is a service account with stored, outdated credentials.",
        "Document the outcome. Follow your organisation's policy before resetting credentials.",
    ],
    "C": [
        "List the distinct accounts attempted and check for shared traits (department, privilege).",
        "Look for the same source IP in other authentication systems.",
        "Check whether any attempted account later had a successful login.",
        "Consider whether this IP is a shared gateway (NAT, proxy) that could explain the volume.",
        "Document the outcome. Follow your organisation's policy before any containment action.",
    ],
}
SUCCESS_FOLLOWUP_STEP = (
    "PRIORITY: a successful login followed the failures. Verify with the user whether that login "
    "was theirs, and review that session's activity."
)
