import numpy as np
import os
import sys
import re
from collections import Counter, defaultdict
from datetime import datetime
from urllib.parse import unquote

from isolation_forest import MyIsolationForest

# ---------------------------------------------------------------------------
# 1) Load data
# ---------------------------------------------------------------------------
script_dir = os.path.dirname(os.path.abspath(__file__))
log_file   = os.path.join(script_dir, 'access.log')

if not os.path.exists(log_file):
    print(f"Error: '{log_file}' not found. Please run 'generate_logs.py' first.")
    sys.exit(1)

print("1) Loading data...")
with open(log_file, 'r') as f:
    raw_logs = f.readlines()

# ---------------------------------------------------------------------------
# 2) Parse logs (full Combined Log Format — captures referer + user agent)
# ---------------------------------------------------------------------------
print("2) Parsing logs...")
log_pattern = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<date>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<url>.*?) HTTP/\d\.\d" '
    r'(?P<status>\d+) (?P<size>\S+) '
    r'"(?P<referer>[^"]*)" '
    r'"(?P<user_agent>[^"]*)"'
)

parsed_data = []
skipped     = 0
for line in raw_logs:
    m = log_pattern.match(line.strip())
    if m:
        parsed_data.append(m.groupdict())
    else:
        skipped += 1

print(f"   Parsed {len(parsed_data)}/{len(raw_logs)} lines "
      f"({skipped} skipped).")

# ---------------------------------------------------------------------------
# 3) Pre-compute aggregates needed for windowed features
# ---------------------------------------------------------------------------
print("3) Pre-computing aggregates...")

DATE_FMT = "%d/%b/%Y:%H:%M:%S %z"

def parse_ts(date_str):
    try:
        return datetime.strptime(date_str, DATE_FMT)
    except ValueError:
        return None

timestamps = [parse_ts(d['date']) for d in parsed_data]

# Build per-IP timestamp list for windowed rate calculation
ip_time_map = defaultdict(list)
for i, d in enumerate(parsed_data):
    if timestamps[i]:
        ip_time_map[d['ip']].append(timestamps[i])

def requests_in_window(ip, ts, window_sec=60):
    """Count requests from *ip* within ±window_sec of timestamp *ts*."""
    if ts is None:
        return 1
    return sum(
        1 for t in ip_time_map[ip]
        if abs((t - ts).total_seconds()) <= window_sec
    )

# ---------------------------------------------------------------------------
# 4) Feature extraction
# ---------------------------------------------------------------------------
print("4) Extracting features...")

SQLI_KEYWORDS = [
    'union', 'select', 'insert', 'update', 'delete', 'drop', 'exec',
    'execute', 'sleep', 'benchmark', 'xp_cmdshell', 'information_schema',
    'or 1=1', "' or '", 'char(', 'cast(', 'convert(', 'waitfor',
    "admin'--", "); ", "from items", "from users"
]

BAD_UA_KEYWORDS = [
    'sqlmap', 'hydra', 'medusa', 'nikto', 'nmap', 'masscan',
    'dirbuster', 'gobuster', 'wfuzz', 'burpsuite', 'metasploit',
]

SENSITIVE_PATHS = [
    '/login', '/admin', '/wp-', '/config', '/phpinfo', '/.env',
    '/.git', '/backup', '/shell', '/server-status', '/proc/',
    '/etc/passwd', 'web.config', 'wp-config',
]

METHOD_MAP = {
    'GET': 0, 'POST': 1, 'PUT': 2, 'DELETE': 3,
    'HEAD': 4, 'OPTIONS': 5, 'PATCH': 6,
}

X_list = []
for i, data in enumerate(parsed_data):
    url         = unquote(data.get('url', ''))
    ua          = data.get('user_agent', '').lower()
    method      = data.get('method', 'GET')
    ts          = timestamps[i]
    ip          = data.get('ip', '')

    # --- Basic fields ---
    try:
        status = float(data['status'])
    except ValueError:
        status = 0.0

    try:
        size = float(data['size'])
    except ValueError:
        size = 0.0

    # --- Feature 1: URL special-character count (SQLi chars) ---
    sqli_chars = float(sum(1 for c in url if c in "'<>=;-()*|\\\""))

    # --- Feature 2: SQLi keyword hits in decoded URL ---
    url_lower       = url.lower()
    sqli_kw_hits    = float(sum(1 for kw in SQLI_KEYWORDS if kw in url_lower))

    # --- Feature 3: URL length (long URLs signal payloads) ---
    url_length = float(len(url))

    # --- Feature 4: Sensitive path targeted ---
    sensitive = float(any(p in url.lower() for p in SENSITIVE_PATHS))

    # --- Feature 5: Malicious user-agent ---
    bad_ua = float(any(kw in ua for kw in BAD_UA_KEYWORDS))

    # --- Feature 6: HTTP method encoded ---
    method_enc = float(METHOD_MAP.get(method, 7))

    # --- Feature 7: Response size (large 200 responses on sensitive paths) ---
    # already captured as `size`

    # --- Feature 8: Time-windowed IP request rate (brute force) ---
    ip_rate = float(requests_in_window(ip, ts, window_sec=60))

    # --- Feature 9: Status-code family (4xx/5xx are anomalous clusters) ---
    status_family = float(int(status) // 100)   # 2, 3, 4, or 5

    X_list.append([
        status,          # 0
        size,            # 1
        sqli_chars,      # 2
        sqli_kw_hits,    # 3
        url_length,      # 4
        sensitive,       # 5
        bad_ua,          # 6
        method_enc,      # 7
        ip_rate,         # 8
        status_family,   # 9
    ])

X = np.array(X_list, dtype=float)

# ---------------------------------------------------------------------------
# 5) Normalize (zero-mean, unit-variance) so no feature dominates tree splits
# ---------------------------------------------------------------------------
print("5) Normalizing features...")
X_mean = X.mean(axis=0)
X_std  = X.std(axis=0)
X_std[X_std == 0] = 1.0          # avoid divide-by-zero on constant columns
X_norm = (X - X_mean) / X_std

# ---------------------------------------------------------------------------
# 6) Isolation Forest
# ---------------------------------------------------------------------------
print("6) Running Isolation Forest...")
forest          = MyIsolationForest(n_estimators=100).fit(X_norm)
anomaly_scores  = forest.decision_function(X_norm)

# ---------------------------------------------------------------------------
# 7) Severity classification
# ---------------------------------------------------------------------------
def classify_severity(idx):
    url_lower   = unquote(raw_logs[idx]).lower()
    status      = X[idx, 0]
    sqli_kw     = X[idx, 3]
    bad_ua      = X[idx, 6]
    ip_rate     = X[idx, 8]
    sqli_chars  = X[idx, 2]
    sensitive   = X[idx, 5]

    DESTRUCTIVE_KEYWORDS = ['delete', 'drop', 'truncate', 'exec', 'xp_cmdshell', 'insert']
    is_destructive = any(kw in url_lower for kw in DESTRUCTIVE_KEYWORDS)

    if status == 200 and is_destructive:
        return "🔴 CRITICAL : Destructive SQLi Possibly Executed"
    if status == 200 and (sqli_kw > 0 or sqli_chars > 3):
        return "🔴 CRITICAL : Possible Successful SQLi Breach"
    if bad_ua and status == 200 and sensitive:
        return "🔴 CRITICAL : Attack Tool Reached Sensitive Endpoint"
    if sqli_kw > 0 and bad_ua:
        return "🟠 HIGH     : SQLi Attempt by Known Attack Tool"
    if ip_rate > 30:
        if sqli_kw > 0 or sqli_chars > 2:
            return "🟠 HIGH     : Brute Force + SQLi Combo Attack"
        return "🟠 HIGH     : Brute Force Pattern Detected"
    if sqli_kw > 0 or sqli_chars > 4:
        return "🟡 MEDIUM   : SQLi Attempt (Server Blocked)"
    if bad_ua:
        return "🟡 MEDIUM   : Known Attack Tool Detected"
    if sensitive and status in (200, 301, 302):
        return "🟠 HIGH     : Sensitive Path Accessed Successfully"

    return "🔵 LOW      : Suspected Anomaly"

# ---------------------------------------------------------------------------
# 8) Report top 10 anomalies
# ---------------------------------------------------------------------------
TOP_N       = 10
top_indices = np.argsort(anomaly_scores)[-TOP_N:][::-1]

print(f"\n{'─'*70}")
print(f"  Final Results — Top {TOP_N} Detected Anomalies")
print(f"{'─'*70}\n")

for rank, i in enumerate(top_indices, 1):
    score    = anomaly_scores[i]
    severity = classify_severity(i)
    print(f"Rank {rank:>2} | Line {i+1:<5} | Score: {score:.4f}")
    print(f"         {severity}")
    print(f"         {raw_logs[i].strip()}")
    print()

print(f"{'─'*70}")
print(f"Feature legend: [status, size, sqli_chars, sqli_kw_hits, url_len,")
print(f"                 sensitive_path, bad_ua, method, ip_rate_60s, status_family]")