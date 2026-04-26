import numpy as np
import os
import sys
import re
from collections import defaultdict
from datetime import datetime
from urllib.parse import unquote
from isolation_forest import MyIsolationForest

def classify_severity(status, sqli_chars, sqli_keywords, bad_ua, url, ip_rate):
    if status == 200 and (sqli_chars > 2 or sqli_keywords > 0):
        return "CRITICAL: Possible Successful SQLi Breach"
    if bad_ua and status == 200:
        return "CRITICAL: Attack Tool Got 200 Response"
    if ip_rate > 50:
        return "HIGH: Brute Force Pattern Detected"
    if sqli_keywords > 0:
        return "MEDIUM: SQLi Attempt (Blocked)"
    return "LOW: Suspected Anomaly"

def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    log_file = os.path.join(script_dir, 'access.log')

    if not os.path.exists(log_file):
        print(f"Error: '{log_file}' not found. Please run 'generate_logs.py' first.")
        sys.exit(1)

    print("1) Loading data...")
    with open(log_file, 'r') as f:
        raw_logs = f.readlines()

    print("2) Preprocessing & 3) Parsing data...")
    log_pattern = re.compile(
        r'(?P<ip>\S+) \S+ \S+ \[(?P<date>[^\]]+)\] '
        r'"(?P<method>\S+) (?P<url>\S+) [^"]*" '
        r'(?P<status>\d+) (?P<size>\S+) '
        r'"(?P<referer>[^"]*)" '
        r'"(?P<user_agent>[^"]*)"'
    )

    parsed_data = []
    valid_raw_logs = []
    for line in raw_logs:
        match = log_pattern.match(line)
        if match:
            parsed_data.append(match.groupdict())
            valid_raw_logs.append(line)
            
    print(f"Parsed {len(parsed_data)}/{len(raw_logs)} lines successfully.")

    print("4) Feature extraction & 5) Vectorization...")
    def parse_timestamp(date_str):
        try:
            return datetime.strptime(date_str, "%d/%b/%Y:%H:%M:%S %z")
        except ValueError:
            return datetime.now()

    timestamps = [parse_timestamp(d['date']) for d in parsed_data]
    ip_time_map = defaultdict(list)
    for i, d in enumerate(parsed_data):
        ip_time_map[d['ip']].append(timestamps[i])

    def requests_in_window(ip, ts, window_seconds=60):
        times = ip_time_map[ip]
        return sum(1 for t in times if abs((t - ts).total_seconds()) <= window_seconds)

    # Extract relevant features to build the numerical matrix X
    X_list = []
    sqli_keywords = ['union', 'select', 'insert', 'delete', 'drop', 'exec',
                     'sleep', 'benchmark', 'xp_cmdshell', 'information_schema']
    bad_ua_keywords = ['sqlmap', 'hydra', 'medusa', 'nikto', 'nmap', 'masscan']

    for i, data in enumerate(parsed_data):
        # Safely handle time if present (fallback to 0.0)
        time_val = data.get('time')
        try:
            response_time = float(time_val) if time_val else 0.0
        except ValueError:
            response_time = 0.0
            
        # Safely handle size (Apache uses '-' for 0 bytes)
        try:
            response_size = float(data['size'])
        except ValueError:
            response_size = 0.0
            
        status_code = float(data['status'])
        
        url = data.get('url', '')
        url_decoded = unquote(url)
        
        # Features: URL metrics
        url_special_chars = float(sum(1 for char in url if char in "'<>=;-()*"))
        sqli_keyword_hits = float(sum(1 for kw in sqli_keywords if kw in url_decoded.lower()))
        url_length = float(len(url_decoded))
        sensitive_path = float(any(p in url.lower() for p in ['/login', '/admin', '/wp-', '/config']))
        
        # Features: UA metrics
        ua = data.get('user_agent', '')
        bad_ua = float(any(kw in ua.lower() for kw in bad_ua_keywords))
        
        # Features: Protocol & Traffic metrics
        method = data.get('method', 'GET')
        method_encoded = float({'GET': 0, 'POST': 1, 'PUT': 2, 'DELETE': 3, 'HEAD': 4, 'OPTIONS': 5}.get(method, 6))
        ip_rate = float(requests_in_window(data['ip'], timestamps[i]))

        X_list.append([
            response_time, response_size, status_code, url_special_chars,
            sqli_keyword_hits, url_length, sensitive_path, bad_ua, method_encoded, ip_rate
        ])

    # Vectorize into a NumPy array ready for Machine Learning
    X = np.array(X_list)
    
    # Normalize features before fitting so features scale fairly
    X_mean = X.mean(axis=0)
    X_std  = X.std(axis=0) + 1e-9  # Add tiny epsilon to avoid divide-by-zero
    X_norm = (X - X_mean) / X_std

    print("6) Anomaly detection...")
    forest = MyIsolationForest(n_estimators=50).fit(X_norm)
    anomaly_scores = forest.decision_function(X_norm)

    print("\n--- Final Results (Top 5 Detected Anomalies) ---")
    # Sort scores descending and get the indices of the top 5 highest scores
    top_indices = np.argsort(anomaly_scores)[-5:][::-1]

    for rank, idx in enumerate(top_indices, 1):
        score = anomaly_scores[idx]
        
        # Retrieve features to assign a categorized severity label
        status = X[idx][2]
        sqli_chars = X[idx][3]
        sqli_kws = X[idx][4]
        is_bad_ua = X[idx][7]
        ip_rate_val = X[idx][9]
        url_val = parsed_data[idx].get('url', '')
        
        severity = classify_severity(status, sqli_chars, sqli_kws, is_bad_ua, url_val, ip_rate_val)
            
        print(f"Rank {rank} | Line {idx+1} | Score: {score:.4f} {severity}")
        print(f"  Raw log: {valid_raw_logs[idx].strip()}\n")

if __name__ == "__main__":
    main()