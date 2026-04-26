import numpy as np
import os
import sys
import re
from collections import Counter
from isolation_forest import MyIsolationForest

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
    r'(?P<ip>\S+) \S+ \S+ \[(?P<date>.*?)\] "(?P<method>\S+) (?P<url>\S+).*?" (?P<status>\d+) (?P<size>\S+)(?: (?P<time>\S+))?'
)

parsed_data = []
for line in raw_logs:
    match = log_pattern.match(line)
    if match:
        parsed_data.append(match.groupdict())

print("4) Feature extraction & 5) Vectorization...")
# Pre-calculate IP frequencies to detect high-rate brute force attacks
ip_counts = Counter(d['ip'] for d in parsed_data)

# Extract relevant features to build the numerical matrix X
X_list = []
for data in parsed_data:
    # Safely handle time (might be missing or '"-"' in standard combined logs)
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
    
    # Feature 4: URL Special Characters (Flags SQLi payloads like ' OR 1=1 --)
    url = data.get('url', '')
    url_special_chars = float(sum(1 for char in url if char in "'<>=;-()*"))
    
    # Feature 5: IP Frequency (Flags Brute Force / Scanners hitting the server rapidly)
    ip_freq = float(ip_counts.get(data.get('ip'), 1))

    X_list.append([response_time, response_size, status_code, url_special_chars, ip_freq])

# Vectorize into a NumPy array ready for Machine Learning
X = np.array(X_list)

print("6) Anomaly detection...")
forest = MyIsolationForest(n_estimators=50).fit(X)
anomaly_scores = forest.decision_function(X)

print("\n--- Final Results (Top 5 Detected Anomalies) ---")
# Sort scores descending and get the indices of the top 5 highest scores
top_indices = np.argsort(anomaly_scores)[-5:][::-1]

for i in top_indices:
    score = anomaly_scores[i]
    print(f"Line {i+1} - Score: {score:.4f} (Suspected Anomaly)")
    print(f"  Raw log: {raw_logs[i].strip()}\n")