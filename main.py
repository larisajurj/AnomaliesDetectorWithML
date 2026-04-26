import numpy as np
from isolation_forest import MyIsolationForest

# Normal data: fast response, small size
normal_logs = np.random.normal(loc=[0.2, 500], scale=[0.05, 50], size=(100, 2))

# Anomalies: very slow response (e.g., SQL injection/DDoS)
anomalous_logs = np.array([[5.0, 2000], [4.5, 1800], [0.1, 10000]])

X = np.vstack([normal_logs, anomalous_logs])

# Run our model
forest = MyIsolationForest(n_estimators=50).fit(X)
anomaly_scores = forest.decision_function(X)

# Results
for i, score in enumerate(anomaly_scores[-3:]):
    print(f"Anomaly log {i+1} - Score: {score:.4f} (Score > 0.6 is suspicious)")