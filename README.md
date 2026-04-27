# AnomaliesDetectorWithML

## Overview

This repository implements a Machine Learning-based Anomaly Detection system for web server access logs. It is designed to identify malicious activities such as SQL Injections, Brute Force attacks, and unauthorized scanning/enumeration using a custom-built **Isolation Forest** algorithm.

Instead of just relying on rigid rules, it uses a custom **Isolation Forest** machine learning algorithm to spot statistically unusual behavior. Then, it passes those anomalies through a few security rules to classify how dangerous they actually are.

> **Academic Context**:
> _8. Detector de Anomalii în Log-uri cu ML Simplu_
> _Antrenează un model de detecție a anomaliilor (Isolation Forest sau similar) pe log-uri de acces web sintetice sau reale._
> _Tenta personală: Studentul generează un set de date inspirat dintr-un scenariu de atac studiat._

## Features

- **Custom Isolation Forest**: A from-scratch implementation of the Isolation Forest algorithm (`isolation_forest.py`).
- **Attack Simulation**: A Python script (`generate_logs.py`) that generates highly realistic Apache/Nginx combined access logs, simulating normal traffic mixed with Brute Force, SQL Injections, and path traversal scans.
- **Advanced Feature Engineering**: The parsing pipeline (`main.py`) extracts critical security metrics from raw text logs, including:
  - Time-windowed IP request rates (for detecting volumetric brute force attacks).
  - SQLi keyword and special character frequencies.
  - Malicious User-Agent detection (e.g., Hydra, SQLMap).
  - Sensitive path targeting (`/login`, `/admin`, etc.).
- **Contextual Severity Scoring**: ML anomaly scores identify the outliers, but a post-processing heuristic engine categorizes them into actionable severities (e.g., `🔴 CRITICAL`, `🟠 HIGH`, `🟡 MEDIUM`, `🔵 LOW`).

## Files

- `main.py` - The main script. It loads the logs, extracts features, runs the ML model, and prints the results.
- `isolation_forest.py` - The ML model.
- `generate_logs.py` - Run this to generate a fresh `access.log` dataset.
- `access.log` - The raw dataset.
- `anomalies_output.csv` - The output file generated after running the detector.

## How to Run

1. **(Optional) Generate a new dataset**:

   ```bash
   python generate_logs.py
   ```

2. **Run the detector**:
   ```bash
   python main.py
   ```
   This will parse the logs, apply the Isolation Forest, and print the detected threats to the console while also saving them to a CSV file (`anomalies_output.csv`).
