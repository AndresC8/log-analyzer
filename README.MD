🛡️ SOC Analyzer – Log Analysis & Detection Dashboard

SOC Analyzer is a hands-on cybersecurity project designed to simulate how a Security Operations Center (SOC) works internally.

The project focuses on log ingestion, normalization, rule-based detections and analyst-style reporting, without relying on commercial SIEM platforms.

It is built as a learning and portfolio project to understand SOC workflows, detection engineering basics and log analysis at scale.

🚀 Key Features
🔹 Log Ingestion

CSV-based log ingestion

Supports authentication-style logs

Schema validation before processing

🔹 Log Normalization

Logs are normalized to a common schema before detections

Required fields:

timestamp

event_type

source_ip

username

This mimics how SIEMs normalize logs from different sources.

🔍 Detection Capabilities (Rule-Based)

The detection engine is modular and currently includes:

✅ Brute Force Detection

Identifies IPs with repeated failed login attempts

Configurable threshold and time window

✅ Successful Brute Force

Detects successful logins after multiple failed attempts

Helps identify potential account compromise

✅ Port Scanning Detection

Detects excessive port_probe events from the same source IP

Simulates network reconnaissance behavior

✅ Off-Hours Logins

Detects successful logins during suspicious hours (e.g. 00:00–05:00)

Useful for anomaly-based investigations

📊 Interactive Dashboard

The project includes an interactive dashboard built with:

Streamlit (UI)

Altair (visualizations)

Pandas (data processing)

Dashboard features:

Overview metrics

Detection-specific tabs

Time-based visualizations

Performance-optimized rendering for large datasets

🤖 SOC Copilot (Optional)

An optional SOC Copilot module uses an LLM to generate a structured SOC-style report based on detection results.

If enabled, it provides:

Executive summary

Technical findings

MITRE ATT&CK mapping

Attack hypotheses

Response & hardening recommendations

⚠️ SOC Copilot is optional and gracefully disabled if no API key is configured.

🧠 Why This Project?

This project was built to practice and demonstrate:

Log analysis fundamentals

Detection logic and thresholds

SOC workflows and triage thinking

How SIEM-like tools work internally

Data visualization for security use cases

It is not meant to replace a SIEM, but to understand how one works under the hood.

🧱 Project Architecture (Simplified)
soc-analyzer/
├── analyzer/
│   ├── detections/
│   │   ├── auth.py
│   │   └── network.py
│   ├── metrics.py
│   └── copilot.py
├── dashboard.py
├── data/
│   └── sample_logs.csv
├── .streamlit/
│   └── secrets.toml
├── requirements.txt
└── README.md

▶️ How to Run Locally
1️⃣ Clone the repository
git clone https://github.com/yourusername/soc-analyzer.git
cd soc-analyzer

2️⃣ Install dependencies
pip install -r requirements.txt

3️⃣ Run the dashboard
streamlit run dashboard.py

4️⃣ Upload a CSV log file

Use the file uploader in the sidebar to load sample or custom logs.

📁 Sample Data

The repository includes synthetic log datasets that simulate:

Aggressive brute force attacks

Port scanning

Off-hours logins

Normal background authentication traffic

These datasets are designed for demo and learning purposes only.

🛠️ Tech Stack

Python

Pandas

Streamlit

Altair

OpenAI API (optional, for SOC Copilot)

📌 Future Improvements (Out of Scope for v3)

Additional log types (firewall, web, cloud)

Advanced parsing modules

Detection tuning & false positive reduction

API-based ingestion

Detection-as-code configuration

⚠️ Disclaimer

This project uses synthetic data only.
It is intended for educational and portfolio purposes, not production use.

🙌 Feedback

Feedback and suggestions are welcome.
This project is part of a continuous learning journey in cybersecurity and SOC operations