# Malware-Monitoring-Lab

# Automated Malware Monitoring & AI Integration

---

## Overview

This project is a Streamlit-based Security Operations Center (SOC) dashboard for real-time malware and system anomaly monitoring. It combines OS/process/network/file monitoring with a pretrained anomaly detection model (joblib) to surface suspicious behaviour and recommend countermeasures.

The app is intended as a defensive research tool for incident responders, blue teams, and security researchers. It runs locally or on a private server and pushes alerts to the UI where you can inspect details and download evidence.

---

## Key Features

* Real-time OS metrics: CPU, memory, disk, processes, network activity.
* Directory monitoring with file event hashing and integrity checks.
* Anomaly detection using a pretrained model (`anomaly_detector.joblib`) + scaler (`scaler.joblib`).
* Forensics view with detailed alert payloads and recommended countermeasures.
* Simple Threat Intelligence integration hooks (VirusTotal, YARA, etc.)
* Streamlit UI with dashboard, processes, network, file events, alerts, and forensics tabs.

---

## Architecture

1. **Data collectors** (local): gather CPU, memory, disk, processes, and network stats regularly.
2. **Directory watcher**: records file creation, modification, deletion and computes hashes.
3. **Feature extractor**: converts raw telemetry into features expected by the ML model.
4. **Anomaly detector**: scaler -> model pipeline (joblib) that outputs an anomaly score.
5. **Streamlit frontend**: displays metrics, charts, alerts and investigation tools.
6. **Optional SIEM export**: send structured events to Splunk HEC / ELK / remote SIEM.

---

## Repository Structure

```
Automated-Malware-Monitoring-AI/
├── ai_models/
│   ├── anomaly_detector.joblib        # pretrained model
│   └── scaler.joblib                  # preprocessing scaler
├── data/                              # optional sample telemetry or logs
├── scripts/
│   ├── train_model.py                 # model training & export script
│   └── feature_extractor.py           # code to build model features
├── screenshots/
│   ├── dashboard.png
│   ├── forensics_tab.png
│   └── run_terminal.png
├── main.py                            # Streamlit app (entrypoint)
├── requirements.txt
├── README.md
└── .gitignore
```

> **Note:** Replace heavy model binaries with placeholders when sharing publicly. Provide download links or instructions to train locally.

---

## Installation

1. Clone the repository:

```bash
git clone https://github.com/<your-username>/Automated-Malware-Monitoring-AI.git
cd Automated-Malware-Monitoring-AI
```

2. Create and activate a Python virtual environment:

```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS/Linux
source .venv/bin/activate
```

3. Install dependencies:

```bash
pip install -r requirements.txt
```


<img width="996" height="834" alt="Screenshot 2025-09-17 174843" src="https://github.com/user-attachments/assets/59c395f0-a1aa-4760-af34-8f68e22401cf" />




4. Run the Streamlit app:

```bash
python -m streamlit run main.py
```


<img width="999" height="315" alt="Screenshot 2025-09-17 175017" src="https://github.com/user-attachments/assets/72e540d0-bc53-4eba-acae-b5808971329b" />






Access via `http://localhost:8501`.

---

## Requirements

```
streamlit>=1.23.0
psutil
watchdog
pandas
numpy
scikit-learn
joblib
matplotlib
plotly
requests
pywin32; platform_system == 'Windows'
```

---


<img width="646" height="296" alt="Screenshot 2025-09-17 195719" src="https://github.com/user-attachments/assets/800dfafd-e9cf-4aa5-8d23-dadef96ac100" />




## Usage

* Start the app with `python -m streamlit run main.py`.
* View real-time system metrics and anomaly alerts.
* Use the Forensics tab for detailed threat analysis.
* Monitor selected directories for malicious file events.

---




<img width="1913" height="922" alt="Screenshot 2025-09-17 175115" src="https://github.com/user-attachments/assets/464d8bb5-f1b6-465a-9956-0c85bb8a7438" />






<img width="1904" height="912" alt="Screenshot 2025-09-17 175056" src="https://github.com/user-attachments/assets/1ac0d6a3-98c2-4868-9d90-21262a540da0" />





## Model Training

Use `scripts/train_model.py` to:

1. Load training telemetry data.
2. Extract features (`scripts/feature_extractor.py`).
3. Train scaler + anomaly detection model (Isolation Forest, One-Class SVM, or Autoencoder).
4. Export `scaler.joblib` and `anomaly_detector.joblib`.

---

## Security

* Do not commit API keys or sensitive logs.
* Anonymize or sample telemetry before sharing.
* Add sensitive files to `.gitignore`.

Example `.gitignore`:

```
.venv/
__pycache__/
*.pyc
ai_models/*.joblib
data/*.db
.env
```

---

## Future Enhancements

* Role-based access for Streamlit UI.
* Agent-based collectors with secure TLS transport.
* VirusTotal integrations.
* Docker + docker-compose support.


---

# Author
Salami Shuaib A. Cybersecurty Consultant
Date: 17th September, 2025.



---


