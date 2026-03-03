# Azure Threat Monitor

A cloud-based security monitoring homelab using Microsoft Azure Sentinel to detect, 
alert, and respond to simulated cyber threats. Built to demonstrate SOC analyst 
skills including threat detection, KQL querying, and NIST CSF alignment.

---

## 🛠️ Tech Stack
- Microsoft Azure Sentinel (SIEM)
- Log Analytics Workspace
- Azure Monitor Agent + Data Collection Rules
- Python (threat simulation via REST API)
- KQL (Kusto Query Language)
- MITRE ATT&CK Framework
- NIST Cybersecurity Framework

---

## 📁 Project Structure
```
azure-threat-monitor/
├── README.md
├── scripts/
│   ├── threat_simulation.py       # Brute force login simulation
│   └── port_scan.py    # Port scan simulation
├── queries/
│   └── alerts.md                  # KQL detection queries
└── docs/
    └── nist-mapping.md            # NIST CSF mapping
```

---

## 🔍 Threat Simulations

### 1. Brute Force Login Attack
- Simulates repeated failed login attempts from malicious IPs
- Sends events to Sentinel via Python REST API
- **MITRE ATT&CK:** T1110 - Brute Force
- **NIST CSF:** Detect

### 2. Port Scan Detection
- Simulates sequential port scanning across common ports
- Detects reconnaissance activity before an attack
- **MITRE ATT&CK:** T1046 - Network Service Discovery
- **NIST CSF:** Detect

---

## ⚙️ How It Works
1. Python scripts simulate threat events and send them directly to 
   Azure Log Analytics via REST API
2. Microsoft Sentinel ingests the events into custom log tables
3. KQL scheduled query rules run every 5 minutes to detect threats
4. Sentinel automatically creates incidents when threats are detected
5. Incidents are tagged and mapped to MITRE ATT&CK and NIST CSF

---

## 📸 Screenshots
> Add your Sentinel incident screenshots here

---

## 🚀 How to Run
1. Clone the repo
2. Install dependencies:
```bash
pip install requests
```
3. Add your Azure credentials to the scripts:
```python
workspace_id = "YOUR_WORKSPACE_ID"
primary_key = "YOUR_PRIMARY_KEY"
```
4. Run simulations:
```bash
python3 scripts/threat_simulation.py
python3 scripts/port_scan.py
```

---

## ⚠️ Warning
This project is for educational purposes (Homelab project) only. All threat simulations and scanning 
are conducted in a controlled Azure environment with no real systems targeted. Please do not do this project outside any isolated environment from your local machine
