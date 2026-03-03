# KQL Detection Queries

## Brute Force Login Detection
**MITRE ATT&CK:** T1110 - Brute Force  
**NIST CSF:** Detect
```kql
ThreatSimulation_CL
| where EventType_s == "FailedLogin"
| where TimeGenerated > ago(1h)
| summarize AttemptCount = count() by SourceIP
| where AttemptCount >= 3
| extend NISTCategory = "Detect"
| extend MITRETechnique = "T1110 - Brute Force"
| extend Recommendation = "Block IP and investigate"
```

## Port Scan Detection
**MITRE ATT&CK:** T1046 - Network Service Discovery  
**NIST CSF:** Detect
```kql
PortScanSimulation_CL
| where EventType_s == "PortScan"
| where TimeGenerated > ago(1h)
| summarize PortsScanned = count(), Ports = make_set(DestinationPort_d) by SourceIP
| where PortsScanned >= 5
| extend NISTCategory = "Detect"
| extend MITRETechnique = "T1046 - Network Service Discovery"
| extend Recommendation = "Block IP and investigate scanning activity"
```
