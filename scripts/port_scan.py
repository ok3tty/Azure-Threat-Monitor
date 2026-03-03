import json
import hmac
import hashlib
import base64
import requests
from datetime import datetime, timezone
import time
import random

# Your credentials
workspace_id = "WORKSPACE ID"
primary_key = "PRIMARY KEY"
log_type = "PortScanSimulation"

def build_signature(date, content_length, method, content_type, resource):
    x_headers = f"x-ms-date:{date}"
    string_to_hash = f"{method}\n{content_length}\n{content_type}\n{x_headers}\n{resource}"
    bytes_to_hash = string_to_hash.encode("utf-8")
    decoded_key = base64.b64decode(primary_key + "==")
    encoded_hash = base64.b64encode(
        hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()
    ).decode("utf-8")
    return f"SharedKey {workspace_id}:{encoded_hash}"

def post_data(body):
    method = "POST"
    content_type = "application/json"
    resource = "/api/logs"
    rfc1123date = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")
    content_length = len(body)
    signature = build_signature(rfc1123date, content_length, method, content_type, resource)
    uri = f"https://{workspace_id}.ods.opinsights.azure.com{resource}?api-version=2016-04-01"
    headers = {
        "Content-Type": content_type,
        "Authorization": signature,
        "Log-Type": log_type,
        "x-ms-date": rfc1123date
    }
    response = requests.post(uri, data=body, headers=headers)
    return response.status_code

# Common ports attackers scan
target_ports = [22, 23, 80, 443, 445, 3389, 8080, 3306, 5432, 21]
attacker_ip = "185.220.101.47"  # Fake malicious IP
target_ip = "20.3.249.19"       # Your VM IP

print("Starting port scan simulation...")

for port in target_ports:
    event = [{
        "TimeGenerated": datetime.now(timezone.utc).isoformat(),
        "EventType": "PortScan",
        "SourceIP": attacker_ip,
        "DestinationIP": target_ip,
        "DestinationPort": port,
        "Protocol": "TCP",
        "Status": random.choice(["Open", "Closed", "Filtered"]),
        "Severity": "Medium",
        "Description": f"Port scan detected on port {port}",
        "NISTCategory": "Detect",
        "MITRETactic": "Discovery",
        "MITRETechnique": "T1046 - Network Service Discovery"
    }]
    body = json.dumps(event)
    status = post_data(body)
    print(f"Port {port} scan event sent - Status: {status}")
    time.sleep(1)

print("Port scan simulation complete!")
