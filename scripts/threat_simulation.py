import json
import hmac
import hashlib
import base64
import requests
from datetime import datetime, timezone
import time

# Your credentials - keep these private!
workspace_id = "9a897498-bd74-42c9-90e6-d89767ae75b2"
primary_key = "Q33T5KQWuW9SBjikl3alFAiMPay12MiAdZDGYtYB5W//68CFBrN184qnEYed01Mx61rvVXbS8+7rWBqbaXisdQ"
log_type = "ThreatSimulation"

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

# Simulate brute force attacks
attackers = ["192.168.1.105", "10.0.0.23", "172.16.0.45"]
usernames = ["admin", "administrator", "root", "user1"]

print("Starting threat simulation...")

for i in range(10):
    event = [{
        "TimeGenerated": datetime.now(timezone.utc).isoformat(),
        "EventType": "FailedLogin",
        "SourceIP": attackers[i % len(attackers)],
        "TargetUsername": usernames[i % len(usernames)],
        "AttemptNumber": i + 1,
        "Severity": "High",
        "Description": "Brute force login attempt detected",
        "NISTCategory": "Detect"
    }]
    body = json.dumps(event)
    status = post_data(body)
    print(f"Event {i+1} sent - Status: {status}")
    time.sleep(1)

print("Simulation complete!")
