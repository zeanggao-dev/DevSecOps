# Cyber Range Runbook (CentOS, Low Resource)

## Scope
This cyber range is defensive simulation for validating cloud firewall, WAF, ACL, IPS, anti-virus, and host security controls.

## Requirements
- Python 3.8+
- No external Python dependencies
- One low-resource VM can run service and UI
- Optional second VM can act as attacker simulator

## Files
- sec-lab.py: Backend API service and simulation engine
- index.html: Home page
- dashboard.html: Operational dashboard
- attacks.html: SQLi and traversal console
- controls.html: Security control manager
- events.html: Event timeline
- range-automation.py: End-to-end quick demo
- automation/attack-matrix.py: Broad payload matrix
- automation/policy-transition-demo.py: Detect versus enforce comparison
- automation/continuous-batch.py: Repeated stability batches

## 1) Start Cyber Range Service (Defender VM)
```bash
cd ~/CodeSpace/kubernetes-devops-security/security-range
python3 sec-lab.py --host 0.0.0.0 --port 8080
```

Open in browser:
- http://<defender-vm-ip>:8080/

## 2) Multi-Page UI Walkthrough
- Home: http://<defender-vm-ip>:8080/index.html
- Dashboard: http://<defender-vm-ip>:8080/dashboard.html
- Attack Console: http://<defender-vm-ip>:8080/attacks.html
- Security Controls: http://<defender-vm-ip>:8080/controls.html
- Events: http://<defender-vm-ip>:8080/events.html

## 3) Attack Feedback Demo (from attacker VM)
SQLi request:
```bash
curl "http://<defender-vm-ip>:8080/demo/search?q=' OR 1=1 -- SQLI_TEST_TOKEN&source_vm=attacker-vm"
```

Traversal request:
```bash
curl "http://<defender-vm-ip>:8080/demo/file?path=../../../../etc/passwd&source_vm=attacker-vm"
```

Expected behavior:
- If controls are detect or disabled: request can return demo vulnerable response
- If WAF or IPS are enforce: request returns blocked response (HTTP 403)

## 4) Security Control API
View control state:
```bash
curl http://127.0.0.1:8080/api/controls
```

Enable enforce mode example:
```bash
curl -X POST http://127.0.0.1:8080/api/control/update \
  -H "Content-Type: application/json" \
  -d '{"control":"waf","enabled":true,"mode":"enforce"}'
```

## 5) Automation Scripts
Quick end-to-end run:
```bash
python3 range-automation.py --target http://<defender-vm-ip>:8080 --output automation-report.json
```

Broad matrix (many payloads each category):
```bash
python3 automation/attack-matrix.py --target http://<defender-vm-ip>:8080 --json-output matrix-report.json --csv-output matrix-report.csv
```

Policy transition comparison:
```bash
python3 automation/policy-transition-demo.py --target http://<defender-vm-ip>:8080 --output policy-transition-report.json
```

Repeated trend batch:
```bash
python3 automation/continuous-batch.py --target http://<defender-vm-ip>:8080 --iterations 10 --sleep 1.0 --output continuous-batch-report.json
```

## 6) Key APIs
- GET /api/health
- GET /api/controls
- GET /api/report
- GET /api/events?limit=100
- GET /demo/search?q=...&source_vm=attacker-vm
- GET /demo/file?path=...&source_vm=attacker-vm
- POST /api/execute
- POST /api/control/update
- POST /api/firewall/evaluate
- POST /api/waf/evaluate
- POST /api/upload-json

## 7) Security Notes
- This environment does not execute real exploitation payloads.
- It uses safe indicators and simulation logic to validate control response.
- Use only in authorized lab environments.
