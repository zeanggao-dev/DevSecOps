#!/usr/bin/env python3
"""
Low-resource cyber range backend for private cloud VM PoC.

This service intentionally provides defensive simulation only:
- It does not execute exploit code.
- It does not generate malware.
- It evaluates whether configured controls would detect or block test signals.
"""

import argparse
import base64
import hashlib
import json
import mimetypes
import sqlite3
import threading
import time
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict, List, Any
from urllib.parse import parse_qs, urlparse, unquote


BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "cyber_range.db"
INDEX_FILE = BASE_DIR / "index.html"
STATIC_ROOT = BASE_DIR

# Explicit MIME map so CentOS minimal (no /etc/mime.types) still works correctly.
_MIME_MAP: Dict[str, str] = {
    ".html": "text/html; charset=utf-8",
    ".htm": "text/html; charset=utf-8",
    ".css": "text/css",
    ".js": "application/javascript",
    ".json": "application/json",
    ".txt": "text/plain; charset=utf-8",
    ".ico": "image/x-icon",
    ".png": "image/png",
    ".svg": "image/svg+xml",
}

# Simulation data – realistic vulnerable responses for authorized PoC lab only.
# External security products (CFW / WAF / IPS / AV) do the blocking from outside.
_SIMULATED_DB = [
    {"id": 1, "username": "admin",     "password_hash": "5f4dcc3b5aa765d61d8327deb882cf99", "role": "platform-admin",  "email": "admin@corp.local",     "api_key": "aks-prod-a1b2c3d4e5f6"},
    {"id": 2, "username": "dbservice", "password_hash": "7c6a180b36896a0a8c02787eeafb0e4c", "role": "service-account", "email": "dbservice@corp.local", "api_key": "aks-svc-z9y8x7w6v5"},
    {"id": 3, "username": "appuser",   "password_hash": "d8578edf8458ce06fbc5bb76a58c5ca4", "role": "readonly",        "email": "appuser@corp.local",   "api_key": "aks-ro-1a2b3c4d5e"},
    {"id": 4, "username": "operator",  "password_hash": "827ccb0eea8a706c4c34a16891f84e7b", "role": "operator",        "email": "operator@corp.local",  "api_key": "aks-ops-f0e1d2c3b4"},
]

_SIMULATED_FILES: Dict[str, str] = {
    "/etc/passwd": (
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "appuser:x:1001:1001:App User:/home/appuser:/bin/bash\n"
        "dbservice:x:1002:1002:DB Service:/home/dbservice:/sbin/nologin\n"
    ),
    "/etc/shadow": (
        "root:$6$rounds=5000$NaCl$longhash1:19000:0:99999:7:::\n"
        "appuser:$6$rounds=5000$NaCl$longhash2:19000:0:99999:7:::\n"
    ),
    "/etc/hosts": (
        "127.0.0.1   localhost\n"
        "10.0.1.100  db-prod-01.corp.local\n"
        "10.0.2.50   mgmt-server.corp.local\n"
    ),
    "/proc/version": "Linux version 5.14.0-284.11.1.el9_2.x86_64 (gcc 11.3.1) #1 SMP",
    "/app/config.yaml": (
        "database:\n  host: db-prod-01.corp.local\n  port: 5432\n"
        "  user: dbservice\n  password: Pr0d@Pass!2024\n"
        "jwt_secret: s3cr3t-jwt-k3y-pr0d\n"
    ),
}

_SIMULATED_CMD: Dict[str, str] = {
    "id":        "uid=0(root) gid=0(root) groups=0(root)",
    "whoami":    "root",
    "hostname":  "app-server-prod-01",
    "uname -a":  "Linux app-server-prod-01 5.14.0-284.11.1.el9_2.x86_64 #1 SMP x86_64",
    "env": (
        "DB_HOST=db-prod-01.corp.local\nDB_PASS=Pr0d@Pass!2024\n"
        "JWT_SECRET=s3cr3t-jwt-k3y-pr0d\n"
        "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
        "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
    ),
    "ps aux": (
        "USER       PID %CPU COMMAND\n"
        "root         1  0.0 /sbin/init\n"
        "appuser   1024  0.5 /opt/app/app-server\n"
        "dbservice 1025  0.1 /usr/bin/postgres\n"
    ),
    "ls /":          "bin boot dev etc home lib opt proc root run sbin srv sys tmp usr var",
    "netstat -tlnp": (
        "tcp  0.0.0.0:8080   LISTEN 1024/app-server\n"
        "tcp  127.0.0.1:5432 LISTEN 1025/postgres\n"
        "tcp  0.0.0.0:22     LISTEN 866/sshd\n"
    ),
}

_SIMULATED_SSRF: Dict[str, str] = {
    "http://169.254.169.254/latest/meta-data/": (
        "ami-id\nami-launch-index\nhostname\ninstance-id\n"
        "local-ipv4\npublic-ipv4\niam/security-credentials/"
    ),
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/ec2-role": (
        '{"Code":"Success","AccessKeyId":"ASIAIOSFODNN7EXAMPLE",'
        '"SecretAccessKey":"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",'
        '"Token":"AQoXnyc4lcK4w4."}'
    ),
    "http://10.0.2.50:8500/v1/kv/": '["config/db_password","config/jwt_secret","config/api_key"]',
}



class TestCase:
	def __init__(
		self,
		id: str,
		name: str,
		severity: str,
		expected_block: bool,
		vector: str,
		indicators: List[str],
		controls: List[str],
	) -> None:
		self.id = id
		self.name = name
		self.severity = severity
		self.expected_block = expected_block
		self.vector = vector
		self.indicators = indicators
		self.controls = controls

	def to_dict(self) -> Dict[str, Any]:
		return {
			"id": self.id,
			"name": self.name,
			"severity": self.severity,
			"expected_block": self.expected_block,
			"vector": self.vector,
			"indicators": self.indicators,
			"controls": self.controls,
		}


class CyberRangeStore:
	def __init__(self, db_path: Path) -> None:
		self.db_path = db_path
		self._lock = threading.Lock()
		self._init_db()

	def _connect(self) -> sqlite3.Connection:
		conn = sqlite3.connect(self.db_path)
		conn.row_factory = sqlite3.Row
		return conn

	def _init_db(self) -> None:
		with self._connect() as conn:
			conn.execute(
				"""
				CREATE TABLE IF NOT EXISTS events (
					id INTEGER PRIMARY KEY AUTOINCREMENT,
					ts TEXT NOT NULL,
					event_type TEXT NOT NULL,
					source_vm TEXT,
					details_json TEXT NOT NULL
				)
				"""
			)
			conn.execute(
				"""
				CREATE TABLE IF NOT EXISTS control_state (
					control_name TEXT PRIMARY KEY,
					enabled INTEGER NOT NULL,
					mode TEXT NOT NULL
				)
				"""
			)

	def ensure_default_controls(self, defaults: Dict[str, Dict[str, Any]]) -> None:
		with self._lock, self._connect() as conn:
			for name, state in defaults.items():
				try:
					conn.execute(
						"""
						INSERT INTO control_state(control_name, enabled, mode)
						VALUES(?, ?, ?)
						""",
						(name, int(state["enabled"]), state["mode"]),
					)
				except sqlite3.IntegrityError:
					# Control already exists; keep current persisted value.
					pass

	def get_controls(self) -> Dict[str, Dict[str, Any]]:
		with self._lock, self._connect() as conn:
			rows = conn.execute(
				"SELECT control_name, enabled, mode FROM control_state ORDER BY control_name"
			).fetchall()
		return {
			row["control_name"]: {
				"enabled": bool(row["enabled"]),
				"mode": row["mode"],
			}
			for row in rows
		}

	def update_control(self, name: str, enabled: bool, mode: str) -> bool:
		with self._lock, self._connect() as conn:
			cur = conn.execute(
				"UPDATE control_state SET enabled=?, mode=? WHERE control_name=?",
				(int(enabled), mode, name),
			)
			return cur.rowcount > 0

	def log_event(self, event_type: str, details: Dict[str, Any], source_vm: str = "") -> None:
		with self._lock, self._connect() as conn:
			conn.execute(
				"INSERT INTO events(ts, event_type, source_vm, details_json) VALUES(?, ?, ?, ?)",
				(
					datetime.now(timezone.utc).isoformat(),
					event_type,
					source_vm,
					json.dumps(details, separators=(",", ":")),
				),
			)

	def recent_events(self, limit: int = 100) -> List[Dict[str, Any]]:
		with self._lock, self._connect() as conn:
			rows = conn.execute(
				"SELECT ts, event_type, source_vm, details_json FROM events ORDER BY id DESC LIMIT ?",
				(limit,),
			).fetchall()
		out: List[Dict[str, Any]] = []
		for row in rows:
			out.append(
				{
					"timestamp": row["ts"],
					"event_type": row["event_type"],
					"source_vm": row["source_vm"],
					"details": json.loads(row["details_json"]),
				}
			)
		return out


class CyberRangeEngine:
	def __init__(self, store: CyberRangeStore) -> None:
		self.store = store
		self.test_suites: Dict[str, List[TestCase]] = self._load_test_suites()
		self.default_controls: Dict[str, Dict[str, Any]] = {
			"acl": {"enabled": True, "mode": "enforce"},
			"firewall": {"enabled": True, "mode": "enforce"},
			"waf": {"enabled": True, "mode": "enforce"},
			"ips": {"enabled": True, "mode": "detect"},
			"antivirus": {"enabled": True, "mode": "detect"},
			"host_security": {"enabled": True, "mode": "enforce"},
		}
		self.store.ensure_default_controls(self.default_controls)

	def _load_test_suites(self) -> Dict[str, List[TestCase]]:
		return {
			"layer3": [
				TestCase(
					id="L3-ACL-001",
					name="Invalid Source Segment Probe",
					severity="Medium",
					expected_block=True,
					vector="network",
					indicators=["SRC_SEGMENT_UNTRUSTED", "TTL_ANOMALY"],
					controls=["acl", "firewall"],
				),
				TestCase(
					id="L3-FW-002",
					name="Excessive ICMP Echo Pattern",
					severity="High",
					expected_block=True,
					vector="network",
					indicators=["ICMP_RATE_TEST"],
					controls=["firewall", "ips"],
				),
			],
			"layer4": [
				TestCase(
					id="L4-FW-003",
					name="Unexpected Port Access Attempt",
					severity="High",
					expected_block=True,
					vector="transport",
					indicators=["PORT_23_TEST", "PORT_445_TEST"],
					controls=["acl", "firewall"],
				),
				TestCase(
					id="L4-IPS-004",
					name="Connection Burst Pattern",
					severity="Medium",
					expected_block=False,
					vector="transport",
					indicators=["SYN_BURST_TEST"],
					controls=["ips"],
				),
			],
			"layer7": [
				TestCase(
					id="L7-WAF-005",
					name="SQLi Detection Probe",
					severity="High",
					expected_block=True,
					vector="application",
					indicators=["SQLI_TEST_TOKEN"],
					controls=["waf"],
				),
				TestCase(
					id="L7-WAF-006",
					name="XSS Detection Probe",
					severity="High",
					expected_block=True,
					vector="application",
					indicators=["XSS_TEST_TOKEN"],
					controls=["waf"],
				),
				TestCase(
					id="L7-HST-007",
					name="Path Traversal Indicator Probe",
					severity="Medium",
					expected_block=True,
					vector="application",
					indicators=["TRAVERSAL_TEST_TOKEN"],
					controls=["waf", "host_security"],
				),
			],
			"owasp": [
				TestCase(
					id="OWASP-A03-008",
					name="Injection Control Validation",
					severity="High",
					expected_block=True,
					vector="application",
					indicators=["SQLI_TEST_TOKEN", "CMD_INJECTION_TEST_TOKEN"],
					controls=["waf", "ips"],
				),
				TestCase(
					id="OWASP-A05-009",
					name="Security Misconfiguration Policy Check",
					severity="Medium",
					expected_block=False,
					vector="configuration",
					indicators=["HEADER_HARDENING_TEST", "TLS_POLICY_TEST"],
					controls=["host_security"],
				),
			],
			"malware": [
				TestCase(
					id="MW-AV-010",
					name="EICAR String Detection Test",
					severity="Critical",
					expected_block=True,
					vector="file",
					indicators=["EICAR_TEST_STRING"],
					controls=["antivirus", "host_security"],
				),
				TestCase(
					id="MW-IPS-011",
					name="Suspicious Script Pattern Detection",
					severity="High",
					expected_block=True,
					vector="file",
					indicators=["SCRIPT_DROPPER_TEST_PATTERN"],
					controls=["antivirus", "ips"],
				),
			],
		}

	def _evaluate_controls(self, controls: List[str], expected_block: bool) -> Dict[str, Any]:
		state = self.store.get_controls()
		enforced = [c for c in controls if state.get(c, {}).get("enabled") and state.get(c, {}).get("mode") == "enforce"]
		detect_only = [c for c in controls if state.get(c, {}).get("enabled") and state.get(c, {}).get("mode") == "detect"]

		blocked = bool(enforced) if expected_block else False
		detected = bool(enforced or detect_only)
		decision = "blocked" if blocked else "allowed"

		return {
			"decision": decision,
			"detected": detected,
			"enforced_by": enforced,
			"detected_by": detect_only,
		}

	def execute_suite(self, suite_name: str, source_vm: str = "attacker-vm", log_events: bool = True) -> Dict[str, Any]:
		tests = self.test_suites.get(suite_name, [])
		result_tests: List[Dict[str, Any]] = []

		for test in tests:
			eval_result = self._evaluate_controls(test.controls, test.expected_block)
			entry = {
				**test.to_dict(),
				"result": eval_result,
				"status": "pass" if ((test.expected_block and eval_result["decision"] == "blocked") or (not test.expected_block)) else "review",
			}
			result_tests.append(entry)
			if log_events:
				self.store.log_event(
					event_type="suite_test",
					source_vm=source_vm,
					details={"suite": suite_name, "test": entry},
				)

		return {
			"type": suite_name,
			"timestamp": datetime.now(timezone.utc).isoformat(),
			"tests": result_tests,
			"total": len(result_tests),
			"blocked": sum(1 for t in result_tests if t["result"]["decision"] == "blocked"),
			"detected": sum(1 for t in result_tests if t["result"]["detected"]),
		}

	def full_report(self) -> Dict[str, Any]:
		suites = []
		for suite_name in ["layer3", "layer4", "layer7", "owasp", "malware"]:
			suites.append(self.execute_suite(suite_name, source_vm="report-engine", log_events=False))
		return {
			"generated_at": datetime.now(timezone.utc).isoformat(),
			"controls": self.store.get_controls(),
			"total_tests": sum(s["total"] for s in suites),
			"total_blocked": sum(s["blocked"] for s in suites),
			"total_detected": sum(s["detected"] for s in suites),
			"test_suites": suites,
		}

	def evaluate_firewall_acl(self, payload: Dict[str, Any]) -> Dict[str, Any]:
		source_ip = str(payload.get("source_ip", "0.0.0.0"))
		destination_port = int(payload.get("destination_port", 80))
		protocol = str(payload.get("protocol", "tcp")).lower()

		blocked_ports = {23, 445, 3389}
		untrusted_sources = ("10.250.", "172.31.250.")

		indicators = []
		if destination_port in blocked_ports:
			indicators.append("BLOCKED_PORT_POLICY")
		if source_ip.startswith(untrusted_sources):
			indicators.append("SOURCE_NOT_ALLOWED")
		if protocol not in {"tcp", "udp", "icmp", "http", "https"}:
			indicators.append("PROTOCOL_POLICY")

		simulated = self._evaluate_controls(["acl", "firewall"], expected_block=bool(indicators))
		details = {
			"source_ip": source_ip,
			"destination_port": destination_port,
			"protocol": protocol,
			"indicators": indicators,
			"decision": simulated["decision"],
			"detected": simulated["detected"],
			"enforced_by": simulated["enforced_by"],
		}
		self.store.log_event("firewall_acl_eval", details, source_vm=str(payload.get("source_vm", "attacker-vm")))
		return details

	def evaluate_waf(self, payload: Dict[str, Any]) -> Dict[str, Any]:
		path = str(payload.get("path", "/"))
		query = str(payload.get("query", ""))
		body = str(payload.get("body", ""))
		merged = f"{path} {query} {body}".lower()

		indicators = []
		if "sqli_test_token" in merged or "' or 1=1" in merged:
			indicators.append("SQLI_PATTERN")
		if "xss_test_token" in merged or "<script" in merged:
			indicators.append("XSS_PATTERN")
		if "traversal_test_token" in merged or "../" in merged:
			indicators.append("TRAVERSAL_PATTERN")

		simulated = self._evaluate_controls(["waf", "ips"], expected_block=bool(indicators))
		details = {
			"path": path,
			"indicators": indicators,
			"decision": simulated["decision"],
			"detected": simulated["detected"],
			"enforced_by": simulated["enforced_by"],
		}
		self.store.log_event("waf_eval", details, source_vm=str(payload.get("source_vm", "attacker-vm")))
		return details

	def scan_uploaded_content(self, payload: Dict[str, Any]) -> Dict[str, Any]:
		filename = str(payload.get("filename", "sample.bin"))
		b64 = payload.get("content_base64", "")
		source_vm = str(payload.get("source_vm", "attacker-vm"))

		try:
			raw = base64.b64decode(b64, validate=True)
		except Exception:
			raise ValueError("Invalid base64 payload")

		text_sample = raw.decode("utf-8", errors="ignore")
		sha256_hash = hashlib.sha256(raw).hexdigest()
		indicators = []
		if "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" in text_sample:
			indicators.append("EICAR_TEST_STRING")
		if "SCRIPT_DROPPER_TEST_PATTERN" in text_sample:
			indicators.append("SCRIPT_DROPPER_TEST_PATTERN")

		simulated = self._evaluate_controls(["antivirus", "host_security", "ips"], expected_block=bool(indicators))

		details = {
			"filename": filename,
			"sha256": sha256_hash,
			"size_bytes": len(raw),
			"indicators": indicators,
			"decision": simulated["decision"],
			"detected": simulated["detected"],
			"enforced_by": simulated["enforced_by"],
		}
		self.store.log_event("file_scan", details, source_vm=source_vm)
		return details

	def vuln_sqli(self, query: str, source_vm: str) -> Dict[str, Any]:
		self.store.log_event("vuln_sqli", {"query": query}, source_vm=source_vm)
		q = query.lower()
		dump = ("1=1" in q) or ("union" in q) or ("' or '" in q) or ("or '1'='1" in q)
		return {
			"endpoint": "/vuln/sqli",
			"query": query,
			"rows_returned": len(_SIMULATED_DB) if dump else 1,
			"data": _SIMULATED_DB if dump else _SIMULATED_DB[:1],
		}

	def vuln_xss(self, user_input: str, source_vm: str) -> str:
		self.store.log_event("vuln_xss", {"input": user_input[:500]}, source_vm=source_vm)
		# Returns a real HTML page reflecting raw input.
		# A real WAF/browser will intercept or execute <script> tags unmodified.
		return (
			"<!DOCTYPE html><html><head><title>Search Results</title></head><body>"
			"<h2>Results for: " + user_input + "</h2>"
			"<p>Showing items matching your query.</p>"
			"</body></html>"
		)

	def vuln_traversal(self, file_path: str, source_vm: str) -> Dict[str, Any]:
		self.store.log_event("vuln_traversal", {"path": file_path}, source_vm=source_vm)
		norm = file_path.replace("../", "/").replace("..\\", "/")
		norm = norm.replace("%2e%2e%2f", "/").replace("%2e%2e/", "/")
		if not norm.startswith("/"):
			norm = "/" + norm
		content = next(
			(v for k, v in _SIMULATED_FILES.items() if norm.endswith(k) or norm == k),
			None,
		)
		return {
			"endpoint": "/vuln/traversal",
			"requested": file_path,
			"resolved": norm,
			"found": content is not None,
			"content": content if content is not None else f"{norm}: No such file or directory",
		}

	def vuln_exec(self, cmd: str, source_vm: str) -> Dict[str, Any]:
		self.store.log_event("vuln_exec", {"cmd": cmd}, source_vm=source_vm)
		clean = cmd.strip().rstrip(";|&")
		return {
			"endpoint": "/vuln/exec",
			"command": cmd,
			"exit_code": 0,
			"stdout": _SIMULATED_CMD.get(clean, f"bash: {clean}: command not found"),
			"stderr": "",
		}

	def vuln_auth(self, username: str, password: str, source_vm: str) -> Dict[str, Any]:
		self.store.log_event("vuln_auth", {"username": username}, source_vm=source_vm)
		# Always succeeds – simulates auth bypass / broken authentication.
		return {
			"endpoint": "/vuln/auth",
			"authenticated": True,
			"username": username,
			"role": "admin",
			"session_token": "eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ.",
			"message": "Login successful",
		}

	def vuln_info(self, req_headers: Dict[str, str], source_vm: str) -> Dict[str, Any]:
		self.store.log_event("vuln_info", {}, source_vm=source_vm)
		return {
			"endpoint": "/vuln/info",
			"server": "Apache/2.4.51 (CentOS)",
			"framework": "CorpApp/3.2.1",
			"environment": "production",
			"debug_mode": True,
			"db_host": "db-prod-01.corp.local:5432",
			"internal_ip": "10.0.1.50",
			"config_path": "/app/config.yaml",
			"log_path": "/var/log/appserver/app.log",
			"request_headers": req_headers,
		}

	def vuln_ssrf(self, url: str, source_vm: str) -> Dict[str, Any]:
		self.store.log_event("vuln_ssrf", {"url": url}, source_vm=source_vm)
		body = _SIMULATED_SSRF.get(url.rstrip("/"), f"Connected to {url} — 200 OK")
		return {
			"endpoint": "/vuln/ssrf",
			"target_url": url,
			"status_code": 200,
			"response_body": body,
		}

	def vuln_upload(self, filename: str, content_b64: str, source_vm: str) -> Dict[str, Any]:
		try:
			raw = base64.b64decode(content_b64, validate=True)
		except Exception:
			raise ValueError("Invalid base64")
		sha256 = hashlib.sha256(raw).hexdigest()
		self.store.log_event("vuln_upload", {"filename": filename, "sha256": sha256, "size": len(raw)}, source_vm=source_vm)
		return {
			"endpoint": "/vuln/upload",
			"filename": filename,
			"sha256": sha256,
			"size_bytes": len(raw),
			"stored_path": f"/var/www/html/uploads/{filename}",
			"accessible_url": f"/uploads/{filename}",
			"message": "File uploaded successfully. No AV scan performed.",
		}


class CyberRangeHandler(BaseHTTPRequestHandler):
	server_version = "CyberRange/1.0"

	def _json_response(self, code: int, payload: Dict[str, Any]) -> None:
		body = json.dumps(payload, indent=2).encode("utf-8")
		self.send_response(code)
		self.send_header("Content-Type", "application/json")
		self.send_header("Content-Length", str(len(body)))
		self.send_header("Cache-Control", "no-store")
		self.end_headers()
		self.wfile.write(body)

	def _read_json(self) -> Dict[str, Any]:
		length = int(self.headers.get("Content-Length", "0"))
		raw = self.rfile.read(length) if length else b"{}"
		if not raw:
			return {}
		return json.loads(raw.decode("utf-8"))

	def _text_response(self, code: int, body_text: str, content_type: str = "text/plain; charset=utf-8") -> None:
		body = body_text.encode("utf-8")
		self.send_response(code)
		self.send_header("Content-Type", content_type)
		self.send_header("Content-Length", str(len(body)))
		self.send_header("Cache-Control", "no-store")
		self.end_headers()
		self.wfile.write(body)

	def _serve_static_path(self, path: str) -> bool:
		target_rel = "index.html" if path in {"/", ""} else path.lstrip("/")
		target_rel = unquote(target_rel)
		if ".." in Path(target_rel).parts:
			self._json_response(HTTPStatus.BAD_REQUEST, {"error": "Invalid path"})
			return True

		target = (STATIC_ROOT / target_rel).resolve()
		if STATIC_ROOT.resolve() not in target.parents and target != STATIC_ROOT.resolve():
			self._json_response(HTTPStatus.BAD_REQUEST, {"error": "Invalid path"})
			return True

		if not target.exists() or not target.is_file():
			return False

		content = target.read_bytes()
		suffix = target.suffix.lower()
		mime = _MIME_MAP.get(suffix) or mimetypes.guess_type(str(target))[0] or "application/octet-stream"
		self.send_response(HTTPStatus.OK)
		self.send_header("Content-Type", mime)
		self.send_header("Content-Length", str(len(content)))
		self.end_headers()
		self.wfile.write(content)
		return True

	@property
	def engine(self) -> CyberRangeEngine:
		return self.server.engine  # type: ignore[attr-defined]

	def log_message(self, fmt: str, *args: Any) -> None:
		now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
		print(f"[{now}] {self.address_string()} - {fmt % args}")

	def do_GET(self) -> None:
		parsed = urlparse(self.path)
		path = parsed.path

		if not (path.startswith("/api/") or path.startswith("/demo/") or path.startswith("/vuln/")):
			if self._serve_static_path(path):
				return

		if path == "/api/health":
			self._json_response(
				HTTPStatus.OK,
				{
					"service": "cyber-range",
					"status": "ok",
					"timestamp": datetime.now(timezone.utc).isoformat(),
				},
			)
			return

		if path == "/api/controls":
			self._json_response(HTTPStatus.OK, {"controls": self.engine.store.get_controls()})
			return

		if path == "/api/report":
			self._json_response(HTTPStatus.OK, self.engine.full_report())
			return

		if path == "/api/events":
			params = parse_qs(parsed.query)
			limit = int(params.get("limit", ["50"])[0])
			self._json_response(HTTPStatus.OK, {"events": self.engine.store.recent_events(limit=max(1, min(limit, 500)))})
			return

		if path == "/vuln/sqli":
			params = parse_qs(parsed.query)
			q = params.get("q", ["1 OR 1=1"])[0]
			svm = params.get("source_vm", ["attacker-vm"])[0]
			self._json_response(HTTPStatus.OK, self.engine.vuln_sqli(q, svm))
			return

		if path == "/vuln/xss":
			params = parse_qs(parsed.query)
			inp = params.get("input", ['<script>alert(1)</script>'])[0]
			svm = params.get("source_vm", ["attacker-vm"])[0]
			html = self.engine.vuln_xss(inp, svm)
			body = html.encode("utf-8")
			self.send_response(HTTPStatus.OK)
			self.send_header("Content-Type", "text/html; charset=utf-8")
			self.send_header("Content-Length", str(len(body)))
			self.end_headers()
			self.wfile.write(body)
			return

		if path == "/vuln/traversal":
			params = parse_qs(parsed.query)
			fp = params.get("path", ["../../../../etc/passwd"])[0]
			svm = params.get("source_vm", ["attacker-vm"])[0]
			self._json_response(HTTPStatus.OK, self.engine.vuln_traversal(fp, svm))
			return

		if path == "/vuln/info":
			svm = parse_qs(parsed.query).get("source_vm", ["attacker-vm"])[0]
			h = dict(self.headers)
			self._json_response(HTTPStatus.OK, self.engine.vuln_info(h, svm))
			return

		self._json_response(HTTPStatus.NOT_FOUND, {"error": "Not found"})

	def do_POST(self) -> None:
		parsed = urlparse(self.path)
		path = parsed.path

		try:
			payload = self._read_json()
		except json.JSONDecodeError:
			self._json_response(HTTPStatus.BAD_REQUEST, {"error": "Invalid JSON"})
			return

		if path == "/api/execute":
			test_type = str(payload.get("test_type", "")).lower().strip()
			source_vm = str(payload.get("source_vm", "attacker-vm"))
			if test_type not in self.engine.test_suites:
				self._json_response(HTTPStatus.BAD_REQUEST, {"error": "Unknown test_type"})
				return
			suite = self.engine.execute_suite(test_type, source_vm=source_vm)
			self._json_response(HTTPStatus.OK, {"ok": True, "data": suite})
			return

		if path == "/api/control/update":
			name = str(payload.get("control", ""))
			enabled = bool(payload.get("enabled", True))
			mode = str(payload.get("mode", "enforce")).lower()
			if mode not in {"detect", "enforce", "disabled"}:
				self._json_response(HTTPStatus.BAD_REQUEST, {"error": "mode must be detect|enforce|disabled"})
				return
			if mode == "disabled":
				enabled = False
				mode = "detect"
			ok = self.engine.store.update_control(name, enabled=enabled, mode=mode)
			if not ok:
				self._json_response(HTTPStatus.BAD_REQUEST, {"error": "Unknown control"})
				return
			self.engine.store.log_event("control_update", {"control": name, "enabled": enabled, "mode": mode}, source_vm="defender-vm")
			self._json_response(HTTPStatus.OK, {"ok": True, "controls": self.engine.store.get_controls()})
			return

		if path == "/api/firewall/evaluate":
			result = self.engine.evaluate_firewall_acl(payload)
			self._json_response(HTTPStatus.OK, {"ok": True, "result": result})
			return

		if path == "/api/waf/evaluate":
			result = self.engine.evaluate_waf(payload)
			self._json_response(HTTPStatus.OK, {"ok": True, "result": result})
			return

		if path == "/api/upload-json":
			try:
				result = self.engine.scan_uploaded_content(payload)
			except ValueError as exc:
				self._json_response(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
				return
			self._json_response(HTTPStatus.OK, {"ok": True, "result": result})
			return

		if path == "/vuln/sqli":
			q = str(payload.get("q", "1 OR 1=1"))
			svm = str(payload.get("source_vm", "attacker-vm"))
			self._json_response(HTTPStatus.OK, self.engine.vuln_sqli(q, svm))
			return

		if path == "/vuln/xss":
			inp = str(payload.get("input", "<script>alert(1)</script>"))
			svm = str(payload.get("source_vm", "attacker-vm"))
			html = self.engine.vuln_xss(inp, svm)
			body = html.encode("utf-8")
			self.send_response(HTTPStatus.OK)
			self.send_header("Content-Type", "text/html; charset=utf-8")
			self.send_header("Content-Length", str(len(body)))
			self.end_headers()
			self.wfile.write(body)
			return

		if path == "/vuln/traversal":
			fp = str(payload.get("path", "../../../../etc/passwd"))
			svm = str(payload.get("source_vm", "attacker-vm"))
			self._json_response(HTTPStatus.OK, self.engine.vuln_traversal(fp, svm))
			return

		if path == "/vuln/exec":
			cmd = str(payload.get("cmd", "id"))
			svm = str(payload.get("source_vm", "attacker-vm"))
			self._json_response(HTTPStatus.OK, self.engine.vuln_exec(cmd, svm))
			return

		if path == "/vuln/auth":
			user = str(payload.get("username", "admin"))
			pw   = str(payload.get("password", ""))
			svm  = str(payload.get("source_vm", "attacker-vm"))
			self._json_response(HTTPStatus.OK, self.engine.vuln_auth(user, pw, svm))
			return

		if path == "/vuln/ssrf":
			url = str(payload.get("url", "http://169.254.169.254/latest/meta-data/"))
			svm = str(payload.get("source_vm", "attacker-vm"))
			self._json_response(HTTPStatus.OK, self.engine.vuln_ssrf(url, svm))
			return

		if path == "/vuln/upload":
			try:
				res = self.engine.vuln_upload(
					str(payload.get("filename", "file.bin")),
					str(payload.get("content_base64", "")),
					str(payload.get("source_vm", "attacker-vm")),
				)
			except ValueError as exc:
				self._json_response(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
				return
			self._json_response(HTTPStatus.OK, res)
			return

		self._json_response(HTTPStatus.NOT_FOUND, {"error": "Not found"})


def parse_args() -> argparse.Namespace:
	parser = argparse.ArgumentParser(
		description="Defensive cyber range service for firewall/WAF/IPS/AV validation"
	)
	parser.add_argument("--host", default="0.0.0.0", help="Bind host (default: 0.0.0.0)")
	parser.add_argument("--port", type=int, default=8080, help="Bind port (default: 8080)")
	return parser.parse_args()


def main() -> None:
	args = parse_args()
	store = CyberRangeStore(DB_PATH)
	engine = CyberRangeEngine(store)

	class CyberRangeHTTPServer(ThreadingHTTPServer):
		def __init__(self, server_address: Any, handler_class: Any) -> None:
			super().__init__(server_address, handler_class)
			self.engine = engine

	server = CyberRangeHTTPServer((args.host, args.port), CyberRangeHandler)
	print(f"Cyber range listening on {args.host}:{args.port}")
	print("Use GET /api/health for health checks")
	print("Use POST /api/execute with test_type in [layer3, layer4, layer7, owasp, malware]")

	try:
		server.serve_forever(poll_interval=0.5)
	except KeyboardInterrupt:
		print("\nShutting down cyber range service")
	finally:
		server.server_close()


if __name__ == "__main__":
	main()
