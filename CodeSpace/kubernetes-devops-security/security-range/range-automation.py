#!/usr/bin/env python3
"""
Automation runner for the defensive cyber range.

Runs baseline suites, WAF/ACL checks, and file-scan checks to produce a concise report.
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
import time
from dataclasses import dataclass
from typing import Any, Dict, List
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


@dataclass
class StepResult:
    name: str
    ok: bool
    details: Dict[str, Any]


class RangeClient:
    def __init__(self, base_url: str, timeout: int = 15) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def _request(self, method: str, path: str, payload: Dict[str, Any] | None = None) -> Dict[str, Any]:
        data = None
        headers = {"Accept": "application/json"}
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"

        req = Request(
            url=f"{self.base_url}{path}",
            method=method,
            data=data,
            headers=headers,
        )
        try:
            with urlopen(req, timeout=self.timeout) as resp:
                body = resp.read().decode("utf-8")
                return json.loads(body)
        except HTTPError as exc:
            body = exc.read().decode("utf-8", errors="ignore")
            raise RuntimeError(f"HTTP {exc.code} for {path}: {body}") from exc
        except URLError as exc:
            raise RuntimeError(f"Connection error for {path}: {exc}") from exc

    def get_health(self) -> Dict[str, Any]:
        return self._request("GET", "/api/health")

    def execute_suite(self, suite: str, source_vm: str) -> Dict[str, Any]:
        return self._request("POST", "/api/execute", {"test_type": suite, "source_vm": source_vm})

    def evaluate_firewall(self, source_vm: str) -> Dict[str, Any]:
        return self._request(
            "POST",
            "/api/firewall/evaluate",
            {
                "source_vm": source_vm,
                "source_ip": "10.250.1.10",
                "destination_port": 445,
                "protocol": "tcp",
            },
        )

    def evaluate_waf(self, source_vm: str) -> Dict[str, Any]:
        return self._request(
            "POST",
            "/api/waf/evaluate",
            {
                "source_vm": source_vm,
                "path": "/search",
                "query": "q=SQLI_TEST_TOKEN",
                "body": "x=XSS_TEST_TOKEN",
            },
        )

    def upload_eicar_test(self, source_vm: str) -> Dict[str, Any]:
        eicar = (
            b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$"
            b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        )
        return self._request(
            "POST",
            "/api/upload-json",
            {
                "source_vm": source_vm,
                "filename": "eicar-test.com.txt",
                "content_base64": base64.b64encode(eicar).decode("ascii"),
            },
        )

    def update_control(self, control: str, enabled: bool, mode: str) -> Dict[str, Any]:
        return self._request(
            "POST",
            "/api/control/update",
            {"control": control, "enabled": enabled, "mode": mode},
        )

    def get_report(self) -> Dict[str, Any]:
        return self._request("GET", "/api/report")


def run_full_demo(client: RangeClient, attacker_vm: str, defender_vm: str) -> Dict[str, Any]:
    steps: List[StepResult] = []

    health = client.get_health()
    steps.append(StepResult("Health check", health.get("status") == "ok", health))

    for suite in ["layer3", "layer4", "layer7", "owasp", "malware"]:
        data = client.execute_suite(suite, source_vm=attacker_vm)
        ok = bool(data.get("ok", False))
        steps.append(StepResult(f"Suite {suite}", ok, data))

    fw = client.evaluate_firewall(source_vm=attacker_vm)
    steps.append(StepResult("Firewall/ACL simulation", bool(fw.get("ok")), fw))

    waf = client.evaluate_waf(source_vm=attacker_vm)
    steps.append(StepResult("WAF simulation", bool(waf.get("ok")), waf))

    av = client.upload_eicar_test(source_vm=attacker_vm)
    steps.append(StepResult("AV upload simulation", bool(av.get("ok")), av))

    # Simulate defender hardening step and rerun one key suite.
    ctl = client.update_control("ips", enabled=True, mode="enforce")
    steps.append(StepResult("Defender control change (IPS enforce)", bool(ctl.get("ok")), ctl))

    post = client.execute_suite("layer7", source_vm=attacker_vm)
    steps.append(StepResult("Post-change Layer7 suite", bool(post.get("ok")), post))

    report = client.get_report()

    return {
        "timestamp": int(time.time()),
        "attacker_vm": attacker_vm,
        "defender_vm": defender_vm,
        "steps": [
            {"name": s.name, "ok": s.ok, "details": s.details}
            for s in steps
        ],
        "summary": {
            "total_steps": len(steps),
            "passed_steps": sum(1 for s in steps if s.ok),
            "failed_steps": sum(1 for s in steps if not s.ok),
        },
        "final_report": report,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Cyber range automation runner")
    parser.add_argument("--target", default="http://127.0.0.1:8080", help="Cyber range base URL")
    parser.add_argument("--attacker-vm", default="attacker-vm", help="Label for attacker VM")
    parser.add_argument("--defender-vm", default="defender-vm", help="Label for defender VM")
    parser.add_argument("--output", default="automation-report.json", help="Output JSON report path")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    client = RangeClient(args.target)

    try:
        report = run_full_demo(client, attacker_vm=args.attacker_vm, defender_vm=args.defender_vm)
    except Exception as exc:
        print(f"Automation failed: {exc}")
        return 1

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print("Automation completed")
    print(f"Output report: {args.output}")
    print(
        "Summary: "
        f"{report['summary']['passed_steps']}/{report['summary']['total_steps']} steps passed"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
