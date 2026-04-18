#!/usr/bin/env python3
"""Compare baseline versus hardened policy posture for customer PoC."""

from __future__ import annotations

import argparse
import json
from urllib.error import HTTPError
from urllib.request import Request, urlopen


CONTROLS = ["acl", "firewall", "waf", "ips", "antivirus", "host_security"]


def call(base: str, path: str, method: str = "GET", payload=None):
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
        return exc.code, json.loads(exc.read().decode("utf-8", errors="ignore"))


def set_mode(base: str, control: str, mode: str):
    enabled = mode != "disabled"
    effective_mode = "detect" if mode == "disabled" else mode
    return call(base, "/api/control/update", "POST", {"control": control, "enabled": enabled, "mode": effective_mode})


def run_suite_set(base: str, source_vm: str):
    suites = ["layer3", "layer4", "layer7", "owasp", "malware"]
    out = []
    for s in suites:
        _, data = call(base, "/api/execute", "POST", {"test_type": s, "source_vm": source_vm})
        out.append(data)
    return out


def aggregate(suites):
    total = 0
    blocked = 0
    detected = 0
    for item in suites:
        d = item.get("data", {})
        total += int(d.get("total", 0))
        blocked += int(d.get("blocked", 0))
        detected += int(d.get("detected", 0))
    return {"total": total, "blocked": blocked, "detected": detected}


def main():
    parser = argparse.ArgumentParser(description="Policy transition PoC demo")
    parser.add_argument("--target", default="http://127.0.0.1:8080")
    parser.add_argument("--output", default="policy-transition-report.json")
    args = parser.parse_args()

    for c in CONTROLS:
        set_mode(args.target, c, "detect")

    baseline_suites = run_suite_set(args.target, "attacker-vm")
    baseline = aggregate(baseline_suites)

    for c in CONTROLS:
        set_mode(args.target, c, "enforce")

    hardened_suites = run_suite_set(args.target, "attacker-vm")
    hardened = aggregate(hardened_suites)

    report = {
        "baseline_detect": baseline,
        "hardened_enforce": hardened,
        "delta": {
            "blocked_change": hardened["blocked"] - baseline["blocked"],
            "detected_change": hardened["detected"] - baseline["detected"],
        },
    }

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print("Policy transition demo complete")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
