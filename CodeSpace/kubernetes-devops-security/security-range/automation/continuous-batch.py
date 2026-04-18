#!/usr/bin/env python3
"""Run repeated batches for stability and trend demonstrations."""

import argparse
import json
import time
from urllib.request import Request, urlopen


def post(base: str, path: str, payload):
    req = Request(
        base.rstrip("/") + path,
        method="POST",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    with urlopen(req, timeout=15) as resp:
        return json.loads(resp.read().decode("utf-8"))


def main():
    parser = argparse.ArgumentParser(description="Continuous range batch runner")
    parser.add_argument("--target", default="http://127.0.0.1:8080")
    parser.add_argument("--iterations", type=int, default=5)
    parser.add_argument("--sleep", type=float, default=1.5)
    parser.add_argument("--output", default="continuous-batch-report.json")
    args = parser.parse_args()

    history = []
    suites = ["layer3", "layer4", "layer7", "owasp", "malware"]

    for i in range(1, args.iterations + 1):
        row = {"iteration": i, "suites": []}
        for s in suites:
            data = post(args.target, "/api/execute", {"test_type": s, "source_vm": f"attacker-vm-{i}"})
            row["suites"].append({
                "suite": s,
                "blocked": data.get("data", {}).get("blocked", 0),
                "detected": data.get("data", {}).get("detected", 0),
                "total": data.get("data", {}).get("total", 0),
            })
        history.append(row)
        time.sleep(args.sleep)

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump({"iterations": args.iterations, "history": history}, f, indent=2)

    print("Continuous batch complete")
    print(f"Output: {args.output}")


if __name__ == "__main__":
    main()
