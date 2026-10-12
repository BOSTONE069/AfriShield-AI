#!/usr/bin/env python3
"""Dependency-free concurrent smoke load test for a running AfriShield API."""

from __future__ import annotations

import argparse
import json
import statistics
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed


def send_request(url: str, timeout: float) -> tuple[int, float]:
    payload = json.dumps(
        {
            "input_type": "sms",
            "context": "Kenya",
            "content": "Verify your account at https://kra-refund-verify.com/login",
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        f"{url.rstrip('/')}/api/analyze",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    started = time.perf_counter()
    with urllib.request.urlopen(request, timeout=timeout) as response:
        response.read()
        return response.status, time.perf_counter() - started


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://localhost:8000")
    parser.add_argument("--requests", type=int, default=50)
    parser.add_argument("--concurrency", type=int, default=10)
    parser.add_argument("--timeout", type=float, default=30.0)
    args = parser.parse_args()

    latencies: list[float] = []
    failures: list[str] = []
    started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        futures = [pool.submit(send_request, args.url, args.timeout) for _ in range(args.requests)]
        for future in as_completed(futures):
            try:
                status, latency = future.result()
                if status == 200:
                    latencies.append(latency)
                else:
                    failures.append(f"HTTP {status}")
            except Exception as exc:
                failures.append(str(exc))

    elapsed = time.perf_counter() - started
    if latencies:
        ordered = sorted(latencies)
        p95_index = max(0, int(len(ordered) * 0.95) - 1)
        print(
            json.dumps(
                {
                    "requests": args.requests,
                    "successful": len(latencies),
                    "failed": len(failures),
                    "requests_per_second": round(len(latencies) / elapsed, 2),
                    "latency_mean_seconds": round(statistics.mean(latencies), 3),
                    "latency_p95_seconds": round(ordered[p95_index], 3),
                },
                indent=2,
            )
        )
    if failures:
        print(json.dumps({"sample_failures": failures[:5]}, indent=2))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
