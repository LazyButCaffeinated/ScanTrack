"""Seed ~10,000 findings, then measure p95 latency of the list endpoint.
Usage: python -m scripts.load_test --url http://localhost:8000 --user admin --password '...'
Report the number you actually measure - don't copy mine.
"""
import argparse
import statistics
import time

import httpx


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://localhost:8000")
    ap.add_argument("--user", required=True)
    ap.add_argument("--password", required=True)
    ap.add_argument("--requests", type=int, default=300)
    a = ap.parse_args()

    c = httpx.Client(base_url=a.url, timeout=30)
    tok = c.post("/api/v1/auth/login", data={"username": a.user, "password": a.password}).json()["access_token"]
    h = {"Authorization": f"Bearer {tok}"}

    sev = ["critical", "high", "medium", "low", "info"]
    for batch in range(2):  # 2 x 5000 = 10,000
        findings = [
            {"asset": f"host-{(batch*5000+i)%400}.lab", "plugin_id": f"P-{batch*5000+i}",
             "title": f"Synthetic finding {batch*5000+i}", "severity": sev[i % 5]}
            for i in range(5000)
        ]
        r = c.post("/api/v1/ingest", json={"scanner": "loadtest", "findings": findings}, headers=h)
        print("seed:", r.json())

    times = []
    for i in range(a.requests):
        t = time.perf_counter()
        c.get("/api/v1/findings", params={"severity": sev[i % 5], "status": "open", "limit": 50}, headers=h).raise_for_status()
        times.append((time.perf_counter() - t) * 1000)
    times.sort()
    print(f"p50={statistics.median(times):.1f}ms  p95={times[int(len(times)*0.95)-1]:.1f}ms  max={times[-1]:.1f}ms")


if __name__ == "__main__":
    main()
