"""
SwiftAudit v10 - tests/test_api.py
=====================================
Integration test — polls REST status endpoint every 10s.
Also tests the SSE stream endpoint to confirm events are flowing.

USAGE:
  python tests/test_api.py

EXPECTS:
  - Server running at http://127.0.0.1:5000
  - GITHUB_TOKEN and SNYK_TOKEN set in .env

ALL IMPORTS VERIFIED:
  os, sys, time, json, threading — stdlib
  requests — pip install requests
  dotenv.load_dotenv — pip install python-dotenv
"""

import os
import sys
import time
import json
import threading

import requests
from dotenv import load_dotenv

load_dotenv()

SERVER   = os.getenv("SWIFTAUDIT_URL", "http://127.0.0.1:5000/api/v1")
TARGET   = os.getenv("SCAN_TARGET",    "https://github.com/stamparm/DSVW")
POLL_S   = 10
MAX_WAIT = 30 * 60  # 30 minutes max

BANNER = "=" * 65


def hdr(title):
    print(f"\n{BANNER}")
    print(f"  {title}")
    print(BANNER)


def check(label, val, expected=None):
    ok = "✅" if (expected is None or val == expected) else "❌"
    print(f"  {ok} {label:<30}: {val}")
    return ok == "✅"


# ─── Health check ─────────────────────────────────────────────
hdr("SwiftAudit v10 — Integration Test")
print(f"  Target        : {TARGET}")
print(f"  Server        : {SERVER}")
print(f"  Scanners      : Snyk Code + Trivy + Snyk IAC + Snyk Container")
print(f"  Poll interval : {POLL_S}s | Max wait: {MAX_WAIT//60}min")
print(BANNER)

hdr("Health Check")
try:
    r = requests.get(f"{SERVER}/health", timeout=10)
    d = r.json()
    check("Status",   r.status_code, 200)
    check("Service",  d.get("service", ""))
    check("Model",    d.get("model", ""))
    check("Port",     d.get("port", 0))
    check("GitHub",   d.get("github", ""))
    check("Snyk",     d.get("snyk", ""))
    check("MCP",      d.get("mcp", True), False)
    check("SSE",      d.get("sse", False), True)
    check("Parallel", d.get("parallel", False), True)
    check("Version",  d.get("version", ""), "10.0")
except Exception as e:
    print(f"  ❌ Health check failed: {e}")
    sys.exit(1)

# ─── Create scan ──────────────────────────────────────────────
hdr(f"Creating Scan: {TARGET}")
try:
    r   = requests.post(f"{SERVER}/scan", json={"repo_url": TARGET}, timeout=15)
    d   = r.json()
    sid = d.get("scan_id", "")
    check("HTTP",       r.status_code, 202)
    check("scan_id",    bool(sid), True)
    check("stream_url", d.get("stream_url", ""))
    print(f"  Scan ID: {sid}")
except Exception as e:
    print(f"  ❌ Create scan failed: {e}")
    sys.exit(1)

# ─── SSE event counter (background thread) ────────────────────
sse_counts = {"progress": 0, "finding": 0, "log": 0, "complete": 0, "error": 0}
sse_lock   = threading.Lock()

def _sse_listener():
    try:
        stream_url = f"http://127.0.0.1:5000/api/v1/scan/{sid}/stream"
        with requests.get(stream_url, stream=True, timeout=MAX_WAIT) as resp:
            for line in resp.iter_lines(decode_unicode=True):
                if not line:
                    continue
                if line.startswith("event:"):
                    etype = line.split(":", 1)[1].strip()
                    with sse_lock:
                        if etype in sse_counts:
                            sse_counts[etype] += 1
                    if etype in ("complete", "error"):
                        break
    except Exception as e:
        print(f"\n  [SSE thread] {e}")

sse_thread = threading.Thread(target=_sse_listener, daemon=True)
sse_thread.start()
print(f"\n  ℹ️  SSE listener started → /api/v1/scan/{sid}/stream")

# ─── Poll status ──────────────────────────────────────────────
hdr("Polling Scan Status")
print(f"  Polling every {POLL_S}s | timeout: 60s/request")

start   = time.time()
polls   = 0
final_d = None

while time.time() - start < MAX_WAIT:
    time.sleep(POLL_S)
    polls += 1
    try:
        r = requests.get(f"{SERVER}/scan/{sid}/status", timeout=60)
        d = r.json()
    except Exception as e:
        print(f"  [{polls:3d}] ⚠️  Poll failed: {e}")
        continue

    status   = d.get("status", "UNKNOWN")
    progress = d.get("progress", 0)
    step     = (d.get("current_step") or "")[:60]
    findings = d.get("findings_count", 0)

    with sse_lock:
        sse_p = sse_counts["progress"]
        sse_f = sse_counts["finding"]

    print(
        f"  [{polls:3d}] Status={status:<10} | {progress:3d}% | "
        f"Findings={findings} | SSE(p={sse_p},f={sse_f}) | {step}"
    )

    if status in ("COMPLETED", "FAILED", "PARTIAL"):
        final_d = d
        break
else:
    print(f"\n  ⏰ Timed out after {MAX_WAIT//60}min")
    sys.exit(1)

elapsed = time.time() - start
print(f"\n  Total elapsed: {elapsed:.1f}s ({elapsed/60:.1f}min)")

# ─── Full result ──────────────────────────────────────────────
hdr("Fetching Full Result")
try:
    r   = requests.get(f"{SERVER}/scan/{sid}/result", timeout=30)
    res = r.json()
    check("HTTP",          r.status_code, 200)
    check("Status",        res.get("status", ""))
    check("Score",         res.get("overall_risk_score", -1))
    check("Grade",         res.get("risk_grade", ""))
    check("Findings",      res.get("findings_count", 0))
    check("Tool findings", res.get("tool_finding_count", 0))
    check("LLM findings",  res.get("llm_finding_count", 0))
    check("Duration",      round(res.get("scan_duration_seconds", 0), 1))
    meta = res.get("metadata", {})
    check("Repo",          f"{meta.get('owner','')}/{meta.get('repo_name','')}")

    findings = res.get("findings", [])
    if findings:
        print(f"\n  Top 5 findings (by severity):")
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        top5 = sorted(findings, key=lambda x: sev_order.get(x.get("severity","INFO"), 5))[:5]
        for i, f in enumerate(top5, 1):
            print(
                f"    {i}. [{f.get('severity','?'):8s}] "
                f"{f.get('title','')[:50]} "
                f"← {f.get('detection_source','')}"
            )
except Exception as e:
    print(f"  ❌ Result fetch failed: {e}")

# ─── SSE summary ──────────────────────────────────────────────
hdr("SSE Event Summary")
with sse_lock:
    for etype, count in sse_counts.items():
        check(f"SSE '{etype}' events", count)

hdr("Test Complete")
status = res.get("status", "UNKNOWN") if final_d else "UNKNOWN"
print(f"  Status  : {status}")
print(f"  Elapsed : {elapsed:.1f}s")
print(f"  Score   : {res.get('overall_risk_score','?')}/100 Grade={res.get('risk_grade','?')}")
print(f"  Findings: {res.get('findings_count','?')}")
print()
