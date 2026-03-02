"""
SwiftAudit v10 - tests/diagnose_network.py
============================================
Run this BEFORE running test_api.py to find exactly which
network call is hanging on your Windows machine.

Usage:
  python tests/diagnose_network.py

Each step has a hard 15-second timeout. You will see exactly
which call passes, which hangs, and which times out.
"""

import os
import sys
import socket
import time
import threading
import requests
from dotenv import load_dotenv

load_dotenv()

TOKEN = os.getenv("GITHUB_TOKEN", "")
REPO  = "https://github.com/stamparm/DSVW"

print("=" * 60)
print("  SwiftAudit v10 — Network Diagnostics")
print("=" * 60)
print()


def run_with_timeout(label, fn, timeout=15):
    """Run fn() with a hard timeout. Print pass/fail/timeout."""
    result_box = [None]
    error_box  = [None]

    def _target():
        try:
            result_box[0] = fn()
        except Exception as e:
            error_box[0] = e

    t = threading.Thread(target=_target, daemon=True)
    t0 = time.time()
    t.start()
    t.join(timeout=timeout)
    elapsed = time.time() - t0

    if t.is_alive():
        print(f"  ⏰ TIMEOUT ({elapsed:.0f}s) — {label}")
        print(f"     → This is the hanging call. Fix: check firewall/proxy/Defender.")
        return False
    elif error_box[0]:
        print(f"  ❌ ERROR ({elapsed:.1f}s) — {label}")
        print(f"     → {error_box[0]}")
        return False
    else:
        print(f"  ✅ OK ({elapsed:.1f}s) — {label}")
        if result_box[0]:
            print(f"     → {str(result_box[0])[:120]}")
        return True


# ── Test 1: Raw TCP connect to api.github.com:443 ─────────────
print("Step 1: Raw TCP connect to api.github.com:443")
def _tcp():
    s = socket.create_connection(("api.github.com", 443), timeout=10)
    s.close()
    return "TCP connect OK"
ok1 = run_with_timeout("TCP connect to api.github.com:443", _tcp, timeout=12)
print()

# ── Test 2: HTTPS GET with NO auth headers ────────────────────
print("Step 2: HTTPS GET /rate_limit (no auth headers)")
def _no_auth():
    r = requests.get(
        "https://api.github.com/rate_limit",
        timeout=(8, 10),
        headers={"User-Agent": "SwiftAudit-test/1.0"},
    )
    return f"HTTP {r.status_code} | remaining={r.json().get('rate',{}).get('remaining','?')}"
ok2 = run_with_timeout("HTTPS GET unauthenticated", _no_auth, timeout=12)
print()

# ── Test 3: HTTPS GET WITH auth token ─────────────────────────
print("Step 3: HTTPS GET /rate_limit (with GITHUB_TOKEN)")
def _with_auth():
    headers = {
        "User-Agent": "SwiftAudit-test/1.0",
        "Accept": "application/vnd.github+json",
    }
    if TOKEN:
        headers["Authorization"] = f"Bearer {TOKEN}"
    r = requests.get(
        "https://api.github.com/rate_limit",
        timeout=(8, 10),
        headers=headers,
    )
    return f"HTTP {r.status_code} | remaining={r.json().get('rate',{}).get('remaining','?')}"
ok3 = run_with_timeout("HTTPS GET authenticated", _with_auth, timeout=12)
print()

# ── Test 4: fetch repo metadata ────────────────────────────────
print("Step 4: GET /repos/stamparm/DSVW (repo metadata)")
def _metadata():
    headers = {"User-Agent": "SwiftAudit-test/1.0", "Accept": "application/vnd.github+json"}
    if TOKEN:
        headers["Authorization"] = f"Bearer {TOKEN}"
    r = requests.get(
        "https://api.github.com/repos/stamparm/DSVW",
        timeout=(8, 10),
        headers=headers,
    )
    d = r.json()
    return f"HTTP {r.status_code} | {d.get('full_name','?')} | branch={d.get('default_branch','?')}"
ok4 = run_with_timeout("GET repo metadata", _metadata, timeout=12)
print()

# ── Test 5: fetch branch SHA ───────────────────────────────────
print("Step 5: GET branch SHA (branches/master)")
def _branch():
    headers = {"User-Agent": "SwiftAudit-test/1.0", "Accept": "application/vnd.github+json"}
    if TOKEN:
        headers["Authorization"] = f"Bearer {TOKEN}"
    r = requests.get(
        "https://api.github.com/repos/stamparm/DSVW/branches/master",
        timeout=(8, 10),
        headers=headers,
    )
    sha = r.json().get("commit", {}).get("sha", "?")[:12]
    return f"HTTP {r.status_code} | SHA={sha}"
ok5 = run_with_timeout("GET branch SHA", _branch, timeout=12)
print()

# ── Test 6: fetch file tree ────────────────────────────────────
print("Step 6: GET file tree (git/trees?recursive=1)")
def _tree():
    headers = {"User-Agent": "SwiftAudit-test/1.0", "Accept": "application/vnd.github+json"}
    if TOKEN:
        headers["Authorization"] = f"Bearer {TOKEN}"
    r_branch = requests.get(
        "https://api.github.com/repos/stamparm/DSVW/branches/master",
        timeout=(8, 10), headers=headers,
    )
    sha = r_branch.json()["commit"]["sha"]
    r_tree = requests.get(
        f"https://api.github.com/repos/stamparm/DSVW/git/trees/{sha}?recursive=1",
        timeout=(8, 25), headers=headers,
    )
    blobs = [i for i in r_tree.json().get("tree", []) if i.get("type") == "blob"]
    return f"HTTP {r_tree.status_code} | {len(blobs)} files"
ok6 = run_with_timeout("GET file tree", _tree, timeout=30)
print()

# ── Summary ───────────────────────────────────────────────────
print("=" * 60)
print("  Summary")
print("=" * 60)
steps = [
    (ok1, "TCP connect"),
    (ok2, "HTTPS unauthenticated"),
    (ok3, "HTTPS authenticated"),
    (ok4, "Repo metadata"),
    (ok5, "Branch SHA"),
    (ok6, "File tree"),
]
all_ok = True
for ok, label in steps:
    icon  = "✅" if ok else "❌/⏰"
    print(f"  {icon}  {label}")
    if not ok:
        all_ok = False

print()
if all_ok:
    print("  ✅ All network calls work. Problem is elsewhere.")
    print("  → Check the server terminal for logs after [GRAPH:navigator]")
    print("  → Look for any Python exception or import error")
else:
    first_fail = next((label for ok, label in steps if not ok), None)
    print(f"  ❌ First failure: {first_fail}")
    print()
    print("  Possible fixes:")
    print("  1. Windows Defender / Firewall blocking Python HTTPS:")
    print("     → Run: python -m pip install requests --upgrade")
    print("     → Or add Python.exe to Windows Defender exclusions")
    print("  2. Corporate proxy:")
    print("     → Set in .env: HTTPS_PROXY=http://your-proxy:port")
    print("  3. VPN interfering with HTTPS:")
    print("     → Disconnect VPN and retry")
    print("  4. GitHub token expired:")
    print("     → Run: gh auth login  OR generate new token at github.com/settings/tokens")
print()
