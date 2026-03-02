import json
import queue
import threading
import time
from typing import Dict, List, Optional
from core.logger import get_logger

logger = get_logger("core.events")

# scan_id → list of per-connection queues
_subscribers: Dict[str, List[queue.Queue]] = {}
_sub_lock = threading.Lock()

# Event history for late-joining clients (e.g. page refresh)
_history: Dict[str, List[dict]] = {}
_hist_lock = threading.Lock()
_MAX_HIST = 300


def _fmt(event_type: str, data: dict) -> str:
    """Format SSE message per spec: event:\ndata:\n\n"""
    return f"event: {event_type}\ndata: {json.dumps(data)}\n\n"


def emit(scan_id: str, event_type: str, data: dict) -> None:
    """Push event to all active SSE connections. Thread-safe. Non-blocking."""
    msg = _fmt(event_type, data)
    # Buffer for history
    with _hist_lock:
        if scan_id not in _history:
            _history[scan_id] = []
        _history[scan_id].append({"type": event_type, "data": data})
        if len(_history[scan_id]) > _MAX_HIST:
            _history[scan_id] = _history[scan_id][-_MAX_HIST:]
    # Push to all live queues
    with _sub_lock:
        qs = list(_subscribers.get(scan_id, []))
    dead = []
    for q in qs:
        try:
            q.put_nowait(msg)
        except queue.Full:
            dead.append(q)
    if dead:
        with _sub_lock:
            for q in dead:
                if q in _subscribers.get(scan_id, []):
                    _subscribers[scan_id].remove(q)
    logger.debug(f"[EVENTS] emit {event_type} → scan={scan_id[:8]} ({len(qs)} subs)")


def subscribe(scan_id: str) -> queue.Queue:
    """Create a new subscriber queue for a browser SSE connection."""
    q = queue.Queue(maxsize=500)
    with _sub_lock:
        _subscribers.setdefault(scan_id, []).append(q)
    logger.info(f"[EVENTS] +subscriber scan={scan_id[:8]}")
    return q


def unsubscribe(scan_id: str, q: queue.Queue) -> None:
    with _sub_lock:
        qs = _subscribers.get(scan_id, [])
        if q in qs:
            qs.remove(q)
    logger.info(f"[EVENTS] -subscriber scan={scan_id[:8]}")


def get_history(scan_id: str) -> List[dict]:
    with _hist_lock:
        return list(_history.get(scan_id, []))


def cleanup(scan_id: str) -> None:
    with _sub_lock:
        _subscribers.pop(scan_id, None)
    with _hist_lock:
        _history.pop(scan_id, None)


def stream_generator(scan_id: str, store_getter):
    """
    Flask SSE generator. Yields SSE strings forever until scan completes.
    1. Replays full history immediately (catches late browser connections)
    2. Heartbeat comment every 15s keeps proxy connections alive
    3. Blocks on queue.get(timeout=1) — zero CPU when idle
    4. Terminates on 'complete' or 'error' event or scan terminal status
    """
    logger.info(f"[EVENTS] SSE stream open scan={scan_id[:8]}")

    # Replay history first
    for evt in get_history(scan_id):
        yield _fmt(evt["type"], evt["data"])

    # Already done?
    entry = store_getter(scan_id)
    if entry and str(entry.get("status", "")).upper() in ("COMPLETED", "FAILED", "PARTIAL"):
        final = entry.get("final_state") or {}
        yield _fmt("complete", {
            "scan_id": scan_id,
            "status": str(entry.get("status", "COMPLETED")),
            "score":  final.get("overall_risk_score", 0),
            "grade":  final.get("risk_grade", "?"),
            "total_findings": len(final.get("findings") or []),
            "duration": entry.get("duration_seconds", 0),
        })
        return

    q = subscribe(scan_id)
    last_beat = time.time()
    try:
        while True:
            # Heartbeat every 15s
            if time.time() - last_beat > 15:
                yield ": heartbeat\n\n"
                last_beat = time.time()
            try:
                msg = q.get(timeout=1.0)
                yield msg
                last_beat = time.time()
                # Stop on terminal events
                if msg.startswith("event: complete") or msg.startswith("event: error"):
                    break
            except queue.Empty:
                # Poll store as fallback
                entry = store_getter(scan_id)
                if entry and str(entry.get("status", "")).upper() in ("COMPLETED", "FAILED", "PARTIAL"):
                    final = entry.get("final_state") or {}
                    yield _fmt("complete", {
                        "scan_id": scan_id,
                        "status":  str(entry.get("status", "COMPLETED")),
                        "score":   final.get("overall_risk_score", 0),
                        "grade":   final.get("risk_grade", "?"),
                        "total_findings": len((final.get("findings") or [])),
                        "duration": entry.get("duration_seconds", 0),
                    })
                    break
    finally:
        unsubscribe(scan_id, q)
        logger.info(f"[EVENTS] SSE stream closed scan={scan_id[:8]}")
