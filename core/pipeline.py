import uuid, threading, time
from datetime import datetime
from typing import Optional, Dict, Any, Literal
from cachetools import TTLCache
from langgraph.graph import StateGraph, START, END
from core.config import config
from core.logger import get_logger
from core.events import emit, cleanup
from core.graph_state import ScanState
from core.models import ScanResult, ScanStatus, RepoMetadata

logger = get_logger("core.pipeline")

_scan_store: TTLCache = TTLCache(
    maxsize=config.SCAN_STORE_MAX_SIZE,
    ttl=config.SCAN_STORE_TTL_HOURS * 3600,
)
_store_lock = threading.Lock()
logger.info(f"[PIPELINE] Store: TTLCache maxsize={config.SCAN_STORE_MAX_SIZE} ttl={config.SCAN_STORE_TTL_HOURS}h")


def _upd(scan_id, pct, step, status=None):
    """Update store + push SSE progress event simultaneously."""
    logger.info(f"[PIPELINE] {scan_id[:8]} | {pct:3d}% | {step}")
    with _store_lock:
        e = _scan_store.get(scan_id)
        if e:
            e["progress"]     = pct
            e["current_step"] = step
            e["status"]       = status or ScanStatus.RUNNING
    emit(scan_id, "progress", {"pct": pct, "step": step, "phase": _phase(step)})


def _log(scan_id, msg, level="INFO"):
    logger.info(f"[PIPE:log] {scan_id[:8]} {msg}")
    emit(scan_id, "log", {"message": msg, "level": level, "ts": time.time()})


def _finding(scan_id, f):
    try:
        emit(scan_id, "finding", {
            "title":    (f.title or "")[:80],
            "severity": str(f.severity).replace("Severity.", "").upper(),
            "file":     f.file_path or "",
            "source":   str(f.detection_source).replace("DetectionSource.", ""),
            "category": str(f.category).replace("VulnCategory.", ""),
        })
    except Exception:
        pass


def _phase(s):
    s = s.lower()
    if "navigator" in s: return "navigator"
    if "clone" in s or "researcher" in s: return "researcher"
    if "snyk" in s or "trivy" in s or "logic" in s or "history" in s: return "scanner"
    if "llm" in s or "enrich" in s: return "analysis"
    if "exploit" in s: return "exploiter"
    if "audit" in s: return "auditor"
    return "pipeline"


# ─── Node 1: Navigator ────────────────────────────────────────
def navigator_node(state):
    sid = state["scan_id"]
    logger.info(f"[GRAPH:navigator] ▶ {sid}")
    from agents.navigator import NavigatorAgent
    _upd(sid, 5, "Navigator: Fetching repository...")
    _log(sid, f"🔍 Navigator — {state['repo_url']}")
    t0 = time.time()
    def _cb(pct, step): _upd(sid, pct, step); _log(sid, f"  {step}")
    try:
        r = NavigatorAgent(token=state.get("github_token"), progress_callback=_cb).run(state["repo_url"])
        n = len(r["files"])
        _log(sid, f"✅ Navigator done {time.time()-t0:.1f}s — {n} files")
        logger.info(f"[GRAPH:navigator] ✅ {n} files {time.time()-t0:.1f}s")
        return {"metadata": r["metadata"], "files": r["files"], "status": ScanStatus.RUNNING,
                "progress": 25, "current_step": "Researcher: Initializing...",
                "agent_logs": r.get("agent_logs", []), "errors": []}
    except Exception as e:
        logger.error(f"[GRAPH:navigator] ❌ {e}")
        _log(sid, f"❌ Navigator failed: {e}", "ERROR")
        emit(sid, "error", {"message": str(e)})
        return {"status": ScanStatus.FAILED, "progress": 0,
                "current_step": f"FAILED: {str(e)[:80]}",
                "agent_logs": [f"❌ {e}"], "errors": [f"Navigator: {e}"]}


# ─── Node 2: Researcher ───────────────────────────────────────
def researcher_node(state):
    sid = state["scan_id"]
    logger.info(f"[GRAPH:researcher] ▶ {sid}")
    from agents.researcher import ResearcherAgent
    files = state.get("files") or []
    if not files:
        return {"findings": [], "tool_finding_count": 0, "llm_finding_count": 0,
                "progress": 55, "current_step": "Exploiter: Simulating...",
                "agent_logs": ["⚠️  No files"], "errors": []}
    _upd(sid, 27, "Researcher: Initializing...")
    _log(sid, f"🔬 Researcher — {len(files)} files")
    t0 = time.time()
    def _cb(pct, step): _upd(sid, pct, step); _log(sid, f"  {step}")
    def _fcb(f): _finding(sid, f)
    try:
        findings = ResearcherAgent(progress_callback=_cb, finding_callback=_fcb).run(
            files, repo_url=state.get("repo_url", ""))
        tc = sum(1 for f in findings if "llm_only" not in str(f.detection_source).lower())
        lc = len(findings) - tc
        _log(sid, f"✅ Researcher {time.time()-t0:.1f}s — {len(findings)} findings ({tc} tool, {lc} LLM)")
        logger.info(f"[GRAPH:researcher] ✅ {len(findings)} findings {time.time()-t0:.1f}s")
        return {"findings": findings, "tool_finding_count": tc, "llm_finding_count": lc,
                "progress": 72, "current_step": "Exploiter: Simulating attacks...",
                "agent_logs": [f"🔬 {len(findings)} findings"], "errors": []}
    except Exception as e:
        logger.error(f"[GRAPH:researcher] ❌ {e}")
        _log(sid, f"❌ Researcher failed: {e}", "ERROR")
        return {"findings": [], "tool_finding_count": 0, "llm_finding_count": 0,
                "progress": 72, "current_step": "Exploiter: Simulating...",
                "agent_logs": [f"❌ {e}"], "errors": [f"Researcher: {e}"]}


# ─── Node 3: Exploiter ────────────────────────────────────────
def exploiter_node(state):
    sid = state["scan_id"]
    findings = list(state.get("findings") or [])
    logger.info(f"[GRAPH:exploiter] ▶ {sid}")
    from agents.exploiter import ExploiterAgent
    _upd(sid, 75, "Exploiter: Simulating attacks...")
    _log(sid, f"⚔️  Exploiter — {len(findings)} findings")
    try:
        enriched = ExploiterAgent().run(findings)
        ec = sum(1 for f in enriched if f.exploit_path)
        _log(sid, f"✅ Exploiter — {ec} attack paths")
        return {"exploit_count": ec, "progress": 85,
                "current_step": "Auditor: Building report...",
                "agent_logs": [f"⚔️  {ec} simulations"], "errors": [],
                "_enriched_findings": enriched}
    except Exception as e:
        logger.error(f"[GRAPH:exploiter] ❌ {e}")
        _log(sid, f"⚠️  Exploiter failed: {e}", "WARNING")
        return {"exploit_count": 0, "progress": 85,
                "current_step": "Auditor: Building report...",
                "agent_logs": [f"⚠️  {e}"], "errors": [f"Exploiter: {e}"]}


# ─── Node 4: Auditor ──────────────────────────────────────────
def auditor_node(state):
    sid = state["scan_id"]
    logger.info(f"[GRAPH:auditor] ▶ {sid}")
    from agents.auditor import AuditorAgent
    enriched = state.get("_enriched_findings")
    findings = enriched if enriched is not None else (state.get("findings") or [])
    meta = state.get("metadata")
    _upd(sid, 87, "Auditor: Building final report...")
    _log(sid, f"📊 Auditor synthesising {len(findings)} findings")
    sr = ScanResult(
        scan_id=sid, status=ScanStatus.RUNNING, repo_url=state["repo_url"],
        metadata=meta, files_analyzed=state.get("files") or [], findings=findings,
        tool_finding_count=state.get("tool_finding_count", 0),
        llm_finding_count=state.get("llm_finding_count", 0),
        scan_started_at=datetime.now(),
    )
    try:
        done = AuditorAgent().run(
            scan_result=sr, findings=findings,
            metadata=meta or RepoMetadata(url=state["repo_url"]),
            all_agent_logs=state.get("agent_logs") or [],
        )
        _log(sid, f"✅ Score {done.overall_risk_score}/100 Grade {done.risk_grade}")
        logger.info(f"[GRAPH:auditor] ✅ Score={done.overall_risk_score} Grade={done.risk_grade}")
        emit(sid, "complete", {
            "scan_id": sid, "status": "COMPLETED",
            "score": done.overall_risk_score, "grade": done.risk_grade,
            "total_findings": len(findings),
            "critical": done.critical_count, "high": done.high_count,
            "medium": done.medium_count, "low": done.low_count,
            "summary": (done.summary or "")[:400], "duration": 0,
            "pdf_path": done.report_pdf_path or "",
        })
        return {"overall_risk_score": done.overall_risk_score, "risk_grade": done.risk_grade,
                "radar_scores": done.radar_scores, "summary": done.summary,
                "report_markdown": done.report_markdown, "report_pdf_path": done.report_pdf_path or "",
                "status": ScanStatus.COMPLETED, "progress": 100, "current_step": "Completed",
                "agent_logs": [f"✅ Score={done.overall_risk_score}"], "errors": []}
    except Exception as e:
        logger.error(f"[GRAPH:auditor] ❌ {e}")
        _log(sid, f"❌ Auditor failed: {e}", "ERROR")
        emit(sid, "error", {"message": f"Audit failed: {e}"})
        return {"overall_risk_score": 0, "risk_grade": "F",
                "summary": f"Audit failed: {e}", "report_markdown": f"# Failed\n{e}",
                "report_pdf_path": "", "status": ScanStatus.PARTIAL, "progress": 100,
                "current_step": "Partial", "agent_logs": [f"❌ {e}"], "errors": [f"Auditor: {e}"]}


def error_node(state):
    sid = state.get("scan_id", "unknown")
    logger.error(f"[GRAPH:error] {state.get('errors')}")
    emit(sid, "error", {"message": "; ".join(state.get("errors") or ["Unknown"])})
    return {"status": ScanStatus.FAILED, "progress": 0, "current_step": "FAILED",
            "agent_logs": ["❌ Pipeline terminated"], "errors": []}


def _route(state) -> Literal["exploiter", "auditor", "error"]:
    if state.get("status") == ScanStatus.FAILED: return "error"
    findings = state.get("findings") or []
    has_high = any(str(f.severity).upper() in {"CRITICAL", "HIGH"} for f in findings)
    logger.info(f"[GRAPH:router] → {'exploiter' if has_high else 'auditor'}")
    return "exploiter" if has_high else "auditor"


def _build():
    b = StateGraph(ScanState)
    for name, fn in [("navigator_node", navigator_node), ("researcher_node", researcher_node),
                     ("exploiter_node", exploiter_node), ("auditor_node", auditor_node),
                     ("error_node", error_node)]:
        b.add_node(name, fn)
    b.add_edge(START, "navigator_node")
    b.add_edge("navigator_node", "researcher_node")
    b.add_conditional_edges("researcher_node", _route,
        {"exploiter": "exploiter_node", "auditor": "auditor_node", "error": "error_node"})
    b.add_edge("exploiter_node", "auditor_node")
    b.add_edge("auditor_node", END)
    b.add_edge("error_node", END)
    logger.info("[PIPELINE] ✅ Graph compiled")
    return b.compile()


_graph = _build()


# ─── Public API ───────────────────────────────────────────────
def create_scan(repo_url, github_token=None):
    sid = str(uuid.uuid4())
    with _store_lock:
        _scan_store[sid] = {
            "scan_id": sid, "repo_url": repo_url,
            "status": ScanStatus.PENDING, "progress": 0, "current_step": "Queued",
            "github_token": github_token, "final_state": None,
            "started_at": datetime.now(), "completed_at": None,
            "duration_seconds": None, "crash_error": None,
        }
    logger.info(f"[PIPELINE] Created: {sid} | {repo_url}")
    return sid


def run_pipeline_async(scan_id):
    t = threading.Thread(target=_run, args=(scan_id,), daemon=True, name=f"scan-{scan_id[:8]}")
    t.start()
    logger.info(f"[PIPELINE] Thread: scan-{scan_id[:8]}")


def _run(scan_id):
    with _store_lock:
        entry = _scan_store.get(scan_id)
    if not entry:
        logger.error(f"[PIPELINE] Not found: {scan_id}")
        return
    logger.info(f"[PIPELINE] 🚀 Graph: {scan_id}")
    t0 = datetime.now()
    with _store_lock:
        if scan_id in _scan_store:
            _scan_store[scan_id].update({"status": ScanStatus.RUNNING, "progress": 5,
                                          "current_step": "Navigator: Fetching repository..."})
    init = {
        "scan_id": scan_id, "repo_url": entry["repo_url"],
        "github_token": entry.get("github_token"), "metadata": None, "files": None,
        "findings": [], "tool_finding_count": 0, "llm_finding_count": 0, "exploit_count": 0,
        "overall_risk_score": 0, "risk_grade": "A", "radar_scores": None,
        "summary": "", "report_markdown": "", "report_pdf_path": "",
        "status": ScanStatus.RUNNING, "progress": 5,
        "current_step": "Navigator: Fetching repository...", "agent_logs": [], "errors": [],
    }
    try:
        final   = _graph.invoke(init)
        elapsed = (datetime.now() - t0).total_seconds()
        logger.info(f"[PIPELINE] ✅ {scan_id} {elapsed:.1f}s {len(final.get('findings',[]))} findings")
        with _store_lock:
            if scan_id in _scan_store:
                _scan_store[scan_id].update({
                    "status": final.get("status", ScanStatus.COMPLETED),
                    "progress": final.get("progress", 100),
                    "current_step": final.get("current_step", "Completed"),
                    "final_state": final, "completed_at": datetime.now(),
                    "duration_seconds": elapsed,
                })
        emit(scan_id, "complete", {
            "scan_id": scan_id, "status": str(final.get("status", "COMPLETED")),
            "score":  final.get("overall_risk_score", 0), "grade": final.get("risk_grade", "?"),
            "total_findings": len(final.get("findings") or []), "duration": elapsed,
        })
    except Exception as e:
        elapsed = (datetime.now() - t0).total_seconds()
        logger.error(f"[PIPELINE] ❌ Crashed: {scan_id} — {e}", exc_info=True)
        with _store_lock:
            if scan_id in _scan_store:
                _scan_store[scan_id].update({
                    "status": ScanStatus.FAILED, "progress": 0,
                    "current_step": f"FAILED: {str(e)[:80]}",
                    "final_state": None, "completed_at": datetime.now(),
                    "duration_seconds": elapsed, "crash_error": str(e),
                })
        emit(scan_id, "error", {"message": str(e)})


def get_scan(scan_id):
    with _store_lock:
        entry = _scan_store.get(scan_id)
    if not entry: return None
    final = entry.get("final_state")
    r = ScanResult(scan_id=scan_id, status=entry.get("status", ScanStatus.PENDING),
                   repo_url=entry["repo_url"], scan_started_at=entry.get("started_at"),
                   scan_completed_at=entry.get("completed_at"),
                   scan_duration_seconds=entry.get("duration_seconds"),
                   errors=[entry["crash_error"]] if entry.get("crash_error") else [])
    if final:
        r.metadata           = final.get("metadata")
        r.files_analyzed     = final.get("files") or []
        enriched             = final.get("_enriched_findings")
        r.findings           = enriched if enriched else (final.get("findings") or [])
        r.overall_risk_score = final.get("overall_risk_score", 0)
        r.risk_grade         = final.get("risk_grade", "A")
        r.radar_scores       = final.get("radar_scores")
        r.summary            = final.get("summary", "")
        r.report_markdown    = final.get("report_markdown", "")
        r.report_pdf_path    = final.get("report_pdf_path", "")
        r.agent_logs         = final.get("agent_logs") or []
        r.errors             = final.get("errors") or []
        r.tool_finding_count = final.get("tool_finding_count", 0)
        r.llm_finding_count  = final.get("llm_finding_count", 0)
    return r


def get_scan_status(scan_id):
    with _store_lock:
        return _scan_store.get(scan_id)


def delete_scan(scan_id):
    with _store_lock:
        if scan_id in _scan_store:
            del _scan_store[scan_id]
            cleanup(scan_id)
            logger.info(f"[PIPELINE] Deleted: {scan_id}")
            return True
    return False


def list_scans():
    with _store_lock:
        return [{"scan_id": k, "status": v.get("status"), "repo_url": v.get("repo_url"),
                 "started_at": v.get("started_at"), "progress": v.get("progress", 0)}
                for k, v in _scan_store.items()]
