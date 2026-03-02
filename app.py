import os
import time

from flask import (
    Flask, Response, request, jsonify,
    render_template, send_from_directory,
)

from core.logger import setup_logging, get_logger
from core.config import config
from core.events import stream_generator
from core.pipeline import (
    create_scan, run_pipeline_async, get_scan,
    get_scan_status, delete_scan, list_scans,
)

# Must be set before any google-genai import to prevent GCE metadata hang
os.environ.setdefault("NO_GCE_CHECK", "true")
os.environ.setdefault("GOOGLE_CLOUD_PROJECT", "none")

setup_logging(level="DEBUG")
logger = get_logger("app")

import logging as _logging
_logging.getLogger("werkzeug").setLevel(_logging.WARNING)

app = Flask(__name__, template_folder="templates")

github_token = config.GITHUB_TOKEN


# ── Global error handlers ─────────────────────────────────────
# Flask's default error pages are HTML. The frontend calls .json() on every
# response, so an unhandled exception that returns HTML causes
# "Unexpected end of JSON input". These handlers ensure every error is JSON.

@app.errorhandler(400)
def bad_request(e):
    logger.warning(f"[APP] 400: {e}")
    return jsonify({"error": str(e)}), 400


@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "not found"}), 404


@app.errorhandler(500)
def internal_error(e):
    logger.error(f"[APP] 500: {e}", exc_info=True)
    return jsonify({"error": f"Internal server error: {str(e)}"}), 500


@app.errorhandler(Exception)
def unhandled(e):
    logger.error(f"[APP] Unhandled exception: {e}", exc_info=True)
    return jsonify({"error": f"Unexpected error: {str(e)}"}), 500


# ── Routes ────────────────────────────────────────────────────

@app.route("/")
def index():
    logger.info("[APP] GET /")
    return render_template("index.html")


@app.route("/api/v1/scan", methods=["POST"])
def create_scan_endpoint():
    data     = request.get_json(silent=True) or {}
    repo_url = (data.get("repo_url") or "").strip()
    if not repo_url:
        return jsonify({"error": "repo_url is required"}), 400
    if not (repo_url.startswith("http://") or repo_url.startswith("https://")):
        return jsonify({"error": "repo_url must be a full URL"}), 400

    logger.info(f"[APP] New scan: {repo_url}")

    scan_id      = create_scan(repo_url, github_token=github_token)
    run_pipeline_async(scan_id)

    return jsonify({
        "scan_id":  scan_id,
        "status":   "PENDING",
        "repo_url": repo_url,
        "stream":   f"/api/v1/scan/{scan_id}/stream",
    }), 202


@app.route("/api/v1/scan/<scan_id>/stream")
def stream_endpoint(scan_id):
    logger.info(f"[APP] SSE stream open: {scan_id[:8]}")
    return Response(
        stream_generator(scan_id, get_scan_status),
        mimetype="text/event-stream",
        headers={
            "Cache-Control":   "no-cache",
            "X-Accel-Buffering": "no",
            "Connection":      "keep-alive",
        },
    )


@app.route("/api/v1/scan/<scan_id>/status")
def status_endpoint(scan_id):
    entry = get_scan_status(scan_id)
    if not entry:
        return jsonify({"error": "scan not found"}), 404
    return jsonify({
        "scan_id":      scan_id,
        "status":       str(entry.get("status", "UNKNOWN")),
        "progress":     entry.get("progress", 0),
        "current_step": entry.get("current_step", ""),
        "repo_url":     entry.get("repo_url"),
    })


@app.route("/api/v1/scan/<scan_id>/result")
def result_endpoint(scan_id):
    entry = get_scan_status(scan_id)
    if not entry:
        return jsonify({"error": "scan not found"}), 404

    status = str(entry.get("status", ""))
    if status.upper() not in ("COMPLETED", "FAILED", "PARTIAL"):
        return jsonify({"error": f"scan not complete yet (status={status})"}), 202

    result = get_scan(scan_id)
    if not result:
        return jsonify({"error": "scan not found"}), 404

    findings_out = []
    for f in (result.findings or []):
        findings_out.append({
            "finding_id":       f.finding_id,
            "title":            f.title,
            "severity":         str(f.severity).replace("Severity.", "").upper(),
            "category":         str(f.category),
            "file_path":        f.file_path,
            "line_number":      f.line_number,
            "description":      f.description,
            "code_snippet":     (f.code_snippet or "")[:1000],
            "cwe_id":           f.cwe_id,
            "owasp_category":   f.owasp_category,
            "confidence":       f.confidence,
            "detection_source": str(f.detection_source),
            "tool_rule_id":     f.tool_rule_id,
            "patch_explanation": f.patch_explanation,
            "patch_code":       (f.patch_code or "")[:2000],
            "cvss_score":       f.cvss_score,
            "exploit_path":     f.exploit_path.dict() if f.exploit_path else None,
        })

    radar = {}
    if result.radar_scores:
        rs = result.radar_scores
        radar = {
            "authentication":    rs.authentication,
            "input_validation":  rs.input_validation,
            "secrets_management": rs.secrets_management,
            "api_security":      rs.api_security,
            "dependency_safety": rs.dependency_safety,
            "configuration":     rs.configuration,
        }

    meta = {}
    if result.metadata:
        m = result.metadata
        meta = {
            "owner":       m.owner,
            "repo_name":   m.repo_name,
            "language":    m.language,
            "stars":       m.stars,
            "size_kb":     m.size_kb,
            "description": m.description,
            "total_files_found": m.total_files_found,
            "files_selected":    m.files_selected,
            "files_skipped":     m.files_skipped,
        }

    return jsonify({
        "scan_id":           scan_id,
        "status":            str(result.status),
        "repo_url":          result.repo_url,
        "overall_risk_score": result.overall_risk_score,
        "risk_grade":        result.risk_grade,
        "summary":           result.summary,
        "findings":          findings_out,
        "finding_count":     len(findings_out),
        "tool_finding_count": result.tool_finding_count,
        "llm_finding_count":  result.llm_finding_count,
        "radar_scores":      radar,
        "metadata":          meta,
        "scan_duration":     result.scan_duration_seconds,
        "agent_logs":        (result.agent_logs or [])[-100:],
        "errors":            result.errors or [],
    })


@app.route("/api/v1/scan/<scan_id>", methods=["DELETE"])
def delete_endpoint(scan_id):
    if delete_scan(scan_id):
        return jsonify({"deleted": scan_id}), 200
    return jsonify({"error": "not found"}), 404


@app.route("/api/v1/scans")
def list_endpoint():
    return jsonify({"scans": [
        {"scan_id": s["scan_id"], "status": str(s["status"]),
         "repo_url": s["repo_url"], "progress": s["progress"]}
        for s in list_scans()
    ]})


@app.route("/reports/<path:filename>")
def serve_report(filename):
    return send_from_directory("reports/output", filename)


@app.route("/api/v1/health")
def health():
    return jsonify({
        "status": "healthy",
        "model":  config.GROQ_MODEL,
        "snyk":   bool(config.SNYK_TOKEN),
        "ts":     time.time(),
    })


# ── Boot ──────────────────────────────────────────────────────

if __name__ == "__main__":
    logger.info("=" * 60)
    logger.info("[APP] SwiftAudit starting")
    logger.info(f"[APP] Host : {config.FLASK_HOST}:{config.FLASK_PORT}")
    logger.info(f"[APP] Model: {config.GROQ_MODEL}")
    logger.info(f"[APP] Snyk : {'SET' if config.SNYK_TOKEN else 'NOT SET'}")
    logger.info("=" * 60)

    try:
        config.validate()
    except ValueError as e:
        logger.error(f"[APP] Config error: {e}")
        raise

    from utils.llm_providers import get_provider_chain
    chain = get_provider_chain()
    logger.info(f"[APP] LLM providers: {[n for n, _ in chain]}")

    app.run(
        host=config.FLASK_HOST,
        port=config.FLASK_PORT,
        debug=False,
        use_reloader=False,
        threaded=True,
    )
