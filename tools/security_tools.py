import json
import ast
import re
from typing import Optional
try:
    from langchain_core.tools import tool
except ImportError:
    from langchain.tools import tool

from core.config import config
from core.logger import get_logger
from utils.llm_client import call_llm, call_llm_for_json
from utils.chunker import chunk_file_content, count_tokens

logger = get_logger("tools.security_tools")


# ============================================================
# NAVIGATOR TOOLS
# ============================================================

@tool
def score_file_priority(file_path: str, file_size: int) -> str:
    """
    Score a file's security analysis priority (0-100) using deterministic rules.
    Returns JSON: {score, reason, language}.
    Higher score = higher priority. Use for every file the Navigator considers.
    Input: file_path (string path), file_size (integer bytes).
    """
    import json as _json
    from pathlib import Path
    from utils.chunker import detect_language

    logger.info(f"[TOOL:score_priority] Scoring: {file_path} ({file_size} bytes)")

    score = 0
    reasons = []

    path_lower = file_path.lower()
    filename = Path(file_path).name.lower()
    ext = Path(file_path).suffix.lower()

    # Skip junk extensions immediately
    if ext in config.IGNORED_EXTENSIONS:
        return _json.dumps({"score": 0, "reason": f"Ignored extension: {ext}", "language": "none"})

    # Skip ignored directories
    for ignored_dir in config.IGNORED_DIRS:
        if f"/{ignored_dir}/" in f"/{path_lower}/" or path_lower.startswith(f"{ignored_dir}/"):
            return _json.dumps({"score": 0, "reason": f"Ignored dir: {ignored_dir}", "language": "none"})

    # FIX #3b: use Pygments-based language detection (no content available here)
    language = detect_language(file_path)

    # High-value filenames
    for pattern in config.HIGH_VALUE_PATTERNS:
        if filename == pattern.lower():
            score += 50
            reasons.append(f"High-value entry point: {filename}")
            break

    # Security keywords in path
    critical_keywords = {
        "auth": 30, "login": 30, "password": 35, "secret": 35,
        "token": 30, "jwt": 30, "oauth": 25, "session": 25,
        "admin": 25, "api": 20, "route": 20, "view": 20,
        "model": 15, "database": 25, "db": 25, "sql": 30,
        "config": 20, "setting": 20, "middleware": 20,
        "upload": 25, "payment": 35, "crypto": 30, "key": 25,
    }
    for kw, pts in critical_keywords.items():
        if kw in path_lower:
            score += pts
            reasons.append(f"Security keyword: '{kw}'")
            break

    # Source code bonus
    source_exts = {".py", ".js", ".ts", ".java", ".php", ".rb", ".go", ".rs", ".cs"}
    if ext in source_exts:
        score += 10
        reasons.append(f"Source code ({language})")

    # Config/secrets files
    if filename in {".env", ".env.example", ".env.sample", "settings.py", "config.js"}:
        score += 40
        reasons.append("Config/secrets file")

    # IaC / container orchestration files — always security-relevant
    # docker-compose exposes ports, mounts volumes, sets env vars — high risk
    # kubernetes/helm manifests control RBAC, network policies, secrets
    IaC_FILENAMES = {
        "docker-compose.yml", "docker-compose.yaml",
        "docker-compose.prod.yml", "docker-compose.prod.yaml",
        "docker-compose.override.yml",
        "kubernetes.yaml", "k8s.yaml",
        "deployment.yaml", "service.yaml", "ingress.yaml",
        "Chart.yaml", "values.yaml",
        "main.tf", "variables.tf", "outputs.tf",
        "cloudformation.yaml", "template.yaml",
        "ansible.yml", "playbook.yml",
    }
    if filename in IaC_FILENAMES:
        score += 40
        reasons.append(f"IaC/orchestration file: {filename}")

    # Large file penalty
    if file_size > 500_000:
        score -= 10
        reasons.append("Large file penalty (>500KB)")

    score = max(0, min(100, score))
    result = {
        "score": score,
        "reason": "; ".join(reasons) if reasons else "Standard file",
        "language": language,
    }

    logger.info(f"[TOOL:score_priority] {file_path} → {score}/100 | {language}")
    return _json.dumps(result)


# ============================================================
# RESEARCHER TOOLS
# ============================================================

@tool
def analyze_file_for_vulnerabilities(file_path: str, file_content: str) -> str:
    """
    Deep security analysis of a single code chunk using Chain-of-Density LLM prompting.
    Returns JSON {findings: [...], file_summary: "..."}.
    Each finding has: title, category, severity, line_number, code_snippet,
    description, cwe_id, owasp_category, confidence, reasoning_trace,
    patch_code, patch_explanation.

    IMPORTANT: This tool receives a SINGLE pre-chunked piece of content.
    Chunking is handled by _run_llm_analysis in researcher.py BEFORE calling
    this tool. Do NOT chunk file_content again — that causes double-chunking
    where the tool receives tiny fragments (33 tokens) instead of full context,
    causing the LLM to return "No logic-level issues found" for every chunk.

    Input: file_path (string), file_content (single chunk of raw code).
    """
    logger.info(f"[TOOL:analyze_vulns] LLM analysis: {file_path} ({len(file_content)} chars)")

    system_prompt = """You are an elite penetration tester performing Chain-of-Density analysis.

NOTE: Deterministic scanners (Bandit, Semgrep, detect-secrets) have already run on this file.
Your job is to find LOGIC-LEVEL vulnerabilities that pattern-matching tools CANNOT detect:
- Broken authentication flows (missing checks, wrong order)
- IDOR (accessing other users' resources without validation)
- Business logic flaws
- Race conditions
- Insecure session management
- Missing authorization on sensitive operations

Do NOT report: obvious syntax issues, missing semicolons, style issues.

For every finding return ONLY this JSON format:
{
  "findings": [
    {
      "title": "Short descriptive title",
      "category": "one of: Broken Authentication, IDOR, SSRF, Command Injection, Path Traversal, XSS, CSRF, Insecure Configuration, Sensitive Data Exposure, Unknown Vulnerability",
      "severity": "CRITICAL | HIGH | MEDIUM | LOW | INFO",
      "line_number": 42,
      "code_snippet": "exact vulnerable code",
      "description": "detailed explanation of the risk",
      "cwe_id": "CWE-89",
      "owasp_category": "A01:2021",
      "confidence": "HIGH | MEDIUM | LOW",
      "reasoning_trace": "Step 1: I noticed X. Step 2: This leads to Y. Step 3: An attacker can Z.",
      "patch_code": "fixed version of the code",
      "patch_explanation": "why this patch prevents the attack"
    }
  ],
  "file_summary": "one sentence security posture summary"
}

Return {"findings": [], "file_summary": "No logic-level issues found."} if clean."""

    user_prompt = (
        f"Perform Chain-of-Density logic security analysis on this file.\n"
        f"File: {file_path}\n\n"
        f"```\n{file_content}\n```\n\nReturn only JSON."
    )

    parsed = call_llm_for_json(
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        label=f"researcher_{file_path.replace('/', '_')[:30]}",
        required_keys=["findings"]
    )

    findings = parsed.get("findings", []) if parsed else []
    file_summary = parsed.get("file_summary", "") if parsed else ""

    if parsed:
        logger.info(f"[TOOL:analyze_vulns] ✅ {file_path}: {len(findings)} findings")
    else:
        logger.warning(f"[TOOL:analyze_vulns] ⚠️  No parsed output for {file_path}")

    return json.dumps({
        "findings": findings,
        "file_summary": file_summary,
        "file_path": file_path,
    })


# ============================================================
# EXPLOITER TOOLS
# ============================================================

@tool
def generate_exploit_path(
    vulnerability_title: str,
    vulnerability_description: str,
    code_snippet: str,
    file_path: str,
    severity: str
) -> str:
    """
    Generate a realistic step-by-step attacker exploit simulation for a confirmed vulnerability.
    Returns JSON: {title, prerequisites, steps, impact, difficulty, attacker_type, proof_of_concept, poc_verified}.
    poc_verified=true means the PoC Python code passed syntax validation.
    Use only for CRITICAL and HIGH severity confirmed findings.
    Input: vulnerability_title, vulnerability_description, code_snippet, file_path, severity.
    """
    logger.info(f"[TOOL:exploit] Generating exploit: {vulnerability_title}")

    system_prompt = """You are a red team expert writing exploit simulations for DEFENSIVE education.

Write a realistic, technically accurate attacker simulation. Be specific:
- Use real HTTP methods, endpoints, payloads
- Reference the actual vulnerable code
- Show a working proof-of-concept (prefer Python or curl)
- Include realistic prerequisites

Return ONLY this JSON:
{
  "title": "The Exploit Scenario Title",
  "prerequisites": ["what attacker needs", "e.g. a valid account", "network access"],
  "steps": [
    {"step_number": 1, "action": "Attacker does X", "target": "endpoint/file", "result": "achieves Y"},
    {"step_number": 2, "action": "...", "target": "...", "result": "..."},
    {"step_number": 3, "action": "...", "target": "...", "result": "..."}
  ],
  "impact": "What data/system is compromised and how many users affected",
  "difficulty": "LOW | MEDIUM | HIGH",
  "attacker_type": "Script Kiddie | Opportunistic Attacker | Skilled Attacker | Nation-State",
  "proof_of_concept": "python or curl command showing the attack"
}"""

    user_prompt = (
        f"Generate exploit simulation for:\n"
        f"Vulnerability: {vulnerability_title}\n"
        f"Severity: {severity}\n"
        f"File: {file_path}\n"
        f"Description: {vulnerability_description[:500]}\n\n"
        f"Vulnerable Code:\n```\n{code_snippet[:1500]}\n```\n\nReturn only JSON."
    )

    result = call_llm_for_json(
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        label=f"exploiter_{vulnerability_title[:25].replace(' ', '_')}",
        required_keys=["steps", "impact"]
    )

    if not result:
        logger.warning(f"[TOOL:exploit] Failed to generate exploit for: {vulnerability_title}")
        result = {
            "title": f"Exploit for {vulnerability_title}",
            "prerequisites": ["Network access to target"],
            "steps": [
                {"step_number": 1, "action": "Identify the vulnerability",
                 "target": file_path, "result": "Attack vector confirmed"}
            ],
            "impact": "Could allow unauthorized access or data exposure",
            "difficulty": "MEDIUM",
            "attacker_type": "Skilled Attacker",
            "proof_of_concept": "# Manual exploitation required"
        }

    # FIX #6: Validate PoC code with ast.parse()
    poc = result.get("proof_of_concept", "")
    poc_verified = False

    if poc and poc.strip():
        # Try Python AST validation
        poc_clean = poc.strip()
        # Remove markdown fences if present
        poc_clean = re.sub(r"^```\w*\n?", "", poc_clean)
        poc_clean = re.sub(r"\n?```$", "", poc_clean)

        if not poc_clean.startswith("curl") and not poc_clean.startswith("http"):
            try:
                ast.parse(poc_clean)
                poc_verified = True
                logger.info(
                    f"[TOOL:exploit] ✅ PoC Python syntax valid for: {vulnerability_title}"
                )
            except SyntaxError as e:
                poc_verified = False
                logger.warning(
                    f"[TOOL:exploit] ⚠️  PoC syntax invalid: {e}. "
                    f"Marking as unverified."
                )
        else:
            # curl/HTTP PoC — mark as unverified (we can't easily validate)
            poc_verified = False
            logger.debug(
                f"[TOOL:exploit] curl/HTTP PoC detected — not AST-verifiable"
            )

    result["poc_verified"] = poc_verified
    logger.info(
        f"[TOOL:exploit] ✅ Exploit: '{result.get('title')}' | "
        f"{len(result.get('steps', []))} steps | "
        f"difficulty={result.get('difficulty')} | "
        f"poc_verified={poc_verified}"
    )
    return json.dumps(result)


# ============================================================
# AUDITOR TOOLS
# ============================================================

@tool
def calculate_risk_score(findings_json: str) -> str:
    """
    Calculate repository risk score (0-100) and letter grade from all findings.
    Also computes 6-dimension radar scores.
    Returns JSON: {overall_risk_score, risk_grade, radar_scores, finding_counts}.
    FIX: This is now pure deterministic Python math — no LLM involved.
    Input: findings_json (JSON string with 'findings' list).
    """
    logger.info("[TOOL:risk_score] Calculating deterministic risk score")

    try:
        data = json.loads(findings_json)
        findings = data.get("findings", [])
    except (json.JSONDecodeError, AttributeError) as e:
        logger.error(f"[TOOL:risk_score] JSON parse error: {e}")
        return json.dumps({"overall_risk_score": 0, "risk_grade": "A", "radar_scores": {}})

    # Deterministic severity weights
    weights = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3, "INFO": 1}
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

    raw_score = 0
    for f in findings:
        sev = str(f.get("severity", "INFO")).upper()
        raw_score += weights.get(sev, 1)
        if sev in counts:
            counts[sev] += 1

    # Normalize: cap at 100
    overall = min(100, raw_score)

    # Deterministic grade thresholds
    if overall >= 75:
        grade = "F"
    elif overall >= 60:
        grade = "D"
    elif overall >= 40:
        grade = "C"
    elif overall >= 20:
        grade = "B"
    else:
        grade = "A"

    # Radar: category → dimension mapping
    category_map = {
        "authentication": ["Broken Authentication", "CSRF"],
        "input_validation": ["SQL Injection", "Command Injection", "XSS",
                             "Path Traversal", "SSRF"],
        "secrets_management": ["Hardcoded Secret"],
        "api_security": ["Unprotected API Endpoint", "IDOR", "Open Redirect"],
        "configuration": ["Insecure Configuration", "Sensitive Data Exposure"],
        "dependency_safety": ["Vulnerable Dependency"],
    }

    radar = {dim: 100 for dim in category_map}

    for f in findings:
        cat = str(f.get("category", ""))
        sev = str(f.get("severity", "LOW")).upper()
        deduction = weights.get(sev, 1) * 3

        for dim, keywords in category_map.items():
            if any(kw.lower() in cat.lower() for kw in keywords):
                radar[dim] = max(0, radar[dim] - deduction)
                break

    result = {
        "overall_risk_score": overall,
        "risk_grade": grade,
        "radar_scores": radar,
        "finding_counts": {**counts, "total": len(findings)},
    }

    logger.info(
        f"[TOOL:risk_score] ✅ Score={overall}/100, Grade={grade}, "
        f"Critical={counts['CRITICAL']}, High={counts['HIGH']}"
    )
    return json.dumps(result)


@tool
def generate_executive_summary(
    repo_url: str,
    risk_score: str,
    risk_grade: str,
    findings_json: str
) -> str:
    """
    Generate a professional executive summary paragraph for the security report.
    Returns plain text (not JSON). LLM is appropriate here — it's writing, not math.
    Input: repo_url, risk_score, risk_grade (strings), findings_json (JSON string).
    """
    logger.info(f"[TOOL:summary] Generating executive summary for {repo_url}")

    try:
        data = json.loads(findings_json)
        findings = data.get("findings", [])
    except Exception:
        findings = []

    critical = sum(1 for f in findings if str(f.get("severity", "")).upper() == "CRITICAL")
    high     = sum(1 for f in findings if str(f.get("severity", "")).upper() == "HIGH")
    total    = len(findings)
    categories = list(set(str(f.get("category", "")) for f in findings if f.get("category")))

    system_prompt = (
        "You are a senior security consultant writing an executive summary "
        "for a penetration test report. Write in professional, accessible language. "
        "Be specific. Use 2-3 paragraphs of prose. No bullet points."
    )

    user_prompt = (
        f"Write an executive summary for:\n"
        f"Repository: {repo_url}\n"
        f"Risk Score: {risk_score}/100 (Grade: {risk_grade})\n"
        f"Findings: {total} total ({critical} Critical, {high} High)\n"
        f"Categories: {', '.join(categories[:6]) or 'None'}"
    )

    try:
        summary = call_llm(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            label="auditor_summary"
        )
        logger.info(f"[TOOL:summary] ✅ {len(summary)} chars")
        return summary
    except Exception as e:
        logger.error(f"[TOOL:summary] Failed: {e}")
        return (
            f"SwiftAudit completed security analysis of {repo_url}. "
            f"The repository received a risk score of {risk_score}/100 (Grade: {risk_grade}). "
            f"{total} vulnerabilities were identified including {critical} critical and "
            f"{high} high severity findings. Immediate remediation is recommended."
        )


# ============================================================
# TOOL EXPORTS
# ============================================================

NAVIGATOR_TOOLS  = [score_file_priority]
RESEARCHER_TOOLS = [analyze_file_for_vulnerabilities]
EXPLOITER_TOOLS  = [generate_exploit_path]
AUDITOR_TOOLS    = [calculate_risk_score, generate_executive_summary]
