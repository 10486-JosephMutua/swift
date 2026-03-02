from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


class VulnCategory(str, Enum):
    SQL_INJECTION             = "SQL Injection"
    XSS                       = "Cross-Site Scripting"
    COMMAND_INJECTION         = "Command Injection"
    PATH_TRAVERSAL            = "Path Traversal"
    HARDCODED_SECRET          = "Hardcoded Secret / Credential"
    BROKEN_AUTH               = "Broken Authentication"
    CSRF                      = "CSRF"
    SSRF                      = "Server-Side Request Forgery"
    OPEN_REDIRECT             = "Open Redirect"
    IDOR                      = "Insecure Direct Object Reference"
    INSECURE_DESERIALIZATION  = "Insecure Deserialization"
    DEPENDENCY_VULN           = "Vulnerable Dependency"
    INSECURE_CONFIG           = "Insecure Configuration"
    SENSITIVE_DATA            = "Sensitive Data Exposure"
    UNKNOWN                   = "Unknown Vulnerability"


class DetectionSource(str, Enum):
    """
    Tracks HOW the vulnerability was detected.
    Tool-detected findings have zero hallucination risk.
    LLM findings are enrichments/suggestions.
    """
    # v10 explicit tool sources
    SNYK_CODE       = "snyk_code"        # Snyk Code SAST
    SNYK_IAC        = "snyk_iac"         # Snyk IaC misconfiguration
    SNYK_CONTAINER  = "snyk_container"   # Snyk Container / Dockerfile
    TRIVY           = "trivy"            # Trivy SCA + secrets
    HISTORY_GUARD   = "history_guard"    # Git history entropy scanner

    # Legacy / LLM sources
    LLM_ENRICHED    = "llm_enriched"     # LLM explanation of tool finding
    LLM_ONLY        = "llm_only"         # Pure LLM reasoning
    LOGIC_AUDITOR   = "logic_auditor"    # Kept for backwards compat (v9 data)

    # Kept for backwards compat with old v9 generic "snyk"
    SNYK            = "snyk"
    DETECT_SECRETS  = "detect-secrets"
    BANDIT          = "bandit"
    SEMGREP         = "semgrep"
    SAFETY          = "safety"


class ScanStatus(str, Enum):
    PENDING   = "PENDING"
    RUNNING   = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED    = "FAILED"
    PARTIAL   = "PARTIAL"


class FileInfo(BaseModel):
    path: str
    language: str           = "unknown"
    size_bytes: int         = 0
    priority_score: int     = 0
    reason: str             = ""
    content: Optional[str]  = None
    content_truncated: bool = False
    chunk_index: int        = 0
    total_chunks: int       = 1


class RepoMetadata(BaseModel):
    url: str
    owner: str             = ""
    repo_name: str         = ""
    default_branch: str    = "main"
    language: str          = ""
    stars: int             = 0
    size_kb: int           = 0
    is_private: bool       = False
    description: str       = ""
    fetched_via: str       = "github_api"
    total_files_found: int = 0
    files_selected: int    = 0
    files_skipped: int     = 0


class ExploitStep(BaseModel):
    step_number: int
    action: str  = ""
    target: str  = ""
    result: str  = ""


class ExploitPath(BaseModel):
    title: str
    prerequisites: List[str]  = Field(default_factory=list)
    steps: List[ExploitStep]  = Field(default_factory=list)
    impact: str               = ""
    difficulty: str           = "MEDIUM"
    attacker_type: str        = ""
    proof_of_concept: str     = ""
    poc_verified: bool        = False


class VulnerabilityFinding(BaseModel):
    finding_id: str
    file_path: str
    line_number: Optional[int]     = None
    code_snippet: str              = ""
    category: VulnCategory         = VulnCategory.UNKNOWN
    severity: Severity             = Severity.MEDIUM
    title: str
    description: str               = ""
    cwe_id: Optional[str]          = None
    owasp_category: Optional[str]  = None
    confidence: str                = "MEDIUM"
    reasoning_trace: str           = ""
    cvss_score: Optional[float]    = None   # v10: CVSS score from Trivy/Snyk

    detection_source: DetectionSource = DetectionSource.LLM_ONLY

    # Tool-specific metadata
    tool_rule_id: str   = ""
    tool_test_name: str = ""

    # Patch
    patch_code: str        = ""
    patch_explanation: str = ""

    # Exploit
    exploit_path: Optional[ExploitPath] = None
    false_positive_risk: str            = "LOW"

    class Config:
        use_enum_values = True


class SecurityRadarScore(BaseModel):
    authentication: int    = Field(100, ge=0, le=100)
    input_validation: int  = Field(100, ge=0, le=100)
    secrets_management: int = Field(100, ge=0, le=100)
    api_security: int      = Field(100, ge=0, le=100)
    dependency_safety: int = Field(100, ge=0, le=100)
    configuration: int     = Field(100, ge=0, le=100)

    @property
    def overall(self) -> int:
        vals = [
            self.authentication, self.input_validation,
            self.secrets_management, self.api_security,
            self.dependency_safety, self.configuration,
        ]
        return int(sum(vals) / len(vals))


class ScanResult(BaseModel):
    scan_id: str
    status: ScanStatus                       = ScanStatus.PENDING
    repo_url: str
    metadata: Optional[RepoMetadata]        = None
    files_analyzed: List[FileInfo]          = Field(default_factory=list)
    findings: List[VulnerabilityFinding]    = Field(default_factory=list)
    radar_scores: Optional[SecurityRadarScore] = None
    overall_risk_score: int                 = Field(0, ge=0, le=100)
    risk_grade: str                         = "A"
    summary: str                            = ""
    scan_started_at: Optional[datetime]     = None
    scan_completed_at: Optional[datetime]   = None
    scan_duration_seconds: Optional[float]  = None
    agent_logs: List[str]                   = Field(default_factory=list)
    errors: List[str]                       = Field(default_factory=list)
    report_markdown: str                    = ""
    report_pdf_path: str                    = ""
    tool_finding_count: int                 = 0   # v10: breakdown by source
    llm_finding_count: int                  = 0   # v10: breakdown by source

    # Severity breakdown (computed by auditor)
    critical_count: int = 0
    high_count: int     = 0
    medium_count: int   = 0
    low_count: int      = 0
    info_count: int     = 0
