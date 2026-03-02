import operator
from typing import Annotated, Optional, List
from typing_extensions import TypedDict

from core.models import (
    RepoMetadata, FileInfo, VulnerabilityFinding,
    SecurityRadarScore, ScanStatus
)


class ScanState(TypedDict):
    """
    Shared state flowing through the SwiftAudit LangGraph pipeline.

    Fields owned by each node:
      Navigator  → repo_url (input), metadata, files, status
      Researcher → findings (appends), tool_finding_count, llm_finding_count
      Exploiter  → findings (enriches in-place via replace), exploit_count
      Auditor    → overall_risk_score, risk_grade, radar_scores,
                   summary, report_markdown, report_pdf_path, status

    Accumulated across all nodes (operator.add reducer):
      agent_logs → each node appends its log entries
      errors     → each node appends non-fatal errors
    """

    # ---- Input (set by pipeline.py before graph.invoke()) ----
    scan_id: str
    repo_url: str
    github_token: Optional[str]

    # ---- Navigator outputs ----
    metadata: Optional[RepoMetadata]
    files: Optional[List[FileInfo]]

    # ---- Researcher outputs ----
    # Annotated with operator.add: Researcher appends, Exploiter replaces the list
    findings: Annotated[List[VulnerabilityFinding], operator.add]
    tool_finding_count: int
    llm_finding_count: int

    # ---- Exploiter outputs ----
    exploit_count: int

    # ---- Auditor outputs ----
    overall_risk_score: int
    risk_grade: str
    radar_scores: Optional[SecurityRadarScore]
    summary: str
    report_markdown: str
    report_pdf_path: str

    # ---- Pipeline-wide ----
    status: ScanStatus
    progress: int
    current_step: str

    # Accumulated log entries from all nodes (operator.add = append per node)
    agent_logs: Annotated[List[str], operator.add]

    # Accumulated non-fatal errors from all nodes
    errors: Annotated[List[str], operator.add]
