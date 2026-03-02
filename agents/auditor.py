import json
import textwrap
from typing import List, Optional, Dict, Any
from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from core.config import config
from core.logger import get_logger
from core.models import (
    ScanResult, VulnerabilityFinding, RepoMetadata,
    SecurityRadarScore, ScanStatus, Severity, DetectionSource
)
from tools.security_tools import calculate_risk_score, generate_executive_summary
from utils.llm_client import invoke_agent_with_fallback
from utils.llm_providers import get_primary_name

logger = get_logger("agents.auditor")


class AuditorAgent:
    """
    Auditor: synthesizes all findings into final structured report.

    FIX #5: Risk score calculation is deterministic Python math (no LLM).
    FIX #7: Report built from Jinja2 template (not f-strings).
    """

    def __init__(self):
        # No LLM stored at init — invoke_agent_with_fallback() selects the
        # provider at call time with automatic failover.
        self._primary_name = get_primary_name()

        # FIX #7: Set up Jinja2 environment
        template_dir = Path(config.REPORT_TEMPLATES_DIR)
        template_dir.mkdir(parents=True, exist_ok=True)

        self.jinja_env = Environment(
            loader=FileSystemLoader(str(template_dir)),
            autoescape=select_autoescape(disabled_extensions=["j2", "md"]),
            trim_blocks=True,
            lstrip_blocks=True,
        )

        logger.info(
            f"[AUDITOR] AuditorAgent v7 initialized | "
            f"primary provider: {self._primary_name} | "
            f"fallback chain active"
        )
        logger.info(f"[AUDITOR] Template dir: {template_dir.absolute()}")

    def run(
        self,
        scan_result: ScanResult,
        findings: List[VulnerabilityFinding],
        metadata: RepoMetadata,
        all_agent_logs: List[str]
    ) -> ScanResult:
        """
        Full audit synthesis pipeline.

        Steps:
        1. Calculate risk score (DIRECT TOOL CALL — no LLM)
        2. Generate executive summary (LLM appropriate — it's writing)
        3. Build Markdown report via Jinja2 template
        4. Generate PDF
        5. Return completed ScanResult
        """
        logger.info(f"[AUDITOR] 📊 Synthesizing: {len(findings)} findings")
        start_time = datetime.now()
        agent_logs = [f"📊 Auditor: Synthesizing {len(findings)} findings..."]

        # ---- Step 1: Risk Score (DIRECT, no LLM) ----
        logger.info("[AUDITOR] Step 1/4: Calculating risk score (deterministic)...")
        agent_logs.append("🎯 Auditor: Calculating risk score (deterministic math)...")

        risk_data = self._calculate_risk_directly(findings)

        scan_result.overall_risk_score = risk_data.get("overall_risk_score", 0)
        scan_result.risk_grade = risk_data.get("risk_grade", "A")

        radar_data = risk_data.get("radar_scores", {})
        scan_result.radar_scores = SecurityRadarScore(
            authentication=radar_data.get("authentication", 100),
            input_validation=radar_data.get("input_validation", 100),
            secrets_management=radar_data.get("secrets_management", 100),
            api_security=radar_data.get("api_security", 100),
            dependency_safety=radar_data.get("dependency_safety", 100),
            configuration=radar_data.get("configuration", 100),
        )

        counts = risk_data.get("finding_counts", {})
        agent_logs.append(
            f"✅ Auditor: Risk Score={scan_result.overall_risk_score}/100 "
            f"(Grade: {scan_result.risk_grade}) | "
            f"Critical={counts.get('CRITICAL', 0)}, High={counts.get('HIGH', 0)}"
        )

        logger.info(
            f"[AUDITOR] Risk Score={scan_result.overall_risk_score}/100, "
            f"Grade={scan_result.risk_grade}"
        )

        # ---- Step 2: Executive Summary (LLM — writing is appropriate) ----
        logger.info("[AUDITOR] Step 2/4: Generating executive summary...")
        agent_logs.append("✍️  Auditor: Writing executive summary...")

        summary = self._generate_summary_with_agent(
            scan_result.repo_url,
            scan_result.overall_risk_score,
            scan_result.risk_grade,
            findings
        )
        scan_result.summary = summary

        # ---- Step 3: Markdown Report (Jinja2) ----
        logger.info("[AUDITOR] Step 3/4: Building report from Jinja2 template...")
        agent_logs.append("📄 Auditor: Rendering report from template...")

        scan_result.report_markdown = self._build_report_jinja2(
            scan_result, findings, metadata, risk_data
        )

        # ---- Step 4: PDF Generation ----
        logger.info("[AUDITOR] Step 4/4: Generating PDF report...")
        agent_logs.append("📑 Auditor: Generating PDF...")

        pdf_path = self._generate_pdf(scan_result)
        scan_result.report_pdf_path = pdf_path

        # ---- Finalize ----
        scan_result.status = ScanStatus.COMPLETED
        scan_result.scan_completed_at = datetime.now()
        scan_result.scan_duration_seconds = (
            datetime.now() - start_time
        ).total_seconds()
        scan_result.agent_logs = all_agent_logs + agent_logs

        # Count by detection source
        scan_result.tool_finding_count = sum(
            1 for f in findings
            if f.detection_source not in (DetectionSource.LLM_ONLY,)
        )
        scan_result.llm_finding_count = sum(
            1 for f in findings
            if f.detection_source == DetectionSource.LLM_ONLY
        )

        elapsed = (datetime.now() - start_time).total_seconds()
        logger.info(
            f"[AUDITOR] ✅ Audit complete in {elapsed:.2f}s | "
            f"Tool findings: {scan_result.tool_finding_count} | "
            f"LLM findings: {scan_result.llm_finding_count}"
        )

        return scan_result

    def _calculate_risk_directly(self, findings: List[VulnerabilityFinding]) -> dict:
        """
        FIX #5: Call calculate_risk_score tool DIRECTLY (no LLM wrapper).

        The tool is pure Python math. No LLM needed.
        """
        logger.info("[AUDITOR] Running deterministic risk calculation")

        findings_json = json.dumps({
            "findings": [
                {
                    "severity": str(f.severity),
                    "category": str(f.category),
                    "detection_source": str(f.detection_source),
                }
                for f in findings
            ]
        })

        try:
            result_str = calculate_risk_score.invoke({
                "findings_json": findings_json
            })
            result = json.loads(result_str)
            logger.info(f"[AUDITOR] Risk calculated: {result}")
            return result

        except Exception as e:
            logger.error(f"[AUDITOR] Risk calculation error: {e}")
            return self._fallback_risk(findings)

    def _fallback_risk(self, findings: List[VulnerabilityFinding]) -> dict:
        """Absolute fallback if tool invocation itself fails."""
        weights = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3, "INFO": 1}
        raw = sum(weights.get(str(f.severity).upper(), 1) for f in findings)
        score = min(100, raw)
        grade = "F" if score >= 75 else "D" if score >= 60 else "C" if score >= 40 else "B" if score >= 20 else "A"
        return {
            "overall_risk_score": score,
            "risk_grade": grade,
            "radar_scores": {
                "authentication": 50, "input_validation": 50,
                "secrets_management": 50, "api_security": 50,
                "dependency_safety": 50, "configuration": 50,
            },
            "finding_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0, "total": len(findings)},
        }

    def _generate_summary_with_agent(
        self,
        repo_url: str,
        risk_score: int,
        risk_grade: str,
        findings: List[VulnerabilityFinding]
    ) -> str:
        """Generate executive summary — LLM is appropriate here (it's writing)."""
        findings_json = json.dumps({
            "findings": [
                {"severity": str(f.severity), "category": str(f.category)}
                for f in findings
            ]
        })

        initial_messages = [{
            "role": "user",
            "content": (
                f"Use generate_executive_summary to write a professional summary. "
                f"repo_url='{repo_url}', risk_score='{risk_score}', "
                f"risk_grade='{risk_grade}', findings_json='{findings_json}'"
            )
        }]

        try:
            result = invoke_agent_with_fallback(
                tools=[generate_executive_summary],
                initial_messages=initial_messages,
                label="auditor_summary",
            )

            messages = result.get("messages", [])
            for msg in reversed(messages):
                msg_type = getattr(msg, "__class__", type(msg)).__name__
                content  = getattr(msg, "content", "")
                if "ToolMessage" in msg_type and content:
                    return content

            # Fallback: use last AI message if tool message not found
            for msg in reversed(messages):
                content = getattr(msg, "content", "")
                if content and len(content) > 50:
                    return content

        except Exception as e:
            logger.error(f"[AUDITOR] Summary generation failed on all providers: {e}")

        return (
            f"SwiftAudit completed security analysis of {repo_url}. "
            f"Risk score: {risk_score}/100 (Grade: {risk_grade}). "
            f"{len(findings)} findings identified."
        )

    def _build_report_jinja2(
        self,
        scan_result: ScanResult,
        findings: List[VulnerabilityFinding],
        metadata: RepoMetadata,
        risk_data: dict,
    ) -> str:
        """
        FIX #7: Build report from Jinja2 template.

        V1 used f-string concatenation across 100+ lines.
        Problem: any None value = ugly 'None' in output.

        V2: Jinja2 template with | default('N/A') filters.
        Template: templates/report.md.j2

        Per Jinja2 docs:
            env = Environment(loader=FileSystemLoader("templates/"))
            template = env.get_template("report.md.j2")
            rendered = template.render(**context)
        """
        logger.info("[AUDITOR] Building report from Jinja2 template...")

        counts = risk_data.get("finding_counts", {})
        radar = scan_result.radar_scores

        # Build detection source breakdown
        tool_counts = {
            "bandit": 0, "semgrep": 0, "secrets": 0, "safety": 0, "llm": 0
        }
        for f in findings:
            src = str(f.detection_source).lower()
            if "bandit" in src:
                tool_counts["bandit"] += 1
            elif "semgrep" in src:
                tool_counts["semgrep"] += 1
            elif "detect" in src:
                tool_counts["secrets"] += 1
            elif "safety" in src:
                tool_counts["safety"] += 1
            else:
                tool_counts["llm"] += 1

        radar_dict = {}
        if radar:
            radar_dict = {
                "authentication": radar.authentication,
                "input_validation": radar.input_validation,
                "secrets_management": radar.secrets_management,
                "api_security": radar.api_security,
                "dependency_safety": radar.dependency_safety,
                "configuration": radar.configuration,
            }

        context = {
            "scan_id": scan_result.scan_id,
            "repo_url": scan_result.repo_url,
            "metadata": metadata,
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"),
            "summary": scan_result.summary or "Security analysis complete.",
            "overall_risk_score": scan_result.overall_risk_score,
            "risk_grade": scan_result.risk_grade,
            "finding_counts": counts,
            "radar_scores": radar_dict,
            "files_analyzed_count": len(scan_result.files_analyzed),
            "scan_duration": (
                f"{scan_result.scan_duration_seconds:.1f}"
                if scan_result.scan_duration_seconds else "N/A"
            ),
            "findings": findings,
            "tool_finding_count": tool_counts,
        }

        try:
            template = self.jinja_env.get_template("report.md.j2")
            rendered = template.render(**context)
            logger.info(f"[AUDITOR] ✅ Jinja2 report rendered: {len(rendered)} chars")
            return rendered

        except Exception as e:
            logger.error(f"[AUDITOR] Jinja2 render failed: {e}")
            # Minimal fallback
            return (
                f"# SwiftAudit Security Report\n\n"
                f"**Repo:** {scan_result.repo_url}\n"
                f"**Risk Score:** {scan_result.overall_risk_score}/100 "
                f"(Grade: {scan_result.risk_grade})\n"
                f"**Total Findings:** {len(findings)}\n\n"
                f"*Report template render failed. See logs.*"
            )

    def _generate_pdf(self, scan_result: ScanResult) -> str:
        """
        Generate PDF using ReportLab — pure Python, zero native dependencies.

        WHY NOT WEASYPRINT:
          WeasyPrint requires libgobject-2.0-0 (GTK) which is not installed on
          Windows by default. Installing GTK on Windows is a 150MB process that
          frequently fails. ReportLab has no C library dependencies and installs
          with a simple `pip install reportlab`.

        LAYOUT:
          Page 1: Cover — repo URL, risk score, grade, scan timestamp
          Page 2: Executive summary + finding counts per severity
          Page 3+: Finding detail cards (one per finding, severity colour-coded)
        """
        if not scan_result.report_markdown:
            return ""

        output_dir = Path(config.REPORTS_OUTPUT_DIR)
        output_dir.mkdir(parents=True, exist_ok=True)
        pdf_path = output_dir / f"{scan_result.scan_id}.pdf"

        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.lib import colors
            from reportlab.lib.units import cm
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.platypus import (
                SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
                HRFlowable, PageBreak, KeepTogether,
            )
            from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT

            # ── Colour palette ──────────────────────────────────
            NAVY     = colors.HexColor("#1d3557")
            BLUE     = colors.HexColor("#457b9d")
            RED      = colors.HexColor("#e63946")
            DARK     = colors.HexColor("#1a1a2e")
            LGREY    = colors.HexColor("#f8f9fa")
            WHITE    = colors.white

            SEV_COLOURS = {
                "CRITICAL": colors.HexColor("#7b0000"),
                "HIGH":     colors.HexColor("#c0392b"),
                "MEDIUM":   colors.HexColor("#e67e22"),
                "LOW":      colors.HexColor("#2980b9"),
                "INFO":     colors.HexColor("#7f8c8d"),
            }

            # ── Styles ───────────────────────────────────────────
            base = getSampleStyleSheet()

            def _style(name, parent="Normal", **kwargs):
                return ParagraphStyle(name, parent=base[parent], **kwargs)

            S_TITLE   = _style("S_TITLE",   "Title",   fontSize=26, textColor=DARK,
                               spaceAfter=6, alignment=TA_CENTER)
            S_SUBTITLE= _style("S_SUB",     "Normal",  fontSize=11, textColor=BLUE,
                               spaceAfter=4, alignment=TA_CENTER)
            S_H1      = _style("S_H1",      "Heading1",fontSize=16, textColor=NAVY,
                               spaceBefore=14, spaceAfter=4)
            S_H2      = _style("S_H2",      "Heading2",fontSize=13, textColor=BLUE,
                               spaceBefore=10, spaceAfter=3)
            S_BODY    = _style("S_BODY",    "Normal",  fontSize=9,  leading=13,
                               spaceAfter=4)
            S_CODE    = _style("S_CODE",    "Code",    fontSize=8,  leading=11,
                               leftIndent=10, spaceAfter=4,
                               backColor=colors.HexColor("#2b2d42"),
                               textColor=colors.HexColor("#edf2f4"))
            S_LABEL   = _style("S_LABEL",   "Normal",  fontSize=8,  textColor=BLUE,
                               spaceBefore=2)
            S_CAPTION = _style("S_CAPTION", "Normal",  fontSize=8,  textColor=colors.grey,
                               alignment=TA_RIGHT)

            doc   = SimpleDocTemplate(
                str(pdf_path), pagesize=A4,
                leftMargin=2*cm, rightMargin=2*cm,
                topMargin=2*cm,  bottomMargin=2*cm,
                title=f"SwiftAudit Report — {scan_result.repo_url}",
            )
            story = []

            # ── Page 1: Cover ────────────────────────────────────
            story.append(Spacer(1, 2*cm))
            story.append(Paragraph("🔒 SwiftAudit v9", S_TITLE))
            story.append(Paragraph("Security Analysis Report", S_SUBTITLE))
            story.append(HRFlowable(width="100%", thickness=2, color=RED, spaceAfter=12))

            repo_display = scan_result.repo_url or "N/A"
            cover_data = [
                ["Repository", repo_display],
                ["Scan ID",    scan_result.scan_id],
                ["Score",      f"{scan_result.overall_risk_score}/100"],
                ["Grade",      scan_result.risk_grade or "N/A"],
                ["Findings",   str(len(scan_result.findings))],
                ["Generated",  datetime.now().strftime("%Y-%m-%d %H:%M UTC")],
            ]
            cover_table = Table(cover_data, colWidths=[4*cm, 13*cm])
            cover_table.setStyle(TableStyle([
                ("FONTSIZE",    (0,0), (-1,-1), 9),
                ("FONTNAME",    (0,0), (0,-1),  "Helvetica-Bold"),
                ("TEXTCOLOR",   (0,0), (0,-1),  NAVY),
                ("BACKGROUND",  (0,0), (-1,-1), LGREY),
                ("ROWBACKGROUNDS", (0,0), (-1,-1), [WHITE, LGREY]),
                ("BOX",         (0,0), (-1,-1), 0.5, colors.lightgrey),
                ("INNERGRID",   (0,0), (-1,-1), 0.25, colors.lightgrey),
                ("TOPPADDING",  (0,0), (-1,-1), 6),
                ("BOTTOMPADDING",(0,0),(-1,-1), 6),
                ("LEFTPADDING", (0,0), (-1,-1), 8),
            ]))
            story.append(cover_table)
            story.append(PageBreak())

            # ── Page 2: Summary + severity breakdown ─────────────
            story.append(Paragraph("Executive Summary", S_H1))
            story.append(HRFlowable(width="100%", thickness=1, color=BLUE, spaceAfter=6))

            summary_text = scan_result.summary or (
                f"Security analysis of {repo_display} completed. "
                f"Risk score: {scan_result.overall_risk_score}/100 "
                f"(Grade: {scan_result.risk_grade}). "
                f"{len(scan_result.findings)} unique findings identified."
            )
            # Wrap long summary lines
            for para in summary_text.split("\n"):
                if para.strip():
                    story.append(Paragraph(para.strip(), S_BODY))
            story.append(Spacer(1, 0.4*cm))

            # Severity counts table
            sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
            for f in scan_result.findings:
                k = str(f.severity).replace("Severity.", "").upper()
                sev_counts[k] = sev_counts.get(k, 0) + 1

            story.append(Paragraph("Finding Severity Breakdown", S_H2))
            sev_data = [["Severity", "Count", "Weight"]] + [
                [sev, str(sev_counts[sev]),
                 {"CRITICAL":"25","HIGH":"15","MEDIUM":"8","LOW":"3","INFO":"1"}[sev]]
                for sev in ("CRITICAL","HIGH","MEDIUM","LOW","INFO")
            ]
            sev_table = Table(sev_data, colWidths=[5*cm, 3*cm, 3*cm])
            sev_style = [
                ("BACKGROUND",   (0,0), (-1,0),  NAVY),
                ("TEXTCOLOR",    (0,0), (-1,0),  WHITE),
                ("FONTNAME",     (0,0), (-1,0),  "Helvetica-Bold"),
                ("FONTSIZE",     (0,0), (-1,-1), 9),
                ("INNERGRID",    (0,0), (-1,-1), 0.25, colors.lightgrey),
                ("BOX",          (0,0), (-1,-1), 0.5, colors.grey),
                ("TOPPADDING",   (0,0), (-1,-1), 5),
                ("BOTTOMPADDING",(0,0), (-1,-1), 5),
                ("LEFTPADDING",  (0,0), (-1,-1), 8),
            ]
            for i, sev in enumerate(("CRITICAL","HIGH","MEDIUM","LOW","INFO"), start=1):
                if sev_counts[sev] > 0:
                    sev_style.append(
                        ("TEXTCOLOR", (0,i), (0,i), SEV_COLOURS[sev])
                    )
                    sev_style.append(
                        ("FONTNAME",  (0,i), (0,i), "Helvetica-Bold")
                    )
            sev_table.setStyle(TableStyle(sev_style))
            story.append(sev_table)
            story.append(PageBreak())

            # ── Pages 3+: Finding detail cards ───────────────────
            story.append(Paragraph("Findings Detail", S_H1))
            story.append(HRFlowable(width="100%", thickness=1, color=BLUE, spaceAfter=8))

            # Sort: CRITICAL first
            sev_order = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}
            sorted_findings = sorted(
                scan_result.findings,
                key=lambda f: sev_order.get(
                    str(f.severity).replace("Severity.","").upper(), 5
                )
            )

            for i, finding in enumerate(sorted_findings, 1):
                sev_str  = str(finding.severity).replace("Severity.", "").upper()
                sev_col  = SEV_COLOURS.get(sev_str, colors.grey)
                cat_str  = str(finding.category).replace("VulnCategory.", "")
                src_str  = str(finding.detection_source).replace("DetectionSource.", "")

                card_elements = []

                # Finding header row
                hdr_data = [[
                    Paragraph(f"#{i} [{sev_str}]", ParagraphStyle(
                        "FH", parent=base["Normal"], fontSize=9,
                        textColor=WHITE, fontName="Helvetica-Bold")),
                    Paragraph(
                        (finding.title or "Untitled")[:90],
                        ParagraphStyle("FT", parent=base["Normal"],
                                       fontSize=9, textColor=WHITE)
                    ),
                ]]
                hdr_table = Table(hdr_data, colWidths=[3*cm, 14*cm])
                hdr_table.setStyle(TableStyle([
                    ("BACKGROUND",   (0,0), (-1,-1), sev_col),
                    ("TOPPADDING",   (0,0), (-1,-1), 5),
                    ("BOTTOMPADDING",(0,0), (-1,-1), 5),
                    ("LEFTPADDING",  (0,0), (-1,-1), 8),
                ]))
                card_elements.append(hdr_table)

                # Metadata row
                meta = f"File: {finding.file_path or 'N/A'}"
                if finding.line_number:
                    meta += f" | Line {finding.line_number}"
                meta += f" | Source: {src_str} | Category: {cat_str}"
                if finding.cwe_id:
                    meta += f" | {finding.cwe_id}"
                card_elements.append(
                    Paragraph(meta, ParagraphStyle(
                        "META", parent=base["Normal"], fontSize=7.5,
                        textColor=BLUE, spaceBefore=2, spaceAfter=2,
                        leftIndent=8,
                    ))
                )

                # Description
                if finding.description:
                    desc = finding.description[:500]
                    card_elements.append(Paragraph(desc, S_BODY))

                # Code snippet
                if finding.code_snippet:
                    snippet = finding.code_snippet[:300]
                    card_elements.append(Paragraph("Code:", S_LABEL))
                    card_elements.append(Paragraph(
                        snippet.replace("<","&lt;").replace(">","&gt;"),
                        S_CODE
                    ))

                # Patch explanation
                if finding.patch_explanation:
                    card_elements.append(Paragraph("Remediation:", S_LABEL))
                    card_elements.append(
                        Paragraph(finding.patch_explanation[:400], S_BODY)
                    )

                card_elements.append(
                    HRFlowable(width="100%", thickness=0.5,
                               color=colors.lightgrey, spaceAfter=6)
                )
                story.append(KeepTogether(card_elements))

            # ── Footer caption ────────────────────────────────────
            story.append(Spacer(1, 0.5*cm))
            story.append(Paragraph(
                f"Generated by SwiftAudit v9 | {datetime.now().strftime('%Y-%m-%d')}",
                S_CAPTION
            ))

            doc.build(story)
            logger.info(f"[AUDITOR] ✅ PDF generated: {pdf_path}")
            return str(pdf_path)

        except ImportError:
            logger.warning(
                "[AUDITOR] reportlab not installed. "
                "Run: pip install reportlab --break-system-packages"
            )
        except Exception as e:
            logger.error(f"[AUDITOR] PDF generation failed: {e}", exc_info=True)

        return ""
