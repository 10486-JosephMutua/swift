# Agent Roles and Responsibilities

SwiftAudit is built as a four-agent pipeline orchestrated by LangGraph.
Each agent has a single, clearly defined responsibility. They communicate
through a shared `ScanState` TypedDict — no agent writes to another agent's
fields directly.

---

## Agent 1 — Navigator
**File:** `agents/navigator.py`
**Role:** Repository intake, file selection, and parallel content fetching

The Navigator is the entry point of the pipeline. It receives the GitHub
repository URL and is responsible for:

- Fetching the full recursive file tree from the GitHub API
- Scoring every file on a 0–100 security relevance scale using
  deterministic rules (file name, path keywords, extension, IaC patterns)
- Selecting the top-priority files for deep analysis
- Fetching file contents in parallel (6 concurrent workers) via the
  GitHub Contents API

**Inputs from ScanState:** `repo_url`, `github_token`
**Outputs to ScanState:** `metadata`, `files`
**Tool used:** `score_file_priority` (LangChain `@tool`)

---

## Agent 2 — Researcher
**File:** `agents/researcher.py`
**Role:** Vulnerability discovery — tool scanning and LLM analysis

The Researcher is the most complex agent. It runs two workstreams
concurrently and merges their findings:

**Workstream 1 — Deterministic tool scanners:**
- Snyk Code (SAST) — injection, XSS, path traversal, secrets
- Trivy (SCA + secrets + Dockerfile misconfig) — CVEs across 15+ package managers
- HistoryGuard — Shannon entropy analysis on `git log` to find zombie secrets

**Workstream 2 — LLM analysis (4 parallel workers):**
- Sends high-priority files to the LLM with a Chain-of-Density prompt
- Targets logic-level vulnerabilities scanners cannot find:
  broken auth, IDOR, business logic flaws, race conditions

All findings are normalised to `VulnerabilityFinding` Pydantic models
and deduplicated before passing forward.

**Inputs from ScanState:** `files`, `repo_url`
**Outputs to ScanState:** `findings`, `tool_finding_count`, `llm_finding_count`
**Tool used:** `analyze_file_for_vulnerabilities` (LangChain `@tool`)

---

## Agent 3 — Exploiter
**File:** `agents/exploiter.py`
**Role:** Attack simulation for high-severity findings

The Exploiter only activates when CRITICAL or HIGH findings exist
(enforced by LangGraph's conditional routing edge). For each qualifying
finding it generates:

- Step-by-step attacker simulation with prerequisites and impact
- Attacker profile (Script Kiddie → Nation-State)
- Proof-of-concept code (Python PoC validated with `ast.parse()`)

This agent is intentionally scoped to CRITICAL/HIGH only — running it
on all findings would waste LLM calls on low-severity issues that don't
warrant detailed attack simulation.

**Inputs from ScanState:** `findings`
**Outputs to ScanState:** enriched `findings` with `exploit_path` attached
**Tool used:** `generate_exploit_path` (LangChain `@tool`)

---

## Agent 4 — Auditor
**File:** `agents/auditor.py`
**Role:** Risk scoring, radar calculation, executive summary, report assembly

The Auditor synthesises all findings into a final report:

- **Risk score (0–100):** Deterministic Python math — severity weights
  summed and normalised. No LLM involved (earlier LLM-based scoring
  produced inconsistent results on identical inputs).
- **Letter grade (A–F):** Threshold-based from the score.
- **6-dimension radar:** Maps findings to authentication, input validation,
  secrets management, API security, dependency safety, configuration.
- **Executive summary:** The one place in the Auditor where an LLM is
  used — it is a writing task where model quality matters.
- **Markdown report:** Assembled via Jinja2 template.

**Inputs from ScanState:** `findings`, `metadata`, `files`
**Outputs to ScanState:** `overall_risk_score`, `risk_grade`, `radar_scores`,
  `summary`, `report_markdown`, `status`
**Tools used:** `calculate_risk_score`, `generate_executive_summary`

---

## How Agents Communicate

Agents do not call each other directly. All communication goes through
the shared `ScanState` TypedDict defined in `core/graph_state.py`.

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐     ┌─────────┐
│  Navigator  │────▶│  Researcher  │────▶│  Exploiter  │────▶│ Auditor │
└─────────────┘     └──────────────┘     └─────────────┘     └─────────┘
       │                   │                    │                  │
       └───────────────────┴────────────────────┴──────────────────┘
                               ScanState (shared)
```

**Conditional routing:** After the Researcher completes, LangGraph checks
whether any CRITICAL or HIGH findings exist. If yes → Exploiter → Auditor.
If no → Auditor directly (skipping Exploiter to save time and LLM cost).

---

## Supporting Modules (not agents)

These modules support the agents but are not agents themselves:

| Module | Role |
|---|---|
| `core/pipeline.py` | LangGraph graph definition and scan lifecycle management |
| `core/scanners.py` | Subprocess runner for Snyk and Trivy CLI tools |
| `core/events.py` | In-process SSE bus for real-time browser streaming |
| `utils/llm_client.py` | 12-provider LLM fallback engine |
| `utils/github_fetcher.py` | Parallel GitHub API file fetcher |
| `agents/history_guard.py` | Git history entropy scanner (used by Researcher) |
| `tools/security_tools.py` | LangChain @tool definitions used by agents |