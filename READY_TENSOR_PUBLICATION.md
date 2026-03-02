# SwiftAudit: A Multi-Agent Security Analysis System for GitHub Repositories

## Abstract

SwiftAudit is a multi-agent security analysis system that combines deterministic scanning tools with LLM-powered reasoning to audit any public GitHub repository. Built on LangGraph, the system uses four specialised agents — Navigator, Researcher, Exploiter, and Auditor — that coordinate through shared state to detect vulnerabilities ranging from SQL injection and hardcoded secrets to broken authentication flows and business logic flaws that pattern-matching tools alone cannot find. Results stream to a React dashboard in real time via Server-Sent Events, typically completing a full audit in under two minutes.

---

## 1. Introduction and Motivation

Security auditing is one of the most cognitively demanding tasks in software development. A skilled penetration tester must simultaneously understand code logic, track data flows across files, reason about attacker goals, and produce actionable remediation advice. It is also repetitive at scale — the same classes of vulnerabilities appear in codebase after codebase.

This combination makes it a strong candidate for multi-agent AI: decompose the task into specialist roles, run the expensive parts in parallel, and let deterministic tools handle what they are good at while LLM reasoning handles what they cannot.

SwiftAudit was built to answer one question: **can a multi-agent system perform a useful security audit of an unfamiliar codebase in under two minutes, producing findings a developer can act on immediately?**

The answer, in practice, is yes — with caveats worth discussing honestly.

---

## 2. System Architecture

### 2.1 Orchestration Framework

SwiftAudit uses **LangGraph** as its orchestration framework. The pipeline is a compiled `StateGraph` with four agent nodes connected by directed edges and one conditional routing step.

```
Navigator → Researcher → [conditional] → Exploiter → Auditor
                                    ↘ (no HIGH/CRITICAL) → Auditor
```

LangGraph was chosen over alternatives (CrewAI, AutoGen) for three reasons. First, its explicit graph model makes the data flow easy to reason about and debug. Second, the `TypedDict`-based `ScanState` with `Annotated[List, operator.add]` reducers lets multiple nodes append to shared lists without race conditions. Third, conditional edges allow routing decisions based on runtime data — in SwiftAudit's case, skipping the Exploiter entirely when no high-severity findings justify the LLM cost.

### 2.2 Shared State

All four agents communicate through a single `ScanState` TypedDict. Fields are either:

- **Set once** — `metadata`, `files`, `overall_risk_score` (plain types, last write wins)
- **Accumulated** — `findings`, `agent_logs`, `errors` (declared with `operator.add` so each node appends without overwriting)

This design means each node is a pure function that reads what it needs and returns only the fields it updated. Nodes have no shared mutable state outside of `ScanState`.

### 2.3 Real-Time Streaming

A custom in-process SSE bus (`core/events.py`) lets any agent thread push events to the browser with ~50ms latency. Each scan ID has its own list of per-connection queues. Pipeline threads call `emit(scan_id, event_type, data)` which is non-blocking and thread-safe. A history buffer of 300 events supports late-joining clients (e.g. page refresh mid-scan).

---

## 3. Agent Design

### 3.1 Navigator Agent

**Role:** Repository intake, file selection, parallel content fetching

The Navigator fetches the full recursive file tree from the GitHub API, then scores every file on a 0–100 priority scale using the `score_file_priority` LangChain tool. The scoring function is fully deterministic — it awards points for security-relevant filenames (auth, login, config, .env), path keywords (sql, password, token, upload, admin), source code extensions, and IaC files (Dockerfiles, Terraform, Kubernetes manifests).

The top-scoring files are fetched in parallel using a `ThreadPoolExecutor` with 6 workers. In sequential form (v9), fetching 15 files took 30–45 seconds. Parallel fetching reduced this to 5–8 seconds — a 6× improvement for a pipeline where every second matters.

**Key design decision:** Scoring is deterministic rather than LLM-driven. An LLM-based file scorer was prototyped but discarded — it was slower, occasionally made poor choices, and added an LLM call to a phase that doesn't benefit from reasoning.

### 3.2 Researcher Agent

**Role:** Tool scanning + LLM analysis, finding normalisation and deduplication

The Researcher is the most complex agent. It runs two workstreams concurrently:

**Tool workstream** (parallel subprocesses):
- **Snyk Code** — SAST, finds injection vulnerabilities, XSS, path traversal, hardcoded secrets in source code
- **Trivy** — SCA across 15+ package managers (CVE detection), secrets scanning across all file types, Dockerfile misconfiguration analysis via `--scanners vuln,secret,misconfig`
- **HistoryGuard** — a custom entropy scanner that streams `git log -p` and computes Shannon entropy on every string literal in deleted diff lines. Strings with entropy > 4.5 that are not git SHAs, UUIDs, or MD5s are reported as "zombie secrets" — credentials that were committed and then deleted but remain permanently accessible in git history

**LLM workstream** (parallel thread pool, 4 workers):
High-priority files are chunked using Pygments-based token-aware splitting and sent to the LLM with a Chain-of-Density prompt. The prompt explicitly instructs the model to target logic-level vulnerabilities that scanners cannot find: broken authentication flows (missing checks, wrong order), IDOR (accessing other users' resources without validation), business logic flaws, race conditions, and insecure session management. The model is explicitly told *not* to report issues Snyk and Trivy already cover.

All findings from both workstreams are normalised into `VulnerabilityFinding` Pydantic models and deduplicated. Deduplication uses a combination of file path, line number range, and category matching — the same vulnerability found by both Snyk and the LLM is merged into a single finding with the tool source preferred.

**Key design decision:** Running tool and LLM workstreams concurrently rather than sequentially was the single largest latency improvement. On a 15-file repository, this reduced Researcher time from ~90 seconds to ~45 seconds.

### 3.3 Exploiter Agent

**Role:** Attacker simulation for high-severity findings

The Exploiter only activates when CRITICAL or HIGH findings exist (enforced by LangGraph's conditional edge). For each qualifying finding it calls `generate_exploit_path`, which prompts the LLM to write a realistic red-team simulation: prerequisites, numbered attack steps with target and result, impact statement, attacker profile (Script Kiddie to Nation-State), and a proof-of-concept.

Python PoC code is validated with `ast.parse()` before being included in the output. Syntactically invalid PoC is marked `poc_verified: false` so the UI can warn users clearly.

**Key design decision:** The Exploiter was intentionally scoped to CRITICAL and HIGH findings only. Running it on all findings would triple the LLM cost and produce exploit paths for low-severity issues where the attack surface is not interesting enough to warrant detailed simulation.

### 3.4 Auditor Agent

**Role:** Deterministic risk scoring, radar calculation, executive summary, report assembly

The Auditor calculates the risk score using **pure Python math** with no LLM involvement. Severity weights (CRITICAL=25, HIGH=15, MEDIUM=8, LOW=3, INFO=1) are summed and normalised to 0–100. This deterministic approach was chosen deliberately — an earlier version used an LLM to generate the score, which produced inconsistent results (the same finding set could score 45 on one run and 62 on another).

A six-dimension radar maps each finding category to one of: authentication, input validation, secrets management, API security, dependency safety, or configuration. Each dimension starts at 100 and loses points proportional to the severity of findings in that category.

The executive summary is the one place in the Auditor where an LLM is used — it is genuinely a writing task where model quality matters.

---

## 4. Tool Integration

| Tool | Integration Type | Phase | What It Finds |
|---|---|---|---|
| `score_file_priority` | Custom LangChain `@tool` | Navigator | Security-relevant files in repo |
| Snyk Code CLI | External subprocess | Researcher | Injection, XSS, path traversal, secrets |
| Trivy CLI | External subprocess | Researcher | CVEs, secrets, Dockerfile misconfiguration |
| HistoryGuard | Custom Python class | Researcher | Zombie secrets in git history |
| `analyze_file_for_vulnerabilities` | Custom LangChain `@tool` | Researcher | Logic flaws, broken auth, IDOR |
| `generate_exploit_path` | Custom LangChain `@tool` | Exploiter | Attack simulation with PoC code |
| `calculate_risk_score` | Custom LangChain `@tool` | Auditor | Risk score and radar dimensions |
| `generate_executive_summary` | Custom LangChain `@tool` | Auditor | Professional summary prose |

---

## 5. LLM Reliability: The 12-Provider Fallback Chain

A security scanner that silently fails mid-scan because Groq is rate-limited is not useful. SwiftAudit implements a 12-provider fallback chain managed by `utils/llm_client.py`.

Every LLM call goes through `call_llm()` which iterates the provider chain in priority order. On any exception — rate limit (429), auth error (401), server error (500), timeout — it logs the failure and immediately retries with the next provider using the identical prompt. The prompt is stateless so no partial results need to be carried.

Providers are initialised once at module load. Any provider whose API key is missing or whose client fails to initialise is silently excluded from the chain. The chain is logged at startup so it is always clear which providers are available.

Provider priority (fastest/most capable first):

1. Groq — llama-3.1-70b (fastest, generous free tier)
2. Gemini 2.5 Flash
3. GitHub Models — gpt-4.1
4. SambaNova — Llama-4-Maverick
5. Mistral Large
6. Gemini 2.0 Flash (second key)
7. Scaleway — gpt-oss-120b
8. NVIDIA — Nemotron-30B
9. OpenRouter — Nemotron-30B (free tier)
10. Novita — Llama-3.3-70B
11. Fireworks — Llama-405B
12. Cloudflare Workers AI — Llama-3.2-3B (emergency)

In practice, with Groq + two Gemini keys configured, no scan in development ever fell past provider 3.

---

## 6. Results and Example Findings

The following is a representative set of findings from scanning [DSVW](https://github.com/stamparm/DSVW), a deliberately vulnerable Python web application:

| Finding | Severity | Source | CVSS |
|---|---|---|---|
| SQL Injection via unsanitised user input | CRITICAL | Snyk Code | 9.8 |
| OS Command Injection via shell=True | CRITICAL | Snyk Code | 10.0 |
| Reflected XSS — unescaped user input | HIGH | LLM | 7.4 |
| Path Traversal — arbitrary file read | HIGH | Snyk Code | 7.5 |
| Werkzeug 0.9.6 — CVE-2023-25577 | HIGH | Trivy | 7.5 |

For the SQL injection finding, the Exploiter generated a three-step attack simulation showing exactly how an attacker would use a UNION-based payload to exfiltrate the full user database, with a working Python proof-of-concept and a verified `ast.parse()` result.

The full output for this scan is available in [`examples/sample_output.json`](examples/sample_output.json).

---

## 7. Design Decisions and Lessons Learned

**Deterministic over LLM where possible.** File scoring, risk calculation, and severity weighting are all pure Python. LLMs were used where reasoning genuinely helps (logic vulnerability detection, exploit simulation, summary writing) and avoided where math or rules are sufficient. This improved consistency and reduced latency.

**Parallel everything.** The single biggest performance gain came from parallelising file fetching, scanner execution, and LLM analysis simultaneously rather than sequentially. A 6× improvement in fetching time and a 2× improvement in analysis time came purely from `ThreadPoolExecutor` — no architectural changes required.

**SSE over polling.** An earlier version polled the `/status` endpoint every two seconds. Switching to SSE cut perceived latency dramatically — the browser now shows findings the instant they are found rather than on the next poll interval.

**The Exploiter routing decision.** Routing the Exploiter conditionally (only when CRITICAL/HIGH findings exist) was important. In clean repositories, skipping the Exploiter saves 20–40 seconds and several LLM calls on findings that don't warrant detailed attack simulation.

**LLM false positives are real.** The LLM analysis workstream produces false positives, particularly in well-written code where the model finds theoretical issues that require multiple unlikely conditions to exploit. Tagging every finding with `detection_source` (snyk_code, trivy, llm_only) and displaying this prominently in the UI lets users apply appropriate skepticism to LLM findings versus deterministic tool findings.

---

## 8. Limitations

- **Private repositories** are not supported without a GitHub token with appropriate permissions
- **Very large repositories** (>500 files) are scanned on a top-15 selection only; deep coverage requires raising `MAX_FILES_TO_ANALYZE`
- **LLM findings require human review** — the system explicitly tags these and the UI communicates their AI-assisted nature
- **First-run Trivy setup** requires downloading a ~200MB CVE database; subsequent scans use the cached copy

---

## 9. Conclusion

SwiftAudit demonstrates that a multi-agent architecture can meaningfully augment traditional security scanning. The LangGraph pipeline coordinates four specialised agents cleanly, the fallback chain makes the system resilient to LLM provider failures, and the parallel execution design keeps the end-to-end runtime practical.

The most important lesson from building this system is that multi-agent AI works best when each agent has a genuinely distinct role with a clear boundary — not just a different name. Navigator, Researcher, Exploiter, and Auditor each do something the others cannot, and the coordination overhead of passing state between them is justified by the specialisation.

---

## 10. Repository

**GitHub:** [https://github.com/10486-JosephMutua/SwiftAudit](https://github.com/10486-JosephMutua/SwiftAudit)

The repository contains complete source code, setup instructions, a `.env.example` with all configuration options, and a sample scan output in `examples/sample_output.json`.

---

## References

- LangGraph Documentation — https://langchain-ai.github.io/langgraph/
- Snyk Code Documentation — https://docs.snyk.io/scan-using-snyk/snyk-code
- Trivy Documentation — https://aquasecurity.github.io/trivy/
- OWASP Top 10 (2021) — https://owasp.org/Top10/
- CWE/SANS Top 25 — https://cwe.mitre.org/top25/
- Shannon, C.E. (1948). A Mathematical Theory of Communication. *Bell System Technical Journal*
