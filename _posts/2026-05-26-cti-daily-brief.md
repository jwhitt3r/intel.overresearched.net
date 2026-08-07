---
layout: post
title:  "CTI Daily Brief: 2026-05-26 - LLM-driven post-exploitation observed; Tycoon 2FA AiTM persists post-takedown"
date:   2026-05-30 21:11:39 +0000
description: "Sysdig TRT documents the first AI-agent-driven intrusion in the wild (CVE-2026-39987 in marimo to Postgres exfil in under one hour). Elastic Security Labs publishes Tycoon 2FA AiTM detections for Entra ID and Google Workspace, confirming the kit remains active despite the March 2026 takedown."
category: daily
tags: [cti, daily-brief, storm-1747, tycoon-2fa, cve-2026-39987]
classification: TLP:CLEAR
reporting_period: "2026-05-26"
generated: "2026-05-30"
draft: true
severity: high
report_count: 3
sources:
  - Sysdig
  - Elastic Security Labs
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-05-26 (24h) | TLP:CLEAR | 2026-05-30 |

## 1. Executive Summary

Three reports were ingested for 2026-05-26 from two sources (Sysdig and Elastic Security Labs), with two rated **HIGH** and one **INFO**. The day's signal is concentrated on two operational themes: AI-driven post-exploitation tradecraft and the durability of adversary-in-the-middle (AiTM) phishing infrastructure. Sysdig's Threat Research Team published the first documented case of a large language model agent driving real-time post-compromise actions, pivoting from CVE-2026-39987 on a marimo notebook to full PostgreSQL exfiltration in under one hour using Cloudflare Workers as an egress pool. Elastic Security Labs released cross-platform detection engineering for Tycoon 2FA, the Storm-1747-attributed Phishing-as-a-Service kit that bypasses MFA on Entra ID and Google Workspace and has resumed operations despite the March 2026 Microsoft/Europol takedown. No CISA KEV additions, ransomware leak posts, or nation-state advisories appeared in the 2026-05-26 ingest. No AI-generated correlation trends or correlation batches were produced for this reporting period.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 0 | — |
| 🟠 **HIGH** | 2 | Sysdig LLM-agent-driven intrusion (CVE-2026-39987); Tycoon 2FA AiTM detection (Storm-1747) |
| 🟡 **MEDIUM** | 0 | — |
| 🟢 **LOW** | 0 | — |
| 🔵 **INFO** | 1 | Sysdig MCP server / Bedrock DSPM product post |

## 3. Priority Intelligence Items

### 3.1 LLM agent drives end-to-end intrusion from marimo CVE to PostgreSQL dump in under one hour

**Source:** [Sysdig](https://webflow.sysdig.com/blog/ai-agent-at-the-wheel-how-an-attacker-used-llms-to-move-from-a-cve-to-an-internal-database-in-4-pivots)

On 2026-05-10 the Sysdig Threat Research Team observed an intrusion in which the post-exploitation phase was executed in real time by a large language model agent rather than a pre-built playbook — described by Sysdig as the first AI-agent-driven intrusion they have captured. Entry was via CVE-2026-39987 on an internet-reachable marimo notebook (WebSocket terminal endpoint `/terminal/ws`). The actor harvested cloud credentials from the compromised host (`/app/.env*`, `/etc/environment`, `/proc/<pid>/environ`, `~/.aws/credentials`), then replayed them through a fanned-out egress pool to call `secretsmanager:GetSecretValue` against an SSH-key secret. The retrieved key drove eight short SSH sessions against a downstream bastion that dumped the schema and full contents of an internal PostgreSQL database in under two minutes. Twelve cloud API calls were spread across eleven distinct Cloudflare Workers points-of-presence in a 22-second burst — a structural signature of Workers being used as a per-request egress pool to defeat per-source-IP detection.

Sysdig's reporting maps the activity to MITRE ATT&CK techniques **T1078** (Valid Accounts), **T1003** (OS Credential Dumping), **T1071.001** (Application Layer Protocol: WebSocket), and **T1105** (Ingress Tool Transfer). Affected technology: marimo notebook (`<=` vulnerable version per CVE-2026-39987), AWS Secrets Manager workflows reachable from compromised hosts, and SSH bastion architectures that trust long-lived secrets stored in AWS.

#### Indicators of Compromise
```
Source IP (initial WebSocket): 157.66.54[.]26
Initial access vector:         WebSocket connection to /terminal/ws on vulnerable marimo notebook
CVE:                           CVE-2026-39987 (marimo terminal RCE)
Egress infrastructure:         Cloudflare Workers (11+ distinct PoP IPs in 22s burst)
Credential targets:            /app/.env*, /etc/environment, /proc/<pid>/environ, ~/.aws/credentials
AWS calls of interest:         sts:GetCallerIdentity, secretsmanager:GetSecretValue
```

> **SOC Action:** (1) Inventory and patch all marimo notebook deployments against CVE-2026-39987; remove notebook web/terminal endpoints from public exposure or front them with auth-aware proxies. (2) Build a CloudTrail/GuardDuty detection for short-window `secretsmanager:GetSecretValue` bursts where the same role/principal is called from a high diversity of source IPs (Cloudflare Workers ASN 13335) within 60 seconds — this is the "fanned-out egress pool" signature. (3) Alert on `sts:GetCallerIdentity` followed within minutes by `secretsmanager:GetSecretValue` against SSH-key-bearing secrets from non-baseline networks. (4) Rotate any SSH private keys stored in Secrets Manager that are reachable from internet-exposed compute, and enforce short-lived certificate-based SSH (e.g., AWS SSM, Teleport, Vault SSH-CA) on bastion hosts.

### 3.2 Tycoon 2FA AiTM kit remains active after March 2026 takedown — detection guidance for Entra ID and Google Workspace

**Source:** [Elastic Security Labs](https://www.elastic.co/security-labs/tycoon-2fa-aitm-detection-engineering)

Elastic Security Labs (Samir Bousseaden, Terrance DeJesus) published cross-platform detection engineering for Tycoon 2FA, the Phishing-as-a-Service kit attributed by Microsoft Threat Intelligence to **Storm-1747**. First observed in August 2023, the kit operates as a reverse proxy that intercepts post-MFA session tokens for Microsoft 365 and Google Workspace. A coordinated takedown in March 2026 led by Microsoft and Europol (with Cloudflare, SpyCloud, eSentire and others) seized over 300 domains, but operators adapted within weeks; by late April 2026 eSentire documented campaigns pairing Tycoon tradecraft with OAuth device code phishing. The kit remains the top entry on ANY.RUN's malware trends tracker, and at its peak accounted for roughly 62% of phishing attempts blocked by Microsoft, reaching 500,000+ organisations monthly.

Two structural variants are in active rotation: (a) WebSocket AiTM (the classic Tycoon flow, JavaScript client speaking Socket.IO back to C2 while proxying victim auth in real time), and (b) Microsoft-only device-code-grant abuse, where the kit relay obtains a device code from `oauth2/devicecode` using the Microsoft Authentication Broker client ID `29d9ed98-a469-4536-ade2-f981bc1d605e`, lures the victim to authenticate at `microsoft.com/devicelogin`, then exchanges the code for access/refresh tokens. Evasion includes IP-based researcher filtering against cloud/hosting providers via `api.ipapi.is` (provider names stored as reversed strings to evade static analysis), CAPTCHA gates, browser fingerprinting, and multi-layer redirect chains. Phishing lures use links and QR codes embedded in PDF, SVG, HTML and PPTX attachments.

MITRE ATT&CK techniques referenced by the report: **T1566** (Phishing), **T1071.001** (Application Layer Protocol: Web Protocols — Socket.IO/WebSocket C2), and **T1189**-tagged Session Token Collection. Affected platforms: Microsoft Entra ID, Microsoft 365, Google Workspace.

> **SOC Action:** (1) Block or alert on Entra ID device-code grants where the client app is the Microsoft Authentication Broker (`29d9ed98-a469-4536-ade2-f981bc1d605e`) and the sign-in originates from a residential/VPN/unusual ASN — pair with Conditional Access to require compliant devices for device-code flows. (2) Hunt sign-in logs for token issuance immediately followed by impossible-travel or session replay from a different ASN within minutes (AiTM session-cookie replay signature). (3) Apply Elastic's published detection rules for Entra ID and Google Workspace (linked in the report) and enable session-bound tokens / Token Protection in Entra ID for high-value identities. (4) Mail-flow: block or quarantine PDF/SVG/HTML/PPTX attachments containing outbound links and QR codes to newly registered or low-reputation domains; enable URL detonation for SVG and HTML.

### 3.3 Sysdig MCP server on Amazon Bedrock — vendor product post (INFO)

**Source:** [Sysdig](https://webflow.sysdig.com/blog/sysdig-mcp-server-on-amazon-bedrock-ai-powered-dspm-in-action)

Sysdig published a product walkthrough describing its MCP server (available on AWS Marketplace) hosted as a Bedrock AgentCore Runtime, enabling foundation-model agents to query Sysdig Secure for DSPM findings, runtime detections, and Kubernetes posture data. No threat intelligence content; included here for completeness as the only INFO-rated item in the 2026-05-26 ingest.

> **SOC Action:** No defensive action required. Teams evaluating agentic security workflows on AWS Bedrock may review for architectural reference.

## 4. AI-Identified Correlation Trends

No AI-identified correlation trends or correlation batches were generated for the 2026-05-26 reporting period. With only three reports ingested and two distinct themes, the pipeline did not produce a correlation cycle for this date. The two priority items are nonetheless thematically adjacent — both showcase attacker abuse of legitimate cloud and identity infrastructure (Cloudflare Workers as egress; Microsoft Authentication Broker device-code flow) to defeat per-source and per-credential controls — but this is editorial observation, not a pipeline-derived trend.

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| — | No data available for this period | No correlation batches produced for 2026-05-26 |

## 5. Trending Entities (Pipeline-Wide)

The 2026-05-26 ingest itself surfaced only one named threat actor (**Storm-1747**) and one named malware family (**Tycoon 2FA**). For situational context, the most-referenced entities across the broader pipeline (May 2026 to date) are listed below — note these are pipeline-wide totals, not specific to 2026-05-26.

### Threat Actors
- **Qilin** (83 reports) — ransomware operator, sustained leak-site activity through May
- **Akira** (74 reports) — ransomware operator, continued double-extortion campaigns
- **The Gentlemen** (63 reports) — ransomware brand prominent on leak aggregators
- **DragonForce** (33 reports) — ransomware operator
- **ShinyHunters** (33 reports) — data-theft/extortion actor
- **Storm-1747** (1 report on 2026-05-26) — Microsoft-tracked operator of the Tycoon 2FA PhaaS kit (this brief)

### Malware Families
- **RansomLook** (127 reports) — leak-site monitoring source (high count reflects feed cadence, not infections)
- **Akira ransomware** / **Akira** (38 + 25 reports) — ransomware payload
- **Tox1 / Tox** (31 + 17 reports) — ransomware-related family
- **The Gentlemen** (15 reports) — ransomware payload tied to the same-named actor
- **Tycoon 2FA** (1 report on 2026-05-26) — AiTM Phishing-as-a-Service kit (this brief)

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| Sysdig | 2 | [link](https://webflow.sysdig.com/blog/ai-agent-at-the-wheel-how-an-attacker-used-llms-to-move-from-a-cve-to-an-internal-database-in-4-pivots) | One HIGH threat research report (LLM-driven intrusion) plus one INFO product post |
| Elastic Security Labs | 1 | [link](https://www.elastic.co/security-labs/tycoon-2fa-aitm-detection-engineering) | HIGH detection-engineering report on Tycoon 2FA AiTM |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Patch marimo notebook deployments against CVE-2026-39987 and remove public exposure of notebook terminal endpoints. The Sysdig case showed a full end-to-end intrusion (initial access → cloud creds → SSH-key retrieval → PostgreSQL exfil) inside one hour.
- 🟠 **SHORT-TERM:** Deploy detections for Cloudflare-Workers-style fanned-out egress against AWS APIs — short-window `secretsmanager:GetSecretValue` bursts from one principal across many distinct ASN-13335 IPs are a high-confidence signature of agent- or workflow-driven credential abuse.
- 🟠 **SHORT-TERM:** Apply Elastic's published Tycoon 2FA detection rules to Entra ID and Google Workspace sign-in telemetry; restrict OAuth device-code grants for the Microsoft Authentication Broker client (`29d9ed98-a469-4536-ade2-f981bc1d605e`) via Conditional Access and enable Token Protection for privileged identities.
- 🟡 **AWARENESS:** Brief SOC and identity teams that the March 2026 Tycoon 2FA takedown is not durable — operators rebuilt within weeks and the kit is again the most-trafficked AiTM platform. Treat post-MFA session-cookie theft (not credential theft) as the primary phishing failure mode.
- 🟢 **STRATEGIC:** Begin treating "AI agent in the loop" as a near-term post-exploitation reality, not a forecast. Detection programs should focus on behavioural and tempo signatures (request fan-out, decision latency, multi-cloud-region calls from a single role) rather than per-tool or per-payload signatures.

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 3 reports processed across 0 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
