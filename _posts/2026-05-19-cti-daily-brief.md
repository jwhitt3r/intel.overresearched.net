---
layout: post
title:  "CTI Daily Brief: 2026-05-19 - ChromaDB max-severity RCE, GitHub breach claimed by TeamPCP, Microsoft seizes Fox Tempest malware-signing service"
date:   2026-05-20 20:05:15 +0000
description: "Critical unauthenticated RCE in ChromaDB (CVE-2026-45829) impacts the AI vector-database ecosystem. TeamPCP claims theft of ~4,000 internal GitHub repositories. Microsoft DCU disrupts Fox Tempest malware-signing-as-a-service tied to Rhysida, Akira, INC and Qilin ransomware. Safepay continues high-volume EU/US victim postings."
category: daily
tags: [cti, daily-brief, teampcp, fox-tempest, safepay, chromadb, cve-2026-45829]
classification: TLP:CLEAR
reporting_period: "2026-05-19"
generated: "2026-05-20"
draft: true
severity: critical
report_count: 7
sources:
  - BleepingComputer
  - RansomLook
  - SANS
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-05-19 (24h) | TLP:CLEAR | 2026-05-20 |

## 1. Executive Summary

Seven reports were processed across two correlation batches in the last 24 hours, dominated by technology- and cloud-sector compromise themes. The defining item is **CVE-2026-45829**, a maximum-severity unauthenticated RCE in the ChromaDB Python/FastAPI vector database; HiddenLayer reports roughly 73% of internet-exposed instances are still vulnerable and the maintainer has not confirmed a fix. Microsoft's Digital Crimes Unit disrupted the **Fox Tempest** malware-signing-as-a-service operation, revoking over 1,000 fraudulent Azure Artifact Signing certificates that had been used to sign Oyster, Lumma Stealer, Vidar and Rhysida/Akira/INC/Qilin/BlackByte ransomware payloads. The hacker group **TeamPCP** claims to have exfiltrated roughly 4,000 internal GitHub source-code repositories and is auctioning the data on a breach forum. Ransomware leak-site activity remained high, with Safepay posting nine victims in the last seven days. No CISA KEV additions were captured in today's pipeline.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 1 | ChromaDB CVE-2026-45829 unauthenticated RCE |
| 🟠 **HIGH** | 3 | GitHub/TeamPCP breach; Microsoft Fox Tempest takedown; Safepay leak-site activity |
| 🟡 **MEDIUM** | 1 | Inc Ransom leak-site infrastructure update |
| 🟢 **LOW** | 0 | — |
| 🔵 **INFO** | 2 | SANS ISC Stormcast; Discord E2EE rollout |

## 3. Priority Intelligence Items

### 3.1 ChromaDB CVE-2026-45829 — Maximum-Severity Unauthenticated RCE in AI Vector Database

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/max-severity-flaw-in-chromadb-for-ai-apps-allows-server-hijacking/)

HiddenLayer disclosed a maximum-severity flaw in ChromaDB's Python FastAPI server logic. A vulnerable endpoint marked as authenticated allows attackers to embed model settings **before** the authentication check fires — the server fetches and executes the attacker-supplied model from Hugging Face, then returns a 500 after the payload has already run. The flaw was introduced in ChromaDB 1.0.0 and was unpatched as of 1.5.8; version 1.5.9 was released two weeks ago but the maintainer has not confirmed whether the issue is fixed. The PyPI package sees nearly 14 million monthly downloads. Shodan queries indicate ~73% of internet-exposed instances are running a vulnerable version. Rust front-end deployments and local-only deployments are not affected.

**Affected products / sectors:** ChromaDB Python/FastAPI ≥ 1.0.0, ≤ 1.5.8 (status of 1.5.9 unconfirmed); AI / ML platforms, agentic AI back-ends, RAG pipelines.

**MITRE ATT&CK:** T1190 (Exploit Public-Facing Application), T1204.006 (User Execution: Malicious File), T1064 (Scripting).

> **SOC Action:** Inventory ChromaDB deployments via internal asset DB and external attack-surface tools; query Shodan/Censys for `chromadb` banners across owned ranges. Immediately restrict the ChromaDB API port at firewall/security-group level so it is not reachable from the public internet. Where the Python server must remain network-reachable, place it behind an authenticating reverse proxy that enforces auth **before** the request hits the API. Scan all ML model artifacts before runtime and disable `trust_remote_code` for untrusted Hugging Face models. Track the 1.5.9 advisory and apply the patched release as soon as the maintainer confirms remediation; in the interim treat any 500 response on `/api/.../...` model-loading endpoints as a potential exploitation indicator.

### 3.2 GitHub Investigates Internal-Repository Breach Claimed by TeamPCP

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/github-investigates-internal-repositories-breach-claimed-by-teampcp/)

TeamPCP is advertising the contents of approximately 4,000 GitHub **internal** code repositories on the Breached hacking forum, demanding a minimum of $50,000 and threatening a free leak if no buyer emerges. GitHub confirmed it is "investigating unauthorized access to GitHub's internal repositories" but says it currently has no evidence customer data stored outside those internal repos was affected. TeamPCP has a documented history of developer-platform supply-chain compromises across GitHub, PyPI, NPM and Docker, including March's Trivy compromise that cascaded into Aqua Security images and the Checkmarx KICS project, and the LiteLLM Python library compromise that deployed the "TeamPCP Cloud Stealer" infostealer to tens of thousands of devices. The same group has been linked to the "Mini Shai-Hulud" supply-chain campaign and previously advertised Mistral AI source code stolen from compromised CI/CD credentials.

**Affected products / sectors:** GitHub (internal infrastructure); downstream impact possible for any organisation consuming GitHub-distributed tooling, GitHub Actions, or GitHub-hosted services.

**MITRE ATT&CK:** T1195.002 (Supply Chain Compromise: Compromise Software Supply Chain), T1078 (Valid Accounts), T1567 (Exfiltration Over Web Service).

> **SOC Action:** Treat GitHub-distributed artefacts and Actions runners as a heightened-risk supply-chain source until GitHub publishes scope. Audit CI/CD secrets stored in GitHub for rotation candidates (PATs, OIDC trust relationships, deploy keys, npm/PyPI/Docker publish tokens) and rotate any TeamPCP could plausibly resell. Pin all third-party Actions to commit SHA rather than tag, and enable required signed commits where feasible. Review egress logs from build infrastructure to `breached[.]*` forum mirrors, paste sites and known TeamPCP exfil tooling; sweep developer endpoints for "TeamPCP Cloud Stealer" / LiteLLM-implant IOCs from prior reporting.

### 3.3 Microsoft Disrupts Fox Tempest Malware-Signing-as-a-Service Operation

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/cybercrime-service-disrupted-for-abusing-microsoft-platform-to-sign-malware/)

Microsoft's Digital Crimes Unit, with industry partners, disrupted **Fox Tempest** — a financially motivated MSaaS operation that abused **Azure Artifact Signing** (formerly Trusted Signing) to issue more than 1,000 short-lived code-signing certificates across hundreds of fraudulent Azure tenants and subscriptions. The operators are assessed to have used stolen US/Canadian identities to pass identity verification. Microsoft seized `signspace[.]cloud`, took hundreds of associated VMs offline, blocked supporting infrastructure, revoked the 1,000+ certificates, and unsealed a complaint in the SDNY naming **Vanilla Tempest** (INC Ransomware affiliates) as a co-conspirator. Other named consumers of the service include **Storm-0501**, **Storm-2561**, and **Storm-0249**. Signed payloads observed include Oyster, Lumma Stealer, Vidar and ransomware from **Rhysida, Akira, INC, Qilin and BlackByte**. A documented kill-chain example: a falsely named Microsoft Teams installer drops a loader, which installs signed Oyster, which deploys Rhysida ransomware.

**Affected products / sectors:** Windows endpoints relying on Authenticode trust; impersonated software brands include Microsoft Teams, AnyDesk, PuTTY, Webex; cross-sector ransomware impact.

**MITRE ATT&CK:** T1553.002 (Subvert Trust Controls: Code Signing), T1204 (User Execution), T1078.004 (Valid Accounts), T1036.001 (Masquerading: Invalid Code Signature), T1496 (Resource Hijacking).

#### Indicators of Compromise
```
Seized domain: signspace[.]cloud
Impersonated installers: Microsoft Teams, AnyDesk, PuTTY, Webex
Loader → Implant chain: <signed loader> → Oyster → Rhysida
Associated malware: Oyster, Lumma Stealer, Vidar, Akira, INC, Qilin, BlackByte, Rhysida
Threat actors: Fox Tempest (operator); Vanilla Tempest, Storm-0501, Storm-2561, Storm-0249 (consumers)
```

> **SOC Action:** Hunt EDR telemetry for signed binaries impersonating Microsoft Teams, AnyDesk, PuTTY or Webex that were installed outside your sanctioned software-distribution path (SCCM/Intune/JAMF/managed installers). Pivot on Authenticode signer name and serial against Microsoft's revocation list once published; treat any binary still trusting a revoked Fox Tempest certificate as suspicious. Block `signspace[.]cloud` and any sibling infrastructure Microsoft publishes. Hunt for Oyster loader behaviour (scheduled task creation, `rundll32` of unsigned DLL from `%PROGRAMDATA%`/`%APPDATA%`, beaconing to recently-registered domains) and for Rhysida pre-encryption staging (RDP lateral movement, AnyDesk install, mass file enumeration). Update SOC playbooks for INC/Rhysida/Qilin/Akira/BlackByte to assume code-signed initial access is now plausible.

### 3.4 Safepay Ransomware — Continued High-Volume Victim Postings

**Source:** [RansomLook](https://www.ransomlook.io//group/safepay)

Safepay's leak site posted nine new victims in the last 7 days and 26 in the last 30, with a fresh post on 2026-05-19 naming `olipes.com` (a Spain-headquartered independent manufacturer founded in 1993). Recent victim mix is geographically and sectorally broad: a German transportation operator (`berlinmobil.de`), a German dermatology clinic (`hautarzt-budihardja.de`), a UK print services SME (`printroom.co.uk`), a US county government (`harrisoncountywv.com`), an Italian-language news outlet, an IT services SME (`adlan.com`), and others. Most of the group's onion infrastructure is currently down (1/13 services degraded — only the primary `safepaypfxntwixwjr...onion` leak site shows 100% uptime over 30 days); average platform uptime is ~12%. Reported contact email: `VanessaCooke94@protonmail.com`. Ransom note artefacts: `readme_safepay.txt`, `readme_safepay_ascii.txt`.

**Affected products / sectors:** SMEs across manufacturing, transportation, healthcare, professional services, local government — primarily EU (DE, ES, UK, IT) with US municipal exposure.

**MITRE ATT&CK:** T1566 (Phishing) per ingested entity data; T1486 (Data Encrypted for Impact) implied by leak-site model.

#### Indicators of Compromise
```
Ransom notes: readme_safepay.txt, readme_safepay_ascii.txt
Contact email: VanessaCooke94[at]protonmail[.]com
Leak site (active): hxxp[://]safepaypfxntwixwjrlcscft433ggemlhgkkdupi2ynhtcmvdgubmoyd[.]onion/
Recently named victim domain: olipes[.]com
```

> **SOC Action:** Deploy file-system detections for the literal filenames `readme_safepay.txt` and `readme_safepay_ascii.txt` across endpoint and file-server telemetry; trigger high-severity alerts on any write of these names outside SOC-managed test paths. Block outbound resolution of `VanessaCooke94@protonmail.com` in mail-flow rules and add the address to insider-risk allow-list exclusions. For organisations matching the victim profile (EU SMEs in manufacturing/healthcare/local government), prioritise EDR coverage on internet-facing RDP, VPN, and Citrix gateways and confirm offline, immutable backups exist for crown-jewel data.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Ransomware groups leveraging malware-signing-as-a-service platforms to enhance operations | Microsoft disrupts Fox Tempest MSaaS tied to Rhysida, Akira, INC, Qilin, BlackByte |
| 🔴 **CRITICAL** | Supply-chain attacks involving popular package managers (npm, PyPI) | Shai-Hulud npm wave; TeamPCP supply-chain campaign continuing through 2026-05-17 |
| 🟠 **HIGH** | Increased targeting of technology and cloud sectors | GitHub/TeamPCP breach; ChromaDB CVE-2026-45829; Fox Tempest abuse of Azure Artifact Signing |
| 🟠 **HIGH** | Rise in phishing-related cybercrimes across sectors | Safepay; Microsoft SSPR abused in Azure data theft; FBI crypto-ATM scams ($388M in 2025); Huawei zero-day behind Luxembourg telecoms outage |
| 🟠 **HIGH** | Exploitation of software vulnerabilities in widely used applications and libraries | Shai-Hulud npm wave; CVE-2026-6473 PostgreSQL integer wraparound |
| 🟠 **HIGH** | Increased targeting of critical infrastructure sectors (manufacturing, energy) | ZKTeco CCTV cameras; Siemens RUGGEDCOM APE1808 devices |
| 🟠 **HIGH** | Increased ransomware activity targeting multiple sectors with sophisticated TTPs | Safepay (`mediafrance.de`); Nightspire (`Vantage Energy LLC`) |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **Qilin** (123 reports) — leading ransomware operation pipeline-wide; also a named consumer of the Fox Tempest MSaaS.
- **Akira** (63 reports) — high-volume ransomware; correlated with Fox Tempest-signed payloads and Anubis healthcare incidents.
- **The Gentlemen** (57 reports) — sustained leak-site posting cadence over the last 30 days.
- **ShinyHunters** (30 reports) — continued data-theft / extortion activity.
- **TeamPCP** (27 reports) — supply-chain compromise specialist; today's GitHub claim is the latest in a Trivy → LiteLLM → Mistral → Mini Shai-Hulud arc.
- **Lockbit5** (26 reports) — high cross-victim correlation in this period (11 reports clustered).
- **Inc Ransom** (26 reports) — leak-site refresh today; affiliates (Vanilla Tempest) named in the Fox Tempest indictment.
- **Safepay** (19 reports) — broad EU/US SME targeting; highest near-term victim cadence outside Qilin.
- **DragonForce** (18 reports) — cluster of manufacturing-sector postings (ZFG ALTHERM, TAURUS INVESTMENT HOLDINGS).
- **Everest** (18 reports) — steady-state activity, no new escalation today.

### Malware Families

- **Akira ransomware** (35 reports) — most-cited ransomware family this period; signed-loader delivery via Fox Tempest now in scope.
- **Tox1 / Tox** (33 / 20 reports) — high recurrence in correlation entries.
- **Qilin** (16 reports) — both an actor and tracked payload identifier.
- **Oyster** (Fox Tempest-signed loader) — documented loader leading to Rhysida; primary detection target for the MSaaS takedown follow-up.
- **Rhysida** (correlated with TSG Enterprises / Landeshauptstadt Stuttgart) — public-sector and enterprise targeting continuing.
- **Lumma Stealer / Vidar** — both observed with Fox Tempest-signed delivery; treat any signed instance with suspicion until certificates are revoked locally.
- **Shai-Hulud / Mini Shai-Hulud** — npm supply-chain malware family driving the critical-rated supply-chain trend.
- **INC Ransomware** (Vanilla Tempest affiliates) — named in Microsoft's SDNY complaint; expect doxxing or branding shifts.

*(Note: "RansomLook" appearing in the malware trending list with 141 reports is an artifact of source-name ingestion, not a malware family.)*

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| BleepingComputer | 4 | [link](https://www.bleepingcomputer.com/news/security/max-severity-flaw-in-chromadb-for-ai-apps-allows-server-hijacking/) | Primary coverage of ChromaDB CVE-2026-45829, GitHub/TeamPCP, Fox Tempest takedown, Discord E2EE |
| RansomLook | 2 | [link](https://www.ransomlook.io//group/safepay) | Leak-site monitoring for Safepay and Inc Ransom |
| SANS | 1 | [link](https://isc.sans.edu/diary/rss/32998) | ISC Stormcast daily podcast |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Take all internet-exposed ChromaDB Python/FastAPI servers off the public internet today; restrict the API port at firewall level and require an authenticating proxy in front. ~73% of exposed instances are vulnerable and no confirmed patch exists. (Ref: §3.1)
- 🔴 **IMMEDIATE:** Hunt for Authenticode-signed binaries impersonating Microsoft Teams, AnyDesk, PuTTY or Webex installed outside sanctioned distribution channels, and rebuild trust chains as Microsoft publishes the revoked Fox Tempest certificate serial numbers. Assume Oyster → Rhysida and similar chains may have signed initial-access stages. (Ref: §3.3)
- 🟠 **SHORT-TERM:** Rotate GitHub-stored CI/CD secrets (PATs, deploy keys, OIDC trusts, package-publishing tokens), pin all third-party GitHub Actions to commit SHA, and audit egress from build infrastructure to TeamPCP-associated infrastructure and known infostealer C2. (Ref: §3.2)
- 🟠 **SHORT-TERM:** Deploy named-file detections for `readme_safepay.txt` / `readme_safepay_ascii.txt`; confirm offline immutable backups for SMEs in manufacturing, healthcare and local government given Safepay's targeting pattern. (Ref: §3.4)
- 🟡 **AWARENESS:** Brief application security and AI/ML platform teams on the converging supply-chain pressure on developer ecosystems — Shai-Hulud npm waves, TeamPCP cross-platform compromises, and ChromaDB AI-stack RCE collectively raise the baseline risk for any LLM/agentic deployment relying on public packages. (Ref: §4)
- 🟢 **STRATEGIC:** Re-evaluate trust assumptions around cloud-issued code-signing services (e.g., Azure Artifact Signing): treat signer identity as a signal, not proof, and require additional provenance (SLSA / Sigstore / internal allow-listing) for high-trust binaries. (Ref: §3.3)

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 7 reports processed across 2 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
