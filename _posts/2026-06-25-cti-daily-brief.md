---
layout: post
title:  "CTI Daily Brief: 2026-06-25 — China-nexus DragonReturn campaign hits Indian MoF; first in-the-wild exploitation of Langflow CVE-2026-55255"
date:   2026-06-26 20:07:42 +0000
description: "62 reports across 15 sources. Critical: China-nexus Operation DragonReturn targeting Indian tax infrastructure with DcRAT; Sysdig observes first in-the-wild exploitation of Langflow IDOR CVE-2026-55255. High: Polymarket supply-chain attack ($3M loss), Amazon Q VS Code MCP auto-execution flaw (CVE-2026-12957), Mini Shai-Hulud npm wave, Microsoft-tracked Node.js implant against hospitality sector, CL-STA-1062 TinyRCT operations against Southeast Asian governments, joint CISA/FBI advisory on Russian messaging-app phishing."
category: daily
tags: [cti, daily-brief, dragonreturn, cl-sta-1062, settra, langflow, mini-shai-hulud, dcrat]
classification: TLP:CLEAR
reporting_period: "2026-06-25"
generated: "2026-06-26"
draft: true
severity: critical
report_count: 62
sources:
  - AlienVault
  - BleepingComputer
  - CISA
  - Microsoft
  - Sysdig
  - Unit42
  - Wiz
  - Wired Security
  - RecordedFutures
  - Schneier
  - Datadog
  - HaveIBeenPwned
  - Upwind
  - RansomLook
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-06-25 (24h) | TLP:CLEAR | 2026-06-26 |

## 1. Executive Summary

The pipeline processed 62 reports across 15 sources in the last 24 hours, with the threat picture dominated by two converging themes: China-nexus cyber-espionage and active exploitation of vulnerabilities in AI/developer tooling. Seqrite (via AlienVault) disclosed Operation DragonReturn, a sustained China-nexus campaign targeting the Indian Ministry of Finance tax-filing infrastructure with multi-stage DcRAT, while Unit 42 documented CL-STA-1062 (overlapping UAT-7237) deploying the new TinyRCT backdoor against Southeast Asian government and energy targets. Sysdig observed the first known in-the-wild exploitation of Langflow CVE-2026-55255 (CVSS 9.9 IDOR), and Wiz published CVE-2026-12957 in the Amazon Q VS Code extension where unconsented MCP auto-execution led to cloud-credential theft from a single repo clone. Supply-chain risk continued: Polymarket lost roughly $3M after a third-party frontend dependency was poisoned, and the Mini Shai-Hulud cluster pushed malicious LeoPlatform npm packages and Go modules through the czirker/llxlr accounts on 24 June. CISA and the FBI re-issued their PSA on Russian Intelligence Services phishing of commercial messaging applications. No new CISA KEV additions were reported in the 24-hour window.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 5 | Operation DragonReturn (DcRAT vs Indian MoF); Langflow CVE-2026-55255 active exploitation; Linux kernel DirtyClone CVE-2026-43503; OpenBSD PPP auth bypass CVE-2026-55706; Krayin CRM RCE CVE-2026-38526 |
| 🟠 **HIGH** | 39 | Settra/Play/Akira/Nova/Inc Ransom/Chaos/AiLock leak-site posts; Polymarket supply-chain theft; Amazon Q MCP flaw; Mini Shai-Hulud npm campaign; Microsoft Photo ZIP hospitality campaign; CL-STA-1062/TinyRCT; CISA Russian-IS messaging advisory; Poland SIM-swap arrests |
| 🟡 **MEDIUM** | 11 | Microsoft libxpm/tun/tap kernel CVEs; American Tower (216k accounts, ShinyHunters); MagMutual 7.3M-record exposure; ~1M passport leak via cannabis dispensary KYC vendor |
| 🔵 **INFO** | 7 | Meta facial-recognition pilot for police/military; FCC undersea-cable rules; GuardDog 3.0 release; agentic GRC red-team write-up |

## 3. Priority Intelligence Items

### 3.1 Operation DragonReturn — China-nexus DcRAT campaign against Indian Ministry of Finance

**Source:** [AlienVault / Seqrite](https://www.seqrite.com/blog/operation-dragonreturn-china-nexus-cyber-espionage-campaign-targeting-govt-of-india-mof-tax-infrastructure-via-multi-stage-dcrat-deployment/)

Seqrite Labs uncovered a sustained spear-phishing operation that impersonates the Indian Income Tax Department to deliver multi-stage DcRAT. The campaign was first observed on 18 May 2026 and remains active; the latest payload variant achieved a 0/66 detection rate on VirusTotal, indicating active rotation. Lures abuse the AY2026-27 ITR filing season, use bilingual Hindi-English Office Memorandum templates, and cite real sections of the Income Tax Act. Initial-access redirection runs through `govtop[.]one/incometax`. Seqrite assesses TTP overlap with a known active China-aligned cluster (Void Arachne is referenced in the entity graph). Targets are pan-India taxpayers, tax professionals, corporate finance teams, and government contractors. Observed techniques include T1566.001 (spear-phishing attachment), T1027 (obfuscation/steganography), T1055 (process injection), T1547.001 (registry run-key persistence), T1543.003 (service install), T1041 (C2 exfil), and T1573 (encrypted channel).

#### Indicators of Compromise
```
C2/Lure domains:
  govtop[.]one
  1kkkkddd[.]com
  ikkkkddd[.]com
  jiayingjing[.]com
  kkxqbh[.]top
  simaqz[.]com

C2 IPv4:
  117.44.201[.]119
  118.107.0[.]197
  204.194.48[.]250
  223.26.63[.]40
  27.50.54[.]191

SHA-256 (selected, full list in source):
  19ca5fe04ca45a18c5bad9658ff73a8f39fe20ced78f690595f1b4c5a90af324
  2f2f8f92af86fb962c30c4c1c9d673f9d94886373d0fcf78f8d105c051ffc643
  34d1231a3bf1e13a9b90daecb5c74d52aea94ca54427b203d77e1adc61a5c4f9
  4a040770fd81d0db9e04cb8dbd2e07e61969072962bb4e736b7c7001444cc2fa
  589aa1f7252cae74538343cd35443c0a8f58ed280f2016918b6e539a0c09529a
  a8614dfad5fd2a79302a7c4829a0fed6f3a0a46b11beb28f89531cdfa83d32b3
  ec5d4103b3d97885e9575ad045b2ef5467bf9fccf71828e418e6488d78983146
  fc17d5b4d64cb61a5aa8fb6bbe1e94885f129b2bf8ee91bca1ccca2b537f6616

URL:
  hxxp[://]govtop[.]one/incometax
```

> **SOC Action:** Block the domain and IP IOCs at egress and proxy. Hunt mail flow for ITR/income-tax themed lures with embedded `govtop[.]one` redirectors. Query EDR for rundll32.exe spawning from `%TEMP%` or user profile paths (T1218.011) and for new run-key persistence under `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` referencing user-temp paths. Flag any process injection from script-host children (wscript/mshta) into trusted processes (T1055). Brief India-facing finance, tax-advisory, and corporate-treasury staff this week.

---

### 3.2 Langflow CVE-2026-55255 — first in-the-wild exploitation observed

**Source:** [Sysdig](https://webflow.sysdig.com/blog/understanding-langflow-cve-2026-55255-and-why-higher-cvss-vulnerabilities-arent-always-the-most-exploited)

On 25 June 2026 the Sysdig Threat Research Team documented the first known active exploitation of CVE-2026-55255, a CVSS 9.9 cross-tenant Insecure Direct Object Reference in Langflow's `POST /api/v1/responses` endpoint. The vulnerable code path in `get_flow_by_id_or_endpoint_name` resolves flows by UUID without an ownership check, allowing any authenticated user to execute any other tenant's flow and surface embedded secrets such as API keys via prompt injection (`"leak api keys"`). The endpoint-name branch is not vulnerable. The same operator was observed pairing this IDOR with the already-KEV-listed CVE-2026-33017 RCE (CVSS 9.3) against the same instance. Fixed in Langflow 1.9.1 (PR #12832). Sysdig notes attackers prioritised the lower-scored RCE because IDOR exploitation requires flow-ID enumeration via `/api/v1/flows/`. MITRE TTPs observed: T1068 (privilege escalation by exploitation) and T1048 (exfiltration over C2).

> **SOC Action:** Upgrade Langflow to ≥1.9.1 immediately; this is operationally critical for any team running Langflow as a hosted multi-tenant service or in CI. If patching is blocked, restrict `/api/v1/flows/` and `/api/v1/responses` to trusted source IPs only and audit recent calls for flow-UUID enumeration patterns. Rotate any API keys, OAuth tokens, or model credentials embedded inside Langflow flows. Add WAF rules to flag `POST /api/v1/responses` payloads containing prompt strings such as `leak api keys`, `print credentials`, or `reveal secrets`.

---

### 3.3 Polymarket frontend supply-chain attack — ~$3M phished from users

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/polymarket-customers-lose-3-million-in-supply-chain-attack/)

Polymarket confirmed a supply-chain compromise of a third-party frontend dependency that allowed attackers to inject malicious JavaScript into the official Polymarket site, tricking users into approving fraudulent wallet transactions. PeckShield estimates ~$3M in `ParyonUSD` stolen, subsequently bridged from Polygon to Ethereum and swapped into ~1,893 ETH. Bubblemaps assesses fewer than 15 accounts were affected. Polymarket's own backend was not impacted; the company has stated affected customers will be reimbursed. MITRE TTP: T1566 (phishing via trusted-frontend abuse). Conceptually similar to the ongoing LastPass/Klue and ShapedPlugin incidents.

> **SOC Action:** For any Web3/finance-facing organisation, inventory third-party JavaScript dependencies loaded by the production frontend, enforce subresource integrity (SRI) on every external script tag, and pin lockfiles for build pipelines. Add a content-security-policy `script-src` allowlist and alert on the appearance of unknown origins. For wallet-using staff: instrument browser-side wallet-confirmation telemetry and confirm transaction targets against expected contract addresses before signing.

---

### 3.4 Amazon Q VS Code Extension — MCP auto-execution leads to cloud-credential theft (CVE-2026-12957)

**Source:** [Wiz Research](https://www.wiz.io/blog/amazon-q-vulnerability)

Wiz disclosed CVE-2026-12957, a high-severity flaw in the Amazon Q Developer Extension for VS Code (language-server versions < 1.65.0). The extension auto-loaded `.amazonq/mcp.json` from any opened workspace without prompting for consent and executed configured MCP servers with full inherited environment, including cloud credentials, SSH keys, and API tokens. Cloning a malicious repository and opening it in VS Code was sufficient for arbitrary code execution. Fixed in language-server 1.65.0. Wiz notes parallel findings by OX Security and Check Point against other AI coding assistants, framing MCP auto-execution as a systemic ecosystem issue. TTPs include T1059.001 (PowerShell) and T1566 (delivery via lure repository).

> **SOC Action:** Verify Amazon Q VS Code extension language-server version is ≥ 1.65.0 across developer fleets via MDM/EDR inventory queries. Add EDR rule for `code.exe` or `node.exe` (Amazon Q language server) spawning unexpected child processes (`npx`, `uv`, `python -m`) shortly after a `git clone` event. Restrict developer workstations from carrying long-lived cloud credentials in environment; prefer short-lived federation (AWS SSO, GCP workload identity). Educate developers that workspace-trust prompts in VS Code are not optional, and audit recent `git clone` history from public sources.

---

### 3.5 Mini Shai-Hulud — coordinated npm and Go supply-chain wave

**Source:** [AlienVault OTX](https://otx.alienvault.com/pulse/6a3df898a72c3bb83671b47b)

A renewed Mini Shai-Hulud / Miasma / Hades wave was published in a coordinated burst on 24 June 2026 through the npm accounts `czirker` and `llxlr`, compromising LeoPlatform npm packages, GitHub Actions workflows, and the Verana Blockchain Go module. The payload chain abuses `binding.gyp` install-time execution, stages a Bun-runtime JavaScript implant, and exfiltrates encrypted bundles containing npm tokens, GitHub PATs, cloud provider credentials, SSH keys, and AI-coding-assistant configurations. GitHub is used as dead-drop infrastructure; persistence is established through orphan branches and fake "dependency-update" Actions workflows. The `RevokeAndItGoesKaboom` marker ties this wave to the earlier codfish/semantic-release-action compromise. MITRE: T1486 (supply-chain compromise — note: AlienVault tagged the supply-chain technique as T1486; T1195 is the canonical ATT&CK ID for supply-chain compromise), T1059.001, T1071.002.

#### Indicators of Compromise
```
npm accounts: czirker, llxlr
Marker string: RevokeAndItGoesKaboom

SHA-256 (selected):
  026588d39b7c650b5c0dfbba6c6fcc0e7ec8e3b72ba8639012e7f71c708f2c3b
  15b415ae41df72acf1f7e9e67569531d41dee62d089d34b4c0fab0c7fe5cc14f
  1a0e1daeaea87cab5610a3cc2aa72e7c6f1abfe55959a156368bcfa6585fa6ce
  32d1bc728d8e504952083a6adc488c309a401c7df4dc8f47b382ce32e4aebe21
  3da2ca129c9920d9acd2e3477aee8f46b5a5f0e9537ad6e7b6ab1df1007adad1
  6a861a479f45fe53f067091414332248bc027ffc396116811d12e57a6ff71250
  927387d0cfac1118df4b383decc2ea6ba49c9d2f98b47098bcbcba1efc026e1f
  a934a5bcf692b9d01e8129bf264be23809dfee464df471d75a9f3fa1bcede343
  ceff7c51d70832c3ec8dd2744b606a23b3c924ef664ae23439b9b742ea154108
  df9ea0c71574e11c93141ad2f018a63a5375cd6d69ca2f744732ad7814170657
```

> **SOC Action:** Block the `czirker` and `llxlr` npm publishers in private registries and CI policies. Search audit logs for the `RevokeAndItGoesKaboom` string in repository history, branches, or CI output. Hunt for unexpected `orphan` branches or new `dependency-update` GitHub Actions workflows committed in the last 72 hours. Rotate any npm tokens, GitHub PATs, and cloud credentials issued to builds that ran since 23 June. EDR-hunt CI/dev hosts for `bun` runtime execution paired with outbound HTTPS to GitHub raw-content URLs the host has not previously contacted.

---

### 3.6 Microsoft tracks "Photo ZIP" multi-stage Node.js implant against hospitality sector

**Source:** [AlienVault / Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/06/25/photo-zip-campaign-targeting-hospitality-industry-delivers-node-js-implant-persistent-access/)

Microsoft Threat Intelligence reports an active multi-stage campaign against hotel and hospitality organisations in Europe and Asia, ongoing since April 2026. Lures are guest-complaint / room-inquiry emails delivered via abused Calendly notifications and Google URL redirects ("authentication laundering"), pointing to photo-themed ZIPs that contain `IMG-*.png.lnk` (Wave 1) or `PHOTO-*.png.lnk` (Wave 2) shortcut files. The chain executes obfuscated PowerShell that deploys a Node.js implant, establishes dual registry-run-key persistence, beacons over non-standard ports, and compiles PE payloads on-host. Microsoft has not attributed the activity. Tags reference PureRAT, TonRAT, and Wacatac as related families. MITRE includes T1566.002, T1059.001/007, T1027/T1027.004, T1547.001, T1562.001, T1571.

#### Indicators of Compromise
```
Selected SHA-256:
  04ec44f2618460f5c77c5e56014a512cc03a123c9c5b6b6b1273e2a1681ac2e1
  1c693bcdaf1da636eb21c274b21cc2f6c52c62ddd514700783eee83fe13acb0a
  3f66634f103b80412d1d670b91befab2a74425d2ea76d904c4a7ffae2ae94b44
  89934cb1494cf0327f0ab82fe644c74caf687814379cad116bd7adaca74c1028
  98825c0c7764f45c891275b2f038ea559e84b340df30b41c2cc77b8d4215c6c8

Domains (selected — large infrastructure footprint):
  bookreservphoto[.]pro
  photobook-reserv[.]pro
  reservebookphot[.]pro
  photobookadm[.]pro
  expedla-getphoto[.]cloud
  tripadvisor-photo-view[.]com
  photo-21473[.]xyz
  photo-26653[.]cfd
  photo-26654[.]cfd
  photo-26656[.]cfd
  photo-7216102[.]click
  doc-imagehub[.]info
  imagestore-hub[.]info
  safedoc-storage[.]info
  visa-vault[.]info
  visaphoto-secure[.]info
```

> **SOC Action:** Block the listed domain TLDs `.cfd`, `.icu`, `.bond`, `.click`, `.sbs` at proxy where business need does not exist (hospitality especially). EDR-hunt for `.lnk` files with double-extension naming (`*.png.lnk`) executed from `%TEMP%`, `%APPDATA%`, or Outlook download paths. Detect Node.js (`node.exe`) execution from non-standard install paths and listening on non-standard ports. Flag run-key persistence with command-line referencing `node`, `npm`, or unusual JS payload paths. Train front-of-house staff to treat ZIP attachments from booking platforms as suspect even when sender domains look legitimate.

---

### 3.7 CL-STA-1062 / UAT-7237 deploys TinyRCT backdoor against Southeast Asian governments

**Source:** [Unit 42](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)

Unit 42 assesses with high confidence that CL-STA-1062 — a Chinese-speaking cluster active since March 2022, overlapping with UAT-7237 reported by Cisco Talos in Taiwan — has been targeting Southeast Asian government entities and energy-sector state-owned enterprises through 2025. Tooling is a hybrid of off-the-shelf utilities (SoftEther VPN, Mimikatz, VNT, JuicyPotato) and a previously undocumented bespoke backdoor, TinyRCT, supporting arbitrary command execution, file enumeration/exfiltration, screen capture, and self-destruct. Tactics include external-facing exploitation (T1190), web-shell deployment (T1505.003), credential dumping (T1003.001), scheduled-task persistence (T1053.005), and encrypted C2 (T1573.001). Between October and December 2025 the cluster likely compromised at least ten organisations in the region.

#### Indicators of Compromise
```
TinyRCT SHA-256:
  00e09754526d0fe836ba27e3144ae161b0ecd3774abec5560504a16a67f0087c
  4e1f8888d020decd09799ec946f1bf677cac6612b24582ddbf4d8ede425d8384
  9b481b69cd91b09fa7bae7428f646dd89473a4c03393e43da81fe756cde1c472
  cbfe8de6ffadbb1d396f61e63eb18e8b11c29527c1528641e3223d4c516cf7c3
  dce5df29bddff5a4ddaea5c4fec14da91f7b69063a6e1c45ed61e5da4fc6c87b
  f34bd1d485de437fe18360d1e850c3fd64415e49d691e610711d8d232071a0b1
```

> **SOC Action:** APAC government and energy-sector tenants: hunt for SoftEther VPN binaries in non-standard install locations, Mimikatz process names (or known variants such as `mimi.exe`, `mz.exe`), and TinyRCT hashes above. Audit IIS/Tomcat web servers for unfamiliar `.aspx` / `.jsp` files written in the last 90 days (T1505.003). Block outbound traffic to SoftEther's anonymising service infrastructure where business need does not exist. Validate MSSQL audit logs for high-volume `bcp` / SELECT exfiltration patterns.

---

### 3.8 Joint CISA/FBI re-issue: Russian Intelligence Services targeting commercial messaging apps

**Source:** [CISA](https://www.cisa.gov/resources-tools/resources/russian-intelligence-services-continue-target-commercial-messaging-applications), [The Record / Recorded Future](https://therecord.media/russia-ukraine-social-engineering-messaging-accounts)

CISA and the FBI updated their March 2026 Public Service Announcement on Russian Intelligence Services (RIS) phishing campaigns against commercial messaging applications. The advisory adds new tactics, recommended mitigations, and example phishing messages. In parallel, Ukraine's SBU reported RIS-attributed social-engineering operations compromising messaging accounts of Ukrainian government officials and military personnel by impersonating "official support services" — no exploitation of the messaging applications themselves, but credential and session-token theft via convincing pretexts. MITRE: T1566.

> **SOC Action:** Distribute CISA's updated PSA to executive-protection, government-liaison, and military-adjacent staff today. Enforce hardware-token MFA on personal messaging accounts where business-relevant communications occur, and treat any "support team" outreach asking for OTPs or session-link confirmations as adversary activity. Add IR runbook coverage for compromised personal-messaging accounts of senior staff (notification, session revocation, contact-list quarantine).

---

### 3.9 Settra ransomware leak-site posts dominate the day's high-severity volume

**Source:** [RansomLook](https://www.ransomlook.io//group/settra)

The Settra ransomware group accounted for the single largest cluster of high-severity reports in the period, posting leak entries for LifeVantage Corporation, Turbo Data Systems Inc., Quality Dining Inc., DyStar, PChome (Taiwan), VA Glass, TMS Central, Doosan, Conduril (Portugal), HMC Farms, and Canopy Brands. The pipeline's correlation analysis (batch 197) shows Settra as the dominant actor of the day with a 0.90-confidence link across these entries, with Tox1 surfacing as a shared infrastructure indicator. Additional active brands in the same 24h: Akira (Precise Forms), Play (Benchmark Industrial Supply), Inc Ransom (Life Bridges, GSP Crop Science), Chaos (Ingerman), AiLock (Hokua), Nova (NSW Rural Fire Service, VSL Marine), The Gentlemen (Atlas Elektronik), Payload (Mosaic Partners, Clínica La Sabana, Software Arge), and Prinz Eugen.

> **SOC Action:** Treat Settra as the priority ransomware brand for the week. If your organisation falls in technology / healthcare / food-and-beverage / heavy industry verticals, validate VPN patch level, MFA enforcement, and external attack-surface for Tox1-style chat-listener exposure (random high ports with TLS to dynamic-DNS endpoints). Pull any indicators referenced on the Settra leak site relevant to your supply chain (the named victims hold third-party data of many partners).

---

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 CRITICAL | Exploitation of critical vulnerabilities in widely used software and systems | DirtyClone CVE-2026-43503 (Linux kernel LPE); Langflow CVE-2026-55255 (first in-the-wild) |
| 🔴 CRITICAL | Sophisticated cyber-espionage campaigns targeting government infrastructure | Operation DragonReturn (India MoF); CL-STA-1062 / TinyRCT (Southeast Asian governments, energy) |
| 🟠 HIGH | Ransomware groups targeting multiple sectors with double-extortion tactics | Settra posts against conduril.pt, va-glass.com, hmcfarms.com; Payload posts against Mosaic Partners, Clínica La Sabana |
| 🟠 HIGH | Phishing as the common entry vector across financially-motivated and intelligence operations | Polymarket third-party JS phishing; fraudulent OpenAI organisation invites to cybersecurity firms |
| 🟠 HIGH | Targeting of critical infrastructure in government and energy | CL-STA-1062 SE Asia energy SoEs; CISA Russian-IS messaging-app advisory |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **The Gentlemen** (86 reports) — Active leak-site brand, latest victim Atlas Elektronik (naval/marine systems).
- **Qilin** (65 reports) — Continuing high-volume RaaS operations across sectors.
- **Deadlock** (55 reports) — Persistent leak-site presence over the last 30 days.
- **Lockbit5** (39 reports) — Rebranded LockBit successor remains visible in the pipeline.
- **Akira** (36 reports) — Latest victim Precise Forms; double-extortion via unpatched VPNs and stolen RDP credentials.
- **ShinyHunters** (23 reports) — Linked to the American Tower 216k-account "pay or leak" extortion.
- **DragonForce** (23 reports) — Continued double-extortion operations.
- **Nova** (22 reports) — Rebrand of RALord with CAPTCHA-gated leak site.
- **Nightspire** (18 reports) — Moderate but sustained activity.

### Malware Families

- **RansomLook** (142 reports) — Pipeline-wide tag covering ransomware leak-site posts.
- **Tox1** (64 reports) — C2/comms used by Settra and other leak-site operators.
- **Tox** (42 reports) — Parent messaging protocol referenced across RaaS infrastructure.
- **Akira ransomware** (16 reports) — Active Windows/ESXi/Linux encryptor (`.akira` extension).
- **Lockbit5** (14 reports) — Successor-family encryptor.
- **Nova** (11 reports) — RaaS payload tied to the Nova brand.
- **RALord** (10 reports) — Predecessor brand to Nova.
- **DcRAT** (this period) — Multi-stage payload in Operation DragonReturn.
- **TinyRCT** (this period) — Novel bespoke backdoor from CL-STA-1062.
- **Mini Shai-Hulud / Miasma / Hades** (this period) — npm/GitHub supply-chain implant family.

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| RansomLook | 28 | [link](https://www.ransomlook.io/) | Ransomware leak-site aggregation; Settra dominant brand |
| Unknown (Telegram-origin) | 7 | — | Telegram CVE drops including DirtyClone, OpenBSD PPP, Krayin CRM, Squidbleed, PixelSmash — channel URLs withheld |
| AlienVault | 5 | [link](https://otx.alienvault.com/) | Operation DragonReturn, Mini Shai-Hulud, Microsoft Photo ZIP relay, STOCKSTAY/Turla, CL-STA-1062 |
| BleepingComputer | 5 | [link](https://www.bleepingcomputer.com/news/security/polymarket-customers-lose-3-million-in-supply-chain-attack/) | Polymarket supply-chain, OpenAI invite phishing, Poland SIM-swap arrests |
| Microsoft | 4 | [link](https://msrc.microsoft.com/update-guide) | libxpm and tun/tap kernel CVEs |
| RecordedFutures | 3 | [link](https://therecord.media/russia-ukraine-social-engineering-messaging-accounts) | Russia messaging-app social engineering, FCC undersea cables, Apple/VK App Store dispute |
| Schneier | 2 | [link](https://www.schneier.com/) | One-million-passport leak; Meta facial-recognition pilot |
| Sysdig | 1 | [link](https://webflow.sysdig.com/blog/understanding-langflow-cve-2026-55255-and-why-higher-cvss-vulnerabilities-arent-always-the-most-exploited) | First in-the-wild Langflow CVE-2026-55255 exploitation |
| Unit42 | 1 | [link](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/) | CL-STA-1062 / TinyRCT |
| Wiz | 1 | [link](https://www.wiz.io/blog/amazon-q-vulnerability) | Amazon Q VS Code MCP auto-execution (CVE-2026-12957) |
| Wired Security | 1 | [link](https://www.wired.com/story/the-pentagon-is-looking-into-the-dialog-data-exposure-for-unmasking-national-security-officials/) | Pentagon investigates Dialog exposure of NSC and DoD officials |
| CISA | 1 | [link](https://www.cisa.gov/resources-tools/resources/russian-intelligence-services-continue-target-commercial-messaging-applications) | Updated PSA on Russian IS messaging-app phishing |
| HaveIBeenPwned | 1 | [link](https://haveibeenpwned.com/Breach/AmericanTower) | American Tower 216,601 accounts (ShinyHunters) |
| Datadog | 1 | [link](https://securitylabs.datadoghq.com/articles/guarddog-3-0-release/) | GuardDog 3.0 (YARA-based npm/Python malware scanning) |
| Upwind | 1 | [link](https://www.upwind.io/feed/cloud-security-ux-broken-runtime-contextcloud-security-ux-runtime-context) | Cloud-security UX opinion piece |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Patch Langflow to ≥1.9.1 (CVE-2026-55255) and rotate any API keys or model credentials embedded in flows. Sysdig confirmed first in-the-wild exploitation on 25 June.
- 🔴 **IMMEDIATE:** Upgrade Amazon Q VS Code extension language-server to ≥1.65.0 (CVE-2026-12957) across developer fleets and audit recent clones of public repositories for `.amazonq/mcp.json` artefacts.
- 🟠 **SHORT-TERM:** Block the DragonReturn and Photo ZIP campaign indicators (full list in Sections 3.1 and 3.6) at proxy and DNS; deploy detection for `*.png.lnk` execution from temp paths and Node.js child processes spawned by Office or Outlook download writes.
- 🟠 **SHORT-TERM:** Quarantine the `czirker` and `llxlr` npm publishers and search recent build outputs for the `RevokeAndItGoesKaboom` string (Mini Shai-Hulud). Rotate npm tokens, GitHub PATs, and cloud-provider credentials issued to affected pipelines since 23 June.
- 🟡 **AWARENESS:** Brief executive-protection and government-liaison staff on the updated CISA/FBI advisory regarding RIS phishing of commercial messaging apps; enforce hardware-token MFA on personal messaging accounts used for business-relevant comms.
- 🟢 **STRATEGIC:** Treat MCP auto-execution as an ecosystem-wide developer-tool risk class (the Amazon Q finding mirrors parallel disclosures from OX Security and Check Point against other AI assistants). Build a developer-tooling threat model that explicitly covers workspace-trust prompts, environment inheritance into spawned MCP processes, and short-lived cloud credentials at the workstation tier.

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 62 reports processed across 4 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
