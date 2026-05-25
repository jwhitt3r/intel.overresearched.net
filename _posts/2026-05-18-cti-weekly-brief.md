---
layout: post
title:  "CTI Weekly Brief: 2026-05-18 to 2026-05-24 - Actively-exploited Defender, Apex One and BitLocker zero-days; Drupal and Ghost CMS mass exploitation; Shai-Hulud npm wave continues"
date:   2026-05-25 08:30:00 +0000
description: "577 reports processed: 47 critical and 333 high. Microsoft Defender, Trend Micro Apex One, Windows BitLocker (YellowKey) and Drupal under active exploitation. Cisco Secure Workload, Ubiquiti UniFi OS and ChromaDB receive max-severity patches. TeamPCP Shai-Hulud worm continues poisoning npm packages while durabletask PyPI compromise targets cloud secrets. Qilin, Akira and The Gentlemen dominate ransomware activity."
category: weekly
tags: [cti, weekly-brief, qilin, teampcp, shai-hulud, cve-2026-34926, cve-2026-26980, cve-2026-9082]
classification: TLP:CLEAR
reporting_period_start: "2026-05-18"
reporting_period_end: "2026-05-24"
generated: "2026-05-25"
draft: false
severity: critical
report_count: 577
sources:
  - Microsoft
  - RansomLock
  - BleepingComputer
  - AlienVault
  - RecordedFutures
  - CISA
  - SANS
  - Wired Security
  - Schneier
  - Unit42
  - Upwind
  - Krebs on Security
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-05-18 to 2026-05-24 (7d) | TLP:CLEAR | 2026-05-25 |

## 1. Executive Summary

This week's pipeline processed **577 reports across 15 correlation batches**, including **47 critical** and **333 high** severity items. The week was dominated by **actively exploited zero-days in core security and infrastructure products**: Trend Micro Apex One (CVE-2026-34926), two Microsoft Defender flaws (CVE-2026-41091 and CVE-2026-45498), and the Windows BitLocker "YellowKey" bypass (CVE-2026-45585) were all added to defensive workflows after CISA additions or public PoC release. CISA also opened a federal patch window after Drupal (CVE-2026-9082) and Ghost CMS (CVE-2026-26980) moved from disclosure into mass exploitation, with the Ghost campaign poisoning **700+ domains** — including Harvard, Oxford, Auburn and DuckDuckGo — to deliver ClickFix infostealer payloads.

The npm ecosystem suffered another wave of **TeamPCP-attributed Shai-Hulud worm activity**, with Unit 42 documenting credential-free initial access and a record single-hour package compromise count. Upwind disclosed a parallel **PyPI compromise of Microsoft's `durabletask` SDK** (versions 1.4.1–1.4.3) that exfiltrates AWS, Azure, GCP, HashiCorp Vault and Kubernetes credentials. Max-severity infrastructure patches landed for Cisco Secure Workload (CVE-2026-20223), three Ubiquiti UniFi OS flaws and ChromaDB (CVE-2026-45829), the last of which leaves an estimated 73% of internet-exposed instances vulnerable. Ransomware-as-a-service operators **Qilin (115 reports), Akira (68), The Gentlemen (64) and TeamPCP (34)** drove pipeline volume, while RecordedFutures attributed the July 2025 nationwide outage of Luxembourg's POST network to a previously undisclosed Huawei VRP zero-day. The composite picture is one of supply chain and security-tool compromise eclipsing perimeter exploitation as the dominant initial-access pattern.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 47 | Apex One, Defender and BitLocker zero-days; Ghost CMS / Drupal mass exploitation; Rsync, BIND 9, rust-openssl, ChromaDB, Cisco Secure Workload, Ubiquiti UniFi OS patches; npm Shai-Hulud and durabletask supply chain compromises |
| 🟠 **HIGH** | 333 | Qilin, Akira, The Gentlemen, Nightspire, Inc Ransom, Nova and Stormous ransomware leak-site postings; Coinbase Cartel and ShinyHunters extortion campaigns |
| 🟡 **MEDIUM** | 115 | Microsoft MSRC advisories of lower CVSS impact; secondary AlienVault OTX pulses; SANS ISC analysis posts |
| 🟢 **LOW** | 30 | Bug bounty disclosures; low-confidence telegram OSINT items |
| 🔵 **INFO** | 52 | RansomLook leak-site metadata; pipeline housekeeping; vendor blog reposts |

## 3. Priority Intelligence Items

### 3.1 Trend Micro Apex One Zero-Day Actively Exploited (CVE-2026-34926)

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/trend-micro-warns-of-apex-one-zero-day-exploited-in-attacks/)

Trend Micro disclosed and patched a directory traversal vulnerability in the on-premises Apex One server. A pre-authenticated local attacker holding administrative credentials can modify a key table to inject malicious code that is then deployed to managed endpoints, effectively turning the EDR console into a malware distribution platform. TrendAI has confirmed at least one in-the-wild exploitation attempt, and CISA added the CVE to the KEV catalogue with a federal patch deadline of **4 June 2026**. Cloud (SaaS) deployments are not affected; only the on-premises product requires action. Trend Micro also patched seven local privilege-escalation flaws in the Apex One Standard Endpoint Protection agent in the same release.

**Affected products:** Trend Micro Apex One (on-premises) server.
**ATT&CK:** T1059 (Command and Scripting Interpreter), T1136 (Create or Modify System Process), T1547 (Boot or Logon Autostart Execution).

> **SOC Action:** Apply the Trend Micro Apex One patch before 4 June. Until patched, restrict administrative access to the Apex One management server to a jump host, enable MFA on all admin accounts, and hunt EDR audit logs for unexpected modifications to agent policy or key tables. Add detection for unsigned binaries being pushed to managed endpoints via the Apex One agent.

### 3.2 Two Microsoft Defender Zero-Days Patched After Active Exploitation

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/microsoft-warns-of-new-defender-zero-days-exploited-in-attacks/), [MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-41091)

Microsoft shipped patches for two actively exploited Defender vulnerabilities. **CVE-2026-41091** is an improper-link-resolution flaw in Microsoft Malware Protection Engine versions ≤ 1.1.26030.3008 that grants SYSTEM privileges. **CVE-2026-45498** is a denial-of-service flaw in Microsoft Defender Antimalware Platform ≤ 4.18.26030.3011 that crashes the protection service on unpatched Windows hosts. CISA added both to the KEV catalogue and ordered FCEB agencies to remediate by **3 June 2026** under BOD 22-01. Updated platform versions are **1.1.26040.8** and **4.18.26040.7** respectively; both ship through standard definition-update channels by default.

**Affected products:** Windows endpoints running Microsoft Defender, System Center Endpoint Protection, and Security Essentials.
**ATT&CK:** T1047 (WMI), T1078 (Valid Accounts), T1068 (Exploitation for Privilege Escalation).

> **SOC Action:** Validate that all managed Windows endpoints have Malware Protection Engine ≥ 1.1.26040.8 and Antimalware Platform ≥ 4.18.26040.7 — run `Get-MpComputerStatus` across the estate. Investigate any host where Defender services were stopped or crashed since 14 May. For CVE-2026-41091, audit for unexpected creation of files in protected directories by `MsMpEng.exe` child processes.

### 3.3 Windows BitLocker "YellowKey" Zero-Day Disclosed Without Patch (CVE-2026-45585)

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/microsoft/microsoft-shares-mitigation-for-yellowkey-windows-zero-day/)

An anonymous researcher operating as **Nightmare Eclipse** publicly disclosed a Windows BitLocker bypass after a dispute with MSRC. Exploitation requires physical access: an attacker places a crafted `FsTx` file on a USB drive or EFI partition, reboots into Windows Recovery Environment (WinRE), and triggers an unrestricted shell against the BitLocker-protected volume by holding CTRL. The same researcher previously released BlueHammer (CVE-2026-33825) and RedSun LPE exploits, and additional unfixed disclosures (GreenPlasma SYSTEM shell, UnDefend Defender-update blocker) are circulating. Microsoft issued CVE-2026-45585 only to publish mitigations, not a code fix.

**Affected products:** Windows endpoints with default-configuration ("TPM-only") BitLocker.
**ATT&CK:** T1064 (Scripting), T1547.002 (Registry Run Keys / Startup Folder).

> **SOC Action:** Convert BitLocker from TPM-only to **TPM+PIN** mode on all laptops via PowerShell, Intune or Group Policy ("Require additional authentication at startup" → "Require startup PIN with TPM"). Remove `autofstx.exe` from `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute`. Update lost-device incident response runbooks to assume BitLocker may be bypassed if physical access occurred.

### 3.4 Ghost CMS Mass Exploitation Powers 700-Domain ClickFix Campaign (CVE-2026-26980)

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/ghost-cms-sql-injection-flaw-exploited-in-large-scale-clickfix-campaign/), [AlienVault OTX](https://otx.alienvault.com/pulse/6a0f06676dfe8431915ed38a)

XLab researchers at Qianxin confirmed exploitation of CVE-2026-26980 (Ghost CMS 3.24.0–6.19.0) against more than 700 domains, including Harvard University, Oxford University, Auburn University and DuckDuckGo. The unauthenticated SQL injection exposes the Ghost admin API key, which attackers use to inject malicious JavaScript into articles. The injected loader fingerprints visitors and overlays a fake Cloudflare prompt as an iframe; victims are coached through a ClickFix sequence that drops one of several payloads, including DLL loaders, JavaScript droppers and an Electron-based binary named `UtilifySetup.exe`. The flaw was patched in Ghost 6.19.1 on 19 February but many sites remain unpatched, and XLab observed competing actor clusters re-infecting cleaned sites.

**Affected products:** Self-hosted Ghost CMS 3.24.0 through 6.19.0.
**ATT&CK:** T1190 (Exploit Public Facing Application), T1059.007 (JavaScript), T1059.001 (Windows Command Shell), T1189 (Drive-by Compromise), T1204 (User Execution), T1566 (Phishing), T1573 (Encrypted Channel).

#### Indicators of Compromise

```
Payload binary: UtilifySetup.exe
Family: ClickFix loader → DLL loader / JavaScript dropper / Electron stub
Vulnerability: CVE-2026-26980 (Ghost CMS SQL injection)
Fix version: Ghost CMS 6.19.1 or later
```

> **SOC Action:** Upgrade all Ghost CMS deployments to 6.19.1+ and **rotate every admin API key** issued before the patch. Pull 30 days of admin API call logs and review for unfamiliar `GET /ghost/api/admin/...` requests. EDR rule: alert on `cmd.exe` or `powershell.exe` launched immediately after Windows clipboard paste activity on browser host processes (ClickFix indicator). Block the XLab-published IOC list at the proxy/DNS layer.

### 3.5 Drupal Core SQL Injection Under Active Exploitation (CVE-2026-9082)

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/drupal-critical-sql-injection-flaw-now-targeted-in-attacks/)

Drupal updated its 18 May advisory on 22 May to confirm in-the-wild exploitation of CVE-2026-9082, an unauthenticated SQL injection in the database abstraction API that affects sites running on PostgreSQL. The project's internal severity score is 23/25 — its highest tier. The flaw can lead to remote code execution, privilege escalation and information disclosure. Affected versions span 8.9.x (EoL), 10.4.x, 10.5.x, 10.6.x, 11.0.x, 11.1.x, 11.2.x and 11.3.x; the patched releases are 10.4.10, 10.5.10, 10.6.9, 11.1.10, 11.2.12 and 11.3.10. The vulnerability was credited to Google/Mandiant's Michael Maturi.

**Affected products:** Drupal core on PostgreSQL backends (MySQL-only installations remain advised to patch because of bundled Symfony/Twig fixes).
**ATT&CK:** T1190 (Exploit Public Facing Application), T1059 (Command and Scripting Interpreter).

> **SOC Action:** Patch all Drupal sites to the relevant fixed branch immediately. Pull web-server logs for the past 14 days and grep for unusual PostgreSQL error strings or large `Content-Length` POSTs to Drupal endpoints. WAF rule: block requests containing single-quote-followed-by-`--` patterns aimed at `?q=` parameters until patched. Decommission or air-gap any Drupal 8/9 instances still in production.

### 3.6 Cisco Secure Workload — Max-Severity Site Admin Bypass (CVE-2026-20223)

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/cisco-max-severity-secure-workload-flaw-gives-hackers-site-admin-privileges/)

Cisco patched a CVSS 10.0 authentication and validation flaw in Secure Workload (formerly Tetration) internal REST APIs. A crafted API request lets an unauthenticated attacker read sensitive data and make configuration changes **across tenant boundaries** with Site Admin privileges. Cisco's PSIRT reports no evidence of pre-disclosure exploitation, but there is no workaround — only the fixed releases (3.10.8.3 and 4.0.3.17) remediate. SaaS deployments were patched server-side. The advisory follows the active exploitation of Cisco Catalyst SD-WAN CVE-2026-20182 earlier in May.

**Affected products:** Cisco Secure Workload 3.9 and earlier (migrate), 3.10 (< 3.10.8.3), 4.0 (< 4.0.3.17).
**ATT&CK:** T1190 (Exploit Public Facing Application), T1071.001 (Web Protocols).

> **SOC Action:** Patch on-premises Secure Workload clusters this week. Until patched, restrict the Secure Workload management VLAN to a small jump-host bastion and audit recent admin actions (segmentation policy changes, tenant role grants). Capture and review NetFlow to/from the Secure Workload appliance for anomalous outbound HTTP/HTTPS.

### 3.7 npm "Shai-Hulud" Worm Wave Continues — TeamPCP Hits Bitwarden CLI Impersonations

**Source:** [Unit 42](https://unit42.paloaltonetworks.com/monitoring-npm-supply-chain-attacks/), [AlienVault OTX](https://otx.alienvault.com/pulse/6a0c1b289f4fe8b7bdf00a84)

Unit 42's updated npm threat landscape report documents the latest wave of the **Shai-Hulud self-replicating worm**, attributed primarily to **TeamPCP**. Two May campaigns introduced novel TTPs: one used a credential-free initial-access technique, and the other produced the highest single-hour package compromise count of any Shai-Hulud iteration to date. A malicious `@bitwarden/cli` v2026.4.0 package was published as a multi-stage credential stealer that targets cloud-provider, CI/CD and developer-workstation tokens, then back-doors every npm package the victim can publish to self-propagate. Public GitHub repositories used in the campaign contain the string "Shai-Hulud: The Third Coming". A parallel `@antv` ecosystem compromise (Mini Shai-Hulud) affected over 300 packages, exfiltrating GitHub, npm, AWS and other secrets to a C2 with GitHub as fallback.

**Affected products:** npm ecosystem — Bitwarden CLI impersonation, @antv packages, Axios-style typosquats.
**ATT&CK:** T1195.002 (Compromise Software Supply Chain), T1552.001 (Credentials in Files), T1078 (Valid Accounts), T1567.002 (Exfiltration to Cloud Storage).

> **SOC Action:** Pin all npm dependencies to specific versions and enforce `npm install --ignore-scripts` in CI runners where feasible. Rotate any npm publishing tokens or GitHub PATs touched by a developer workstation that installed packages in the last 14 days. Block egress from CI/CD runners to non-allow-listed domains. Hunt for `@bitwarden/cli@2026.4.0` and unexpected post-install scripts in `package-lock.json` diffs.

### 3.8 `durabletask` PyPI Supply Chain Compromise Targets Cloud Secrets

**Source:** [Upwind](https://www.upwind.io/feed/newly-discovered-durabletask-malware-targeted-kubernetes-cloud-secrets-and-ci-cd-infrastructure)

Upwind identified three consecutive malicious releases of Microsoft's official **Azure Durable Task Python SDK** (`durabletask` 1.4.1, 1.4.2, 1.4.3) on PyPI on 19 May. A dropper in `durabletask/__init__.py` fetches `rope.pyz` from `check.git-service.com` and executes a multi-cloud credential framework targeting AWS, Azure, GCP and Kubernetes — including full Secrets Manager / Parameter Store dumping, HashiCorp Vault collection, and GitHub PAT theft. The payload is Linux-only, uses User-Agent filtering to block researchers, performs sandbox-aware CPU gating, deploys selective persistence, and includes a geopolitically targeted destructive routine. No GitHub tags or release entries exist for the three malicious versions, suggesting the attacker compromised the long-lived `PYPI_API_TOKEN` stored in GitHub Actions Secrets and uploaded the wheels directly via Twine.

**Affected products:** `durabletask` PyPI package versions 1.4.1, 1.4.2, 1.4.3 (yank or upgrade beyond malicious range).
**ATT&CK:** T1195.002 (Compromise Software Supply Chain), T1003 (OS Credential Dumping), T1552 (Credentials from Password Stores), T1078 (Valid Accounts), T1071 (Application Layer Protocol), T1562.001 (Impair Defenses).

#### Indicators of Compromise

```
PyPI versions: durabletask 1.4.1, 1.4.2, 1.4.3
Payload: rope.pyz
C2 host: check.git-service[.]com (TLS cert issued 2026-05-16)
Targets: AWS, Azure, GCP credentials; Kubernetes secrets; HashiCorp Vault; GitHub PATs
```

> **SOC Action:** Scan all build and runtime environments for the three malicious `durabletask` versions and forcibly downgrade or remove. Rotate any AWS, Azure, GCP, Kubernetes and HashiCorp Vault credentials accessible from CI/CD runners that pulled the package between 19–25 May. Block `check.git-service[.]com` at egress. Migrate Python publishing pipelines from long-lived API tokens to PyPI Trusted Publisher (OIDC).

### 3.9 SEO Poisoning Campaign Impersonates Gemini CLI and Claude Code

**Source:** [EclecticIQ via AlienVault OTX](https://blog.eclecticiq.com/seo-poisoning-campaign-leverages-gemini-and-claude-code-impersonation-to-deliver-infostealer)

EclecticIQ exposed a financially motivated campaign in which threat actors typosquat domains for Gemini CLI (`geminicli[.]co[.]com`, `gemini-setup[.]com`) and Claude Code (`claudecode[.]co[.]com`, `claude-setup[.]com`), then use SEO poisoning to surface those pages above legitimate vendor results. Developers are coached to paste a single PowerShell command into a terminal, which downloads an in-memory infostealer (`Install.ps1`) that harvests OAuth tokens, CI/CD credentials, corporate VPN configuration and sensitive files before exfiltrating to `events[.]msft23[.]com`. The malware also supports arbitrary remote code execution for hands-on-keyboard escalation.

**Affected products:** Windows developer workstations searching for AI coding assistant installers.
**ATT&CK:** T1583.001 (Acquire Infrastructure: Domains), T1608.005 (Stage Capabilities: SEO Poisoning), T1059.001 (PowerShell), T1566 (Phishing), T1539 (Steal Web Session Cookie).

#### Indicators of Compromise

```
Domains: geminicli[.]co[.]com, gemini-setup[.]com, claudecode[.]co[.]com, claude-setup[.]com, olive3451[.]com, get-monero[.]co[.]uk, chocolatey[.]net
Hostnames: events[.]msft23[.]com, events[.]ms709[.]com, metrics[.]msft17[.]com, api[.]bio9438[.]com, community[.]chocolatey[.]net, www[.]pinvoke[.]net
URLs: hxxps[:]//geminicli[.]com/, hxxp[:]//events[.]msft23[.]com/process, hxxps[:]//community[.]chocolatey[.]net/install[.]ps1|iex
SHA-256 (selected):
  0e8c45d847f57095d9879c0da764ab02431db4d5d85f50c4fd5ba38353b79eed
  1439d30ebeac3a6ccb9545acaa350783a83cc08746cb575e59ddb0efc77d412a
  27e17661f5573f63b65e3a5cfe5bdca75acdc1911441b032781f7ebe125d9194
  64d2a9a49e27d89f1b3489d7db29c3a3a12b4b090f59c24b694c239cb55db262
  a1c5e1d9bdc1a931c11ac6fdfdff1fbc69ff88521cf443cb174f9720a05fe72d
  efbf87447d93f4232b1169920f75c2066d19863ebc28fb2d2662353dc4ef61d8
  ff81cb9263fcde5870a0748fd6af2d30a4ba864415c15ca14827d0dd723eb60c
```

> **SOC Action:** Block the listed typosquat domains and C2 hostnames at proxy and DNS. Configure browser group policy to flag results outside an allow-list of vendor domains (e.g. `*.anthropic.com`, `ai.google.dev`) for AI tooling queries. Educate developers to install AI CLIs via package managers under the vendor's documented URL only. EDR rule: alert on `powershell.exe` invocations with `iex (New-Object Net.WebClient).DownloadString` patterns within five minutes of browser activity.

### 3.10 Ubiquiti UniFi OS Receives Three Max-Severity Patches

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/ubiquiti-patches-three-max-severity-unifi-os-vulnerabilities/)

Ubiquiti patched three CVSS 10.0 flaws in UniFi OS: **CVE-2026-34908** (Improper Access Control allowing unauthorized system changes), **CVE-2026-34909** (Path Traversal exposing underlying account files), and **CVE-2026-34910** (Improper Input Validation enabling command injection from the network). Two additional bugs were also fixed: CVE-2026-33000 (command injection) and CVE-2026-34911 (information disclosure). All five were reported via Ubiquiti's HackerOne programme and rated low-complexity to exploit. Censys tracks nearly **100,000 Internet-exposed UniFi OS endpoints**, ~50,000 in the United States; exploitation status is currently unknown.

**Affected products:** UniFi OS (UniFi Consoles, Network, Protect, Access, Talk and Connect apps).
**ATT&CK:** T1190 (Exploit Public Facing Application), T1059 (Command and Scripting Interpreter), T1078 (Valid Accounts).

> **SOC Action:** Update UniFi consoles to the latest UniFi OS release this week. Inventory internet-exposed UniFi devices and restrict management interfaces to a VPN-only ACL. Subscribe to Ubiquiti security advisories and assume Ubiquiti devices may be conscripted into botnets (precedent: FBI Moobot takedown, 2024) — monitor for unexpected outbound traffic from UniFi consoles.

### 3.11 ChromaDB Max-Severity RCE Threatens AI Application Backends (CVE-2026-45829)

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/max-severity-flaw-in-chromadb-for-ai-apps-allows-server-hijacking/)

HiddenLayer disclosed a CVSS 10.0 flaw in the Python FastAPI version of **ChromaDB**, the vector database used as a retrieval backend for many LLM and agentic-AI applications. An API endpoint marked as authenticated loads a model from Hugging Face **before** the authentication check fires; the server returns 500 to reject the request, but by then the malicious model has already executed. The flaw was introduced in 1.0.0; the vendor released 1.5.9 two weeks ago but it is unclear whether the patch is effective and the maintainer has not responded to disclosure attempts since 17 February. Shodan queries from HiddenLayer indicate **~73% of internet-exposed Chroma instances run a vulnerable version**. The PyPI package sees nearly 14 million downloads/month.

**Affected products:** ChromaDB Python FastAPI deployments exposed via HTTP. Local-only or Rust frontend deployments are not affected.
**ATT&CK:** T1190 (Exploit Public Facing Application), T1204.006 (User Execution: Malicious File), T1059 (Command and Scripting Interpreter).

> **SOC Action:** Audit internal AI platform inventory for ChromaDB; until the patch status is confirmed, restrict the Chroma API port (`8000` by default) to internal management VLANs only or migrate to the Rust frontend. Implement model-artefact scanning before any model is loaded by an AI service. Suspend or air-gap any internet-exposed ChromaDB deployments.

### 3.12 Huawei Zero-Day Caused Luxembourg Nationwide Telecom Outage

**Source:** [The Record (Recorded Future)](https://therecord.media/huawei-zero-day-behind-last-year-luxembourg-telecom-outage)

Multiple sources briefed RecordedFutures that the July 2025 nationwide outage at POST Luxembourg — which took down landline, 4G, 5G and emergency-call connectivity for over three hours — was triggered by a **previously undisclosed Huawei VRP zero-day**. Specially crafted network traffic placed Huawei enterprise routers in a continuous reboot loop. POST's investigation concluded the malicious traffic was simply transiting POST as a carrier and was not aimed at the operator. No CVE has been assigned and Huawei has issued no public advisory in the ten months since. Similar DoS-via-protocol-traffic flaws were patched in Huawei VRP previously (CVE-2021-22359, CVE-2022-29798).

**Affected products:** Huawei VRP-based enterprise routers carrying internet transit.
**ATT&CK:** T1499.004 (Endpoint DoS: Application or System Exploitation), T1071.001 (Web Protocols).

> **SOC Action:** Telecom and ISP operators running Huawei VRP equipment should engage Huawei directly for any non-public hotfixes covering this DoS class and consider rate-limiting or filtering anomalous protocol traffic at peering edges. Enterprises with Huawei branch routers should monitor for repeated unexpected reboots and have a manual reboot-and-isolation runbook ready.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Ransomware-as-a-Service groups expanding operations globally | Adensa Teknoloji / SECONT (Nova); Sponseller Group / Global Retool / ExpoCredit (Qilin); 115 Qilin-attributed reports this week |
| 🔴 **CRITICAL** | Exploitation of critical vulnerabilities in software leading to widespread impact | Ghost CMS ClickFix (CVE-2026-26980); NASM heap UAF (CVE-2026-6068); macOS sandbox bypass (CVE-2026-28910) |
| 🔴 **CRITICAL** | Supply chain attacks deploying credential-stealing malware | Laravel Lang packages hijacked; Roundcube CVE-2025-49113 RCE; durabletask PyPI compromise |
| 🔴 **CRITICAL** | Exploitation of widely-used technology stacks (Kubernetes, Rsync) | CVE-2026-45250 FreeBSD LPE; CVE-2026-43617/43618/43620/29518/45232 Rsync (5 CVEs) |
| 🔴 **CRITICAL** | npm and PyPI supply-chain campaigns by TeamPCP / Shai-Hulud | Mini Shai-Hulud TanStack packages; Shai-Hulud "Third Coming"; durabletask SDK; 600+ npm packages in May wave |
| 🟠 **HIGH** | The Gentlemen ransomware running broad coordinated multi-region campaign | Victims in Japan, China, Ireland, Turkey, Poland, Austria and US (Openmind Networks, Koa Glass, ACAM, TRANSSYSTEM, Caka Grup, Sanatorio Delta) |
| 🟠 **HIGH** | Increased ransomware activity in healthcare and finance | Papa John's Egypt, Bresme Madrid, "la familia adualt day center" (Nightspire) |
| 🟠 **HIGH** | Sophisticated phishing campaigns leveraging AI personas | "Patriot Bait" 5-year influence and fraud campaign; The Gentlemen defense-evasion analysis |
| 🟠 **HIGH** | Cloud and AI-tooling sectors increasingly targeted | TeamPCP GitHub internal-repo breach; ChromaDB max-severity; Microsoft Self-Service Password Reset abuse |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **Qilin** (115 reports) — Dominant RaaS operator this week; multiple new leak-site postings including Sponseller Group, Global Retool and ExpoCredit
- **Akira** (68 reports) — Double-extortion across education, healthcare and manufacturing (Karlin Foods, Gitis, Function Enterprises, Buffalo Niagara Convention Center)
- **The Gentlemen** (64 reports) — Coordinated multi-region campaign across logistics, engineering and technology in Japan, China, Ireland, Turkey, Poland, Austria and US
- **TeamPCP** (34 reports) — Primary attribution for the May Shai-Hulud npm worm waves and GitHub internal-repository breach
- **ShinyHunters** (28 reports) — Active extortion against Charter Communications and Baker Distributing Company
- **Inc Ransom** (24 reports) — Continuing leak-site postings (Meirc Training and Consulting this week)
- **DragonForce** (19 reports) — Sustained leak-site activity
- **Safepay** (19 reports) — Phishing-led intrusions; named alongside Microsoft password-reset abuse coverage
- **Lockbit5** (19 reports) — Ongoing leak-site postings; lower velocity than April
- **Nightspire** (18 reports) — Healthcare and food-service victims (Papa John's Egypt, Bresme Madrid)
- **Everest** (18 reports), **FulcrumSec** (17), **Stormous** (16), **Nova/RALord** (16), **Lamashtu** (15) — Long-tail RaaS / data-broker activity

### Malware Families

- **RansomLook** (141 mentions) — Leak-site aggregator infrastructure observed across most RaaS postings
- **Akira ransomware** (37) and **Akira** (21) / **Akira Ransomware** (14) — Active payload across 60+ victims this week
- **Tox1** (34) and **Tox** (18) — Encrypted-messaging tooling used for RaaS C2 / negotiation
- **Mini Shai-Hulud** (10), **Shai-Hulud** (8) — Self-replicating npm supply-chain worms in active waves
- **The Gentlemen** (14) — Ransomware payload tied to the cross-region campaign
- **Qilin** (15) — Payload tooling for the dominant RaaS operator
- **RaaS** (11) — Generic tooling references across multiple leak-site disclosures
- **Nova** (10) / **RALord** (9) — Rebranded RaaS operation; expanding leak-site postings
- **Nightspire** (9) — Payload tied to healthcare/food-service intrusions
- **durabletask / rope.pyz** (new) — Microsoft Azure Durable Task Python SDK PyPI compromise — multi-cloud credential framework
- **UtilifySetup.exe** (new) — Electron-based ClickFix payload delivered via Ghost CMS exploitation

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| Microsoft | 201 | [link](https://msrc.microsoft.com/update-guide) | MSRC advisories — Rsync CVE cluster, Defender zero-days, Azure SDK, rust-openssl, xmldom, cmd/go |
| RansomLook | 186 | [link](https://www.ransomlook.io/) | Leak-site postings — Qilin, Akira, The Gentlemen, Nightspire, Nova dominate |
| BleepingComputer | 47 | [link](https://www.bleepingcomputer.com) | Primary coverage of zero-day disclosures (Apex One, Defender, YellowKey, Ghost CMS, Drupal, Cisco, Ubiquiti, ChromaDB) |
| AlienVault | 37 | [link](https://otx.alienvault.com) | OTX pulses — Ghost CMS, npm/@antv compromise, SEO poisoning |
| RecordedFutures | 18 | [link](https://therecord.media) | Luxembourg POST telecom outage attribution |
| Unknown | 16 | — | Telegram (channel name redacted) — CVE write-ups and PoC disclosures |
| CISA | 12 | [link](https://www.cisa.gov/news-events/cybersecurity-advisories) | ICS advisories — ABB B&R Automation Studio, ScadaBR, Siemens RUGGEDCOM APE1808, ZKTeco CCTV |
| SANS | 9 | [link](https://isc.sans.edu) | Analysis posts including TeamPCP supply chain coverage |
| Wired Security | 9 | [link](https://www.wired.com/category/security/) | Long-form analysis pieces |
| Schneier | 8 | [link](https://www.schneier.com/blog) | CISA security leak coverage; YellowKey BitLocker; macOS kernel exploit |
| Unit42 | 5 | [link](https://unit42.paloaltonetworks.com/monitoring-npm-supply-chain-attacks/) | npm threat-landscape updates documenting Shai-Hulud / TeamPCP waves |
| HaveIBeenPwned | 5 | [link](https://haveibeenpwned.com) | Breach corpus additions |
| Upwind | 4 | [link](https://www.upwind.io/feed/newly-discovered-durabletask-malware-targeted-kubernetes-cloud-secrets-and-ci-cd-infrastructure) | `durabletask` PyPI supply chain compromise disclosure |
| Wiz | 4 | [link](https://www.wiz.io/blog) | Cloud security research |
| Krebs on Security | 3 | [link](https://krebsonsecurity.com) | Investigative reporting |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Patch Trend Micro Apex One (CVE-2026-34926), Microsoft Defender Malware Protection Engine ≥ 1.1.26040.8 / Antimalware Platform ≥ 4.18.26040.7, and Drupal core (CVE-2026-9082) before the CISA federal deadlines of 3–4 June. These flaws are actively exploited and impact security-critical infrastructure.
- 🔴 **IMMEDIATE:** Force-remove `durabletask` versions 1.4.1, 1.4.2 and 1.4.3 from all build and runtime environments and rotate AWS, Azure, GCP, Kubernetes and HashiCorp Vault credentials accessible from any CI/CD runner that touched the package between 19 and 25 May.
- 🔴 **IMMEDIATE:** Upgrade Ghost CMS to 6.19.1+, rotate every admin API key, and pull 30 days of admin API logs to investigate post-compromise activity. Block the XLab IOC list at the proxy.
- 🟠 **SHORT-TERM:** Patch Cisco Secure Workload (3.10.8.3 / 4.0.3.17) and Ubiquiti UniFi OS this week. Both vendors patched CVSS 10.0 flaws with low exploitation complexity; assume internet-exposed instances will be scanned within days.
- 🟠 **SHORT-TERM:** Convert BitLocker from TPM-only to TPM+PIN on all laptops and remove `autofstx.exe` from BootExecute to mitigate the YellowKey (CVE-2026-45585) exploit pending a Microsoft code fix. Refresh lost-device IR runbooks.
- 🟠 **SHORT-TERM:** Migrate Python and Node publishing pipelines to OIDC / PyPI Trusted Publisher and rotate any long-lived `PYPI_API_TOKEN` or npm publish tokens held in GitHub Actions Secrets. The `durabletask` and Shai-Hulud campaigns both abused long-lived publishing tokens.
- 🟡 **AWARENESS:** Brief developer teams on the SEO-poisoning typosquat campaign impersonating Gemini CLI and Claude Code. Add `geminicli[.]co[.]com`, `gemini-setup[.]com`, `claudecode[.]co[.]com`, `claude-setup[.]com`, `events[.]msft23[.]com`, `chocolatey[.]net` and the EclecticIQ hashes to detection. Enforce "install from documented vendor URL only" policy.
- 🟡 **AWARENESS:** Inventory ChromaDB and other AI-application backends; restrict to internal networks until CVE-2026-45829 patch effectiveness is confirmed. Treat third-party ML-model artefacts as untrusted code and scan before runtime load.
- 🟢 **STRATEGIC:** Build a supply-chain incident response runbook covering both npm and PyPI worm-class events: pinned dependencies, automated lockfile diffing, restricted post-install scripts in CI, egress allow-listing from build runners, and an enterprise-wide token rotation procedure. Shai-Hulud and durabletask demonstrate this is now a recurring incident class, not an exception.
- 🟢 **STRATEGIC:** Track RaaS leak-site activity (Qilin, Akira, The Gentlemen, Nightspire, TeamPCP) as a leading indicator of sector targeting and adjust threat-hunting priorities accordingly. The Gentlemen's coordinated multi-region wave suggests broader infrastructure prepositioning.

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 577 reports processed across 15 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
