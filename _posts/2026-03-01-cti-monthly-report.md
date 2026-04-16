---
layout: post
title:  "CTI Monthly Report: March 2026 - TeamPCP Supply Chain Siege, CanisterWorm Iran Wiper, Handala Stryker Intrusion, DarkSword iOS KEV, Ransomware Surge"
date:   2026-04-16 09:00:00 +0000
description: "March 2026 saw a historic supply chain campaign by TeamPCP across Trivy, LiteLLM, Checkmarx KICS, Telnyx, Axios, and OpenVSX; the CanisterWorm Kubernetes wiper targeting Iranian infrastructure; Handala's destructive wipe of 80,000 Stryker medical devices via Intune; CISA KEV additions for the DarkSword iOS exploit chain; and a sustained ransomware surge led by Qilin, The Gentlemen, Nightspire, TeamPCP, and DragonForce."
category: monthly
tags: [cti, monthly-report, teampcp, canisterworm, handala, qilin, darksword, cve-2026-20963, cve-2026-3909, cve-2026-3910, tycoon2fa, react2shell, voidlink]
classification: TLP:CLEAR
reporting_period_start: "2026-03-01"
reporting_period_end: "2026-03-31"
generated: "2026-04-16"
severity: "critical"
draft: false 
report_count: 1320
sources:
  - BleepingComputer
  - Microsoft
  - SANS
  - Schneier
  - Wired Security
  - Krebs on Security
  - The Hacker News
  - CISA
  - Google TAG
  - Rapid7
  - watchTowr
  - Telegram OSINT
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-03-01 to 2026-03-31 (March 2026) | TLP:CLEAR | 2026-04-16 |

## 1. Executive Summary

March 2026 was dominated by a single theme: **trusted software supply chains weaponised at scale**. The threat cluster tracked as **TeamPCP** chained compromises across at least six widely deployed developer and infrastructure projects — Trivy, LiteLLM, Checkmarx KICS, Telnyx, Axios, and OpenVSX — seeding credential-stealing payloads into CI/CD pipelines used by thousands of downstream organisations. Stolen secrets from one compromise were used to seed the next, producing a cross-pollinated supply-chain incident without close recent parallel. In parallel, a previously unreported worm dubbed **CanisterWorm** exploited misconfigured Kubernetes DaemonSets to deploy destructive wipers across Iranian industrial and telecommunications infrastructure, and the **Handala** operation publicly claimed an Intune-borne wipe of approximately 80,000 Stryker-managed medical devices alongside a leak of FBI Director Patel's personal email. CISA added six vulnerabilities underpinning the **DarkSword** iOS exploit chain to the KEV catalogue after operator **UNC6353** (Russia-linked) and **UNC6748** (a PARS Defense customer) were observed in active deployments against journalists, dissidents, and defence-industrial-base personnel. On the vulnerability front, Chrome shipped emergency patches for two in-the-wild zero-days (**CVE-2026-3909** in Skia, **CVE-2026-3910** in V8) and Microsoft remediated an unauthenticated SharePoint RCE (**CVE-2026-20963**, CVSS 9.8) which saw public PoC release mid-month. Ransomware activity remained at record volumes with **Qilin** (55 leak-site disclosures), **The Gentlemen** (48), **Nightspire** (37), the **TeamPCP** ransomware sibling brand (32), and **DragonForce** (27) leading victim counts, while two notable brand additions — **Coinbase Cartel** and **shadowbyt3$** — established leak-site presences. AI-generated malware moved from theoretical concern to observed-in-the-wild with the **React2Shell** and **VoidLink** families, and the previously disrupted **Tycoon2FA** MFA-phishing PaaS returned with fresh infrastructure at volumes higher than its pre-takedown baseline. Across the month the CognitiveCTI pipeline processed **1,320 reports across 39 correlation batches**, with critical-severity reporting concentrated on supply chain abuse, destructive attacks, and zero-day exploitation. The strategic takeaway is consistent across every top-tier incident this month: **identity, secrets, and trust relationships are the new primary attack surface**, and defensive programmes that still anchor to endpoint telemetry alone will be badly outpaced.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 142 | TeamPCP supply chain chain-compromise; CanisterWorm Iran wiper; Handala/Stryker; DarkSword iOS CISA KEV; Chrome CVE-2026-3909/3910; SharePoint CVE-2026-20963; LiteLLM PyPI compromise |
| 🟠 **HIGH** | 318 | Qilin/Akira/Nightspire/DragonForce/PLAY ransomware operations; FBI Director Patel email leak; Tycoon2FA PaaS resurgence; SharePoint PoC release; Intune abuse patterns |
| 🟡 **MEDIUM** | 602 | Chromium batch advisories; AI-generated malware (React2Shell, VoidLink); Coinbase Cartel/The Gentlemen extortion claims; RegPwn registry analysis; Samsung compat issues |
| 🟢 **LOW** | 178 | SmartApeSG loader variants; Samsung One UI compatibility issues; vendor low-severity advisories; commodity phishing campaigns |
| 🔵 **INFO** | 80 | Defend4Container research; pipeline telemetry notes; threat landscape backgrounders |

**Month-over-month observation:** Critical-severity volume rose sharply versus February 2026 (estimated ~90 critical-severity reports), driven almost entirely by the TeamPCP chain and CanisterWorm coverage cascades. High-severity volume remained comparable to February; medium-severity growth is primarily Chromium advisory expansion and the emerging AI-malware reporting beat.

## 3. Priority Intelligence Items

### 3.1 TeamPCP Supply Chain Siege Across Six Ecosystems
**Source:** [BleepingComputer](https://www.bleepingcomputer.com), [The Hacker News](https://thehackernews.com), [SANS ISC](https://isc.sans.edu)

Throughout March, a threat cluster tracked as **TeamPCP** executed staged compromises of multiple developer tooling and infrastructure supply chains. Confirmed affected projects include **Trivy** (container scanner), **LiteLLM** (PyPI package, malicious versions 1.78.5–1.79.0), **Checkmarx KICS** (IaC scanner), **Telnyx** (telecom API SDK), **Axios** (HTTP client, npm and Python variants), and **OpenVSX** (VS Code extension registry). Implants harvested CI/CD secrets — GitHub/GitLab Personal Access Tokens, AWS access keys, npm publish tokens, Azure service-principal credentials, and Kubernetes service-account tokens — and in several cases used the stolen credentials to pivot into adjacent projects and seed new malicious releases. The cross-pollination pattern means a downstream organisation that installed only one of the six affected packages is nonetheless exposed via the transitive trust chain. Post-compromise behaviour included outbound staging to Cloudflare Workers (`*.workers.dev`) and Fastly edge endpoints before callback to actor infrastructure, consistent with living-off-trusted-infrastructure tradecraft intended to evade simple egress monitoring.

TeamPCP operates a parallel ransomware-style extortion brand — not all intrusions end in a supply-chain implant; some result in data theft and leak-site publication of victims whose CI/CD credentials were harvested. This is the most significant structural innovation of the campaign: the group has reduced the marginal cost of a new ransomware victim to "whichever organisation happened to rebuild against a poisoned package this week," which decouples victim selection from the usual initial-access marketplace.

**Affected sectors:** Software development, cloud, MSSPs, financial services, any organisation consuming the listed packages. MITRE ATT&CK: **T1195.002** (Supply Chain Compromise: Software Supply Chain), **T1552.001** (Credentials in Files), **T1213** (Data from Information Repositories), **T1071.001** (Application Layer Protocol: Web Protocols), **T1567** (Exfiltration Over Web Service).

#### Indicators of Compromise
```
LiteLLM malicious versions: 1.78.5, 1.78.6, 1.78.7, 1.79.0
Trivy malicious builds: releases between 2026-03-08 and 2026-03-22
Staging domain: teampcp-update[.]workers[.]dev
Staging domain: cdn-mirror-pkg[.]fastly[.]net
C2: 185.234.52[.]183:443
C2: 45.153.242[.]77:443
SHA256 (litellm payload): 3f9ac7b1e0d84c2a5fe8b927d6e41cb0a2f5d3e89c07b12a4e61cfa38d72b905
SHA256 (trivy post-install hook): e982ac17bd53fcaa09c9e7b6d18ab3f25f6e3d7e44ca1e09a4c7bdfe23aa81fd
User-Agent: axios/1.x (node) — used even by non-Axios-derived variants
```

> **SOC Action:** Immediately query package-inventory and CI/CD logs for installations of LiteLLM versions 1.78.5 through 1.79.0, Trivy builds installed between 2026-03-08 and 2026-03-22, and the affected Checkmarx KICS, Telnyx SDK, Axios, and OpenVSX extensions published in that window. Rotate **all** CI/CD secrets exposed to those runners, including GitHub/GitLab PATs, npm tokens, AWS keys, Azure service principals, and Kubernetes service-account tokens. Block egress to `teampcp-update[.]workers[.]dev`, `cdn-mirror-pkg[.]fastly[.]net`, and the listed IPs. Enforce package-pinning with hash verification, mandatory signature verification (Sigstore/cosign), and runner egress allow-lists. Audit GitHub/GitLab organisation audit logs for unusual release publication or token creation events across the last 60 days.

### 3.2 CanisterWorm Kubernetes DaemonSet Wiper Targets Iran
**Source:** [BleepingComputer](https://www.bleepingcomputer.com), [Wired Security](https://www.wired.com)

A self-propagating destructive tool dubbed **CanisterWorm** used exposed Kubernetes API servers and misconfigured RBAC to schedule malicious **DaemonSets** across every node in a cluster, then invoked `dd`, `blkdiscard`, and direct writes to raw block devices to destroy data. Observed targets were concentrated in Iranian telecommunications, petrochemical, and port-operator environments. No ransom note was dropped — the intent was destruction, not extortion — and the activity aligns temporally with ongoing regional tensions. The worm component attempts to pivot laterally by scanning RFC1918 address space for additional Kubernetes API servers exposed with default or weak authentication, and a second attempted cluster against a non-Iranian target late in the month suggests proliferation risk beyond the initial victim set. MITRE ATT&CK: **T1610** (Deploy Container), **T1485** (Data Destruction), **T1078** (Valid Accounts), **T1613** (Container and Resource Discovery), **T1046** (Network Service Discovery).

#### Indicators of Compromise
```
Container image: registry-proxy[.]cdn-cf[.]net/canworm:v3
DaemonSet name pattern: kube-node-metrics-*
C2: 193.178.170[.]155:443
Domain: retrypoti[.]top
Domain: k8s-telemetry-sync[.]xyz
SHA256 (wiper binary): b170ffc861d8e5ac42fb903d7ee15c89a64ff2fb61a3c7d9e204187cfa3e8d51
SHA256 (worm loader): a4c82d1e97b03f5e6dd9f0a12e87b43ca56fd1b08e27a4b61c9e0fd385a712e0
```

> **SOC Action:** Audit Kubernetes API-server exposure and enforce network segmentation so that only bastion/jump hosts can reach the API. Remove the `system:unauthenticated` group from every cluster role binding; no legitimate use case survives this check. Hunt for DaemonSets that mount `hostPath`, carry `privileged: true`, or reference registries outside your approved-registry list. Alert on `blkdiscard`, `dd if=/dev/zero`, and unexplained writes to `/dev/sd*` or `/dev/nvme*n1` inside container runtime logs. Enforce Pod Security Admission `restricted` profile cluster-wide. For organisations running multi-cluster estates, centralise audit-log ingestion and write correlation detections that alert on the same DaemonSet name appearing across clusters within a short window.

### 3.3 Handala Wipes ~80,000 Stryker Medical Devices via Intune; FBI Director Email Leaked
**Source:** [BleepingComputer](https://www.bleepingcomputer.com), [Krebs on Security](https://krebsonsecurity.com)

The Iran-aligned **Handala** group claimed a destructive intrusion against Stryker that used a compromised Intune tenant to push a Win32 app deployment policy triggering `cipher /w` across approximately 80,000 managed endpoints — including surgical-navigation and imaging workstations in hospitals globally. No custom malware was deployed; the attack relied entirely on abuse of legitimate Intune configuration rights to push a signed tool that performs destructive secure-delete operations. Initial access is reported to have been obtained via adversary-in-the-middle (AiTM) phishing against an Intune-privileged administrator whose session was replayed to add an attacker-controlled app registration with device-management graph permissions. MITRE ATT&CK: **T1484.001** (Group Policy Modification), **T1485** (Data Destruction), **T1078.004** (Valid Accounts: Cloud Accounts), **T1557** (Adversary-in-the-Middle), **T1098** (Account Manipulation).

Separately but concurrently, Handala dumped a cache of emails allegedly from FBI Director Patel's personal Gmail account, driving significant press attention but limited operational IOCs. The leak has not been independently authenticated at the time of writing, and responsible handling requires treating the content as unverified pending formal confirmation.

> **SOC Action:** Audit Intune Global Administrator and Intune Administrator role assignments; enforce Privileged Identity Management (PIM) time-bound activation with MFA for every privileged role. Review **all** Win32 app deployment assignments for the last 60 days and alert on new deployments targeting large device groups or "All Devices"/"All Users" scopes. Enable Microsoft Entra ID Protection risk-based policies for identities with device-management rights. Enforce phishing-resistant MFA (FIDO2 / Windows Hello for Business) for every Intune-privileged account. For healthcare: validate offline/immutable backup recoverability for clinical workstations against a 4-hour RTO, and rehearse an isolated-tenant rebuild playbook. Hunt Entra ID audit logs for app-registration creation events in the last 60 days where the application was granted Intune device-management or `DeviceManagementConfiguration.ReadWrite.All` scopes.

### 3.4 DarkSword iOS Exploit Chain — Six CVEs Added to CISA KEV
**Source:** [CISA](https://www.cisa.gov), [The Hacker News](https://thehackernews.com), [Wired Security](https://www.wired.com)

CISA added six CVEs underpinning the **DarkSword** commercial iOS exploit chain to the Known Exploited Vulnerabilities catalogue after corroborated observations of deployment by Russia-linked **UNC6353** and **UNC6748** (a customer of Iranian vendor **PARS Defense**). The chain achieves zero-click RCE and sandbox escape against iOS 18.x prior to Apple's emergency point release 18.4.1. Victimology centred on journalists, exiled dissidents, defence-industrial-base personnel, and selected policy researchers. Delivery observed across iMessage attachment parsers and WebKit drive-by chains from targeted spear-phish links. MITRE ATT&CK: **T1068** (Exploitation for Privilege Escalation), **T1055** (Process Injection), **T1189** (Drive-by Compromise — for WebKit variant), **T1203** (Exploitation for Client Execution), **T1203** plus **T1056.001** (Keylogging) in the post-exploitation stage.

The simultaneous appearance of a Russia-linked operator and a PARS Defense customer on the same vendor chain reinforces an emerging pattern: commercial spyware vendors increasingly sell to multiple state clients whose interests only partially overlap, producing an exploit-reuse risk that amplifies the blast radius of any single customer's operational security failure.

> **SOC Action:** Enforce iOS 18.4.1 minimum OS version in MDM compliance policies for all managed iPhones; mark non-compliant devices as unmanaged and block corporate resource access. Enable Apple Lockdown Mode for high-risk roles (executives, journalists, legal, M&A, HR, board). Ingest the six KEV CVEs into vulnerability management with federal 2026 KEV-due-date SLAs. Monitor for unusual iCloud backup exfiltration patterns against at-risk accounts (velocity anomalies, new device registrations, unexplained 2FA prompts). Provide Lockdown Mode briefings to impacted role populations and document the trade-offs so users do not reflexively disable it.

### 3.5 Chrome Zero-Days CVE-2026-3909 (Skia) and CVE-2026-3910 (V8)
**Source:** [BleepingComputer](https://www.bleepingcomputer.com), [The Hacker News](https://thehackernews.com), [Google TAG](https://blog.google/threat-analysis-group/)

Google shipped an emergency Chrome Stable channel update addressing two in-the-wild zero-days: **CVE-2026-3909** (heap corruption in Skia, used for sandbox escape) and **CVE-2026-3910** (type confusion in V8, used for initial RCE). Exploitation chains were attributed by Google TAG to a commercial spyware vendor targeting civil society; the chain shared infrastructure overlap with DarkSword staging domains, raising the possibility that the same vendor or an affiliated operator is behind both chains. Edge, Brave, Opera, and Vivaldi shipped downstream fixes within 72 hours. MITRE ATT&CK: **T1189** (Drive-by Compromise), **T1203** (Exploitation for Client Execution), **T1055** (Process Injection for sandbox escape).

> **SOC Action:** Force Chrome/Chromium-based browser updates to the remediated build via GPO/Intune configuration profiles within 24 hours; verify enforcement via a telemetry query rather than trusting the policy push. Query EDR for browser processes spawning `cmd.exe`, `powershell.exe`, `wscript.exe`, `mshta.exe`, or unknown children during the exposure window. Ingest TAG-published IOCs into web proxy blocklists. Consider site-isolation-enforcement, SmartScreen enhancements, and Enhanced Safe Browsing for high-risk user populations. For civil-society-adjacent roles, pair with the §3.4 Lockdown Mode recommendations.

### 3.6 SharePoint Unauthenticated RCE — CVE-2026-20963 (CVSS 9.8)
**Source:** [Microsoft](https://msrc.microsoft.com), [BleepingComputer](https://www.bleepingcomputer.com), [watchTowr](https://labs.watchtowr.com), [Rapid7](https://www.rapid7.com/blog/)

Microsoft patched **CVE-2026-20963**, a pre-authentication remote code execution affecting on-premises SharePoint Server Subscription Edition and SharePoint 2019. The vulnerability allows a remote unauthenticated attacker to execute arbitrary code in the SharePoint service-account context via a crafted SOAP payload routed through a deserialisation sink in a legacy collaboration endpoint. Rapid7 and watchTowr published technical analyses and PoC code was released mid-month — historically a reliable precursor to mass exploitation within 7–14 days. Active exploitation had not been confirmed by month-end but scanning volumes against SharePoint endpoints rose substantially in the final week. MITRE ATT&CK: **T1190** (Exploit Public-Facing Application), **T1505.003** (Server Software Component: Web Shell), **T1059.001** (PowerShell), **T1078.002** (Valid Accounts: Domain Accounts, for post-exploitation pivot).

> **SOC Action:** Apply the March Security Update to all on-prem SharePoint farms within 48 hours. If patching is blocked, place affected farms behind an authenticated reverse proxy or WAF with SOAP-body filtering and body-size limits. Hunt in IIS logs (`LAYOUTS/15/*.aspx`) for anomalous POSTs with large XML bodies and for new `.aspx` files dropped under `_layouts` or `_catalogs` in the last 30 days. Audit SharePoint service-account permissions; if the account has domain-wide rights, reduce to least privilege immediately. Enable AMSI for SharePoint where available.

### 3.7 LiteLLM PyPI Package Compromise (Sub-Campaign of TeamPCP)
**Source:** [The Hacker News](https://thehackernews.com), [SANS ISC](https://isc.sans.edu)

Although covered under §3.1, the **LiteLLM** compromise warrants standalone treatment given the package's pervasive use in LLM gateway deployments. Affected versions (1.78.5–1.79.0) carried a post-install hook that exfiltrated environment variables — including OpenAI, Anthropic, Azure OpenAI, AWS Bedrock, Google Vertex, and self-hosted inference-endpoint credentials — to actor infrastructure. Downstream impact included several third-party AI platforms whose hosted LiteLLM gateways passed customer keys through the malicious runtime, producing a secondary exposure population who never installed the package themselves. The hook also captured `LITELLM_MASTER_KEY` values used to administer LiteLLM tenancy, enabling tenant-level pivoting in multi-tenant deployments. MITRE ATT&CK: **T1195.002**, **T1552.001**, **T1552.005** (Credentials from Password Stores: Cloud Credentials), **T1528** (Steal Application Access Token).

> **SOC Action:** In addition to §3.1 remediation, rotate **all** third-party LLM API keys that passed through a LiteLLM gateway during the compromise window. Audit cloud-provider CloudTrail / Activity Log / Audit Log for anomalous inference calls from new source IPs or unusual model selections. Enforce per-key spend caps, egress allow-lists, and rate limits on LLM gateway egress. For organisations offering hosted LLM services to customers, issue a proactive customer advisory and coordinate key-rotation assistance — silence here invites regulatory scrutiny.

### 3.8 Ransomware Surge — Qilin, The Gentlemen, Nightspire, DragonForce, Coinbase Cartel
**Source:** [BleepingComputer](https://www.bleepingcomputer.com), Telegram (channel name redacted)

March saw sustained ransomware activity with **Qilin** posting 55 victim disclosures, **The Gentlemen** 48, **Nightspire** 37, the **TeamPCP** ransomware sibling 32, **DragonForce** 27, **Coinbase Cartel** 26, and **Akira** 22. Notable single victims included a US regional hospital system (Qilin), a European automotive Tier-1 supplier (DragonForce), and a UK critical-national-infrastructure MSP (Akira). Tradecraft commonalities across affiliates included ScreenConnect/AnyDesk for persistence, Impacket and Certipy for lateral movement, and Rclone to MEGA (or Backblaze B2) for exfiltration. A marked shift this month: encryption is increasingly optional — several affiliates (notably The Gentlemen and Coinbase Cartel) did not deploy an encryptor at all, operating on data-theft-and-extort alone. MITRE ATT&CK: **T1486** (Data Encrypted for Impact), **T1567.002** (Exfiltration to Cloud Storage), **T1219** (Remote Access Software), **T1003.006** (OS Credential Dumping: DCSync), **T1482** (Domain Trust Discovery).

> **SOC Action:** Detect unauthorised RMM installs (ScreenConnect, AnyDesk, Atera, Splashtop, Action1) via application-control and EDR; block unsanctioned installers at the proxy. Block Rclone execution outside approved admin workstations with application-control policies. Audit external-facing VPN and Citrix portals for weak/absent MFA; these remain the dominant affiliate entry path. Validate immutable backup restore times against 4-hour RTO targets. Hunt for DCSync events and Certipy abuse signatures (ESC1/ESC3/ESC8) in the last 90 days.

### 3.9 Tycoon2FA PaaS Returns Post-Takedown with New Infrastructure
**Source:** [BleepingComputer](https://www.bleepingcomputer.com), [The Hacker News](https://thehackernews.com)

The **Tycoon2FA** MFA-phishing PaaS, disrupted in a late-2025 takedown, re-emerged in March at volumes higher than its pre-takedown baseline. The new iteration features improved evasion (browser-based fingerprinting and TLS-client-hello mimicry that defeats several popular headless detonation sandboxes), CAPTCHA gates on victim-facing proxy pages to frustrate automated reconnaissance, and reuse-resistant session cookies with short lifetimes that narrow the defender replay window. Microsoft 365 and Google Workspace credential theft are the dominant use cases; downstream effects include BEC, OAuth consent phishing for persistence, and Intune-privileged account compromise (linked to the §3.3 Handala methodology). MITRE ATT&CK: **T1566.002** (Spearphishing Link), **T1557** (AiTM), **T1550.004** (Use Alternate Authentication Material: Web Session Cookie), **T1078.004** (Valid Accounts: Cloud).

> **SOC Action:** Enforce phishing-resistant MFA (FIDO2 / Windows Hello for Business / platform-bound passkeys) for privileged accounts; deprecate OTP-based MFA where possible. Implement conditional-access policies requiring compliant / hybrid-joined devices for privileged roles. Monitor Entra ID sign-in logs for AiTM indicators: anomalous user-agent strings, unusual autonomous-system numbers, impossible-travel signals, and token-replay attempts. Ingest Tycoon2FA infrastructure IOCs into proxy blocklists.

### 3.10 AI-Generated Malware Observed In-the-Wild — React2Shell and VoidLink
**Source:** [The Hacker News](https://thehackernews.com), Microsoft

Two malware families analysed this month — **React2Shell** (a JavaScript-based webshell backdoor) and **VoidLink** (a Go-based loader) — carry hallmarks of LLM-assisted development: unusually verbose inline documentation, import patterns more typical of tutorial code than production malware, and function-naming conventions that mirror common LLM outputs. Operationally the families are not exceptional, but their ease of production lowers the barrier for lower-tier actors to field bespoke tooling and complicates hash- and signature-based detection. MITRE ATT&CK: **T1505.003** (Web Shell), **T1059.007** (Command and Scripting Interpreter: JavaScript), **T1105** (Ingress Tool Transfer).

> **SOC Action:** Shift detection weighting from hash/signature to behaviour — assume an endless supply of novel-but-mundane malware. Prioritise script-content inspection and AMSI telemetry; for webshells, focus on file-write anomalies in web directories and anomalous user-agent patterns hitting newly created endpoints. Brief IR teams that novel-looking code may no longer imply a sophisticated adversary.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Supply chain cross-pollination — credentials stolen from one package compromise used to seed the next | TeamPCP chain: Trivy → LiteLLM → Checkmarx KICS → Telnyx → Axios → OpenVSX, tracked across six discrete correlation batches in March |
| 🔴 **CRITICAL** | Kubernetes-native destructive attacks emerge as a distinct TTP | CanisterWorm DaemonSet wiper; second cluster attempted against non-Iranian target late March; aligns with Microsoft Threat Intel advisory on Kubernetes RBAC abuse |
| 🔴 **CRITICAL** | Destructive wiping via legitimate endpoint-management planes ("LotEDM") | Handala/Stryker Intune abuse mirrors earlier SCCM-abuse patterns; extends the "no-malware" destructive playbook to cloud EDM tooling |
| 🔴 **CRITICAL** | Commercial spyware vendor chains linked across multiple state operators | DarkSword used by UNC6353 (Russia-linked) and UNC6748 (PARS Defense customer); infrastructure overlap with Chrome zero-day chain (CVE-2026-3909/3910) |
| 🟠 **HIGH** | AI-generated malware moves from theoretical concern to observed in-the-wild | React2Shell and VoidLink families analysed by multiple vendors; hash/signature-based detection losing marginal value |
| 🟠 **HIGH** | MFA-phishing-as-a-service resurgence after disruption | Tycoon2FA returns post-takedown with new infrastructure; higher volume than pre-takedown baseline; OTP MFA now a known-bad posture |
| 🟠 **HIGH** | Encryption-optional ransomware business models continue to grow | The Gentlemen, Coinbase Cartel, and others operating data-theft-only extortion; reduces operator risk while preserving leverage |
| 🟠 **HIGH** | Identity-platform compromise as initial access displaces endpoint exploits | Across Handala, TeamPCP, and multiple ransomware incidents, identity-provider or IdP-adjacent access was the precipitating event |
| 🟡 **MEDIUM** | Chromium-adjacent advisories clustering around V8 and rendering engines | Two zero-days plus four critical-severity advisories in March alone |
| 🟡 **MEDIUM** | Healthcare sector pressure intensifying | Stryker mass-wipe plus Qilin US hospital ransomware; sector-wide IOC and TTP sharing warranted |

## 5. Vulnerability Landscape

Month-notable CVEs published or exploited in March 2026:

| CVE | Product | CVSS | Exploited? | Notes |
|-----|---------|------|------------|-------|
| CVE-2026-20963 | Microsoft SharePoint (SE / 2019) | 9.8 | PoC public; scanning observed | Unauthenticated RCE; SOAP deserialisation |
| CVE-2026-3909 | Google Chrome (Skia) | High | Yes (ITW) | Sandbox escape half of TAG-tracked chain |
| CVE-2026-3910 | Google Chrome (V8) | High | Yes (ITW) | Initial RCE half of TAG-tracked chain |
| CVE-2026-nnnn × 6 | Apple iOS / iPadOS | Various | Yes (ITW — DarkSword) | CISA KEV; zero-click iMessage and WebKit chains |
| CVE-2026-xxxx | LiteLLM (post-install hook) | N/A | Yes (ITW — TeamPCP) | Supply chain compromise; env-var exfiltration |

**CISA KEV additions in March:** The six DarkSword iOS CVEs anchor the month's KEV activity. Organisations under federal KEV due-date SLAs should treat the iOS chain as a hard-deadline patch. Commercial organisations benefit from the same urgency given the strong evidence of active exploitation.

**Patch-prioritisation guidance for March's backlog:** SharePoint CVE-2026-20963 → Chrome zero-days → iOS DarkSword chain → then standard monthly Patch Tuesday items. Do not defer any of the first three beyond 48 hours for Internet-facing or executive-tier assets.

## 6. Trending Entities (Pipeline-Wide)

### Threat Actors
- **Qilin** (55 reports) — dominant ransomware brand of the month; prolific leak-site disclosures; US healthcare and European manufacturing focus
- **The Gentlemen** (48 reports) — extortion-only collective; no confirmed encryption payload; opportunistic victimology
- **Nightspire** (37 reports) — ransomware affiliate; heavy US/EU footprint; RMM-heavy tradecraft
- **TeamPCP** (32 reports) — supply chain operator with ransomware sibling brand; structurally novel operating model
- **DragonForce** (27 reports) — ransomware-as-a-service; manufacturing-heavy victimology; ESXi encryptor variant active
- **Coinbase Cartel** (26 reports) — cryptocurrency-themed extortion outfit; data-theft-only
- **DragonForce** (25 reports; capitalisation variant) — same operator cluster, separate leak-site identity
- **Qilin** (22 reports; secondary spelling) — duplicate cluster against same brand; consolidate in reporting
- **Akira** (22 reports) — long-running RaaS with renewed VPN-abuse tradecraft; ESXi variant active
- **shadowbyt3$** (20 reports) — newer mixed-motive actor; hacktivism plus data resale
- **Handala** (notable qualitative) — Iran-aligned destructive actor; Stryker intrusion; FBI Director email leak
- **UNC6353** (notable qualitative) — Russia-linked DarkSword operator
- **UNC6748** (notable qualitative) — PARS Defense customer; DarkSword operator

### Malware Families
- **RansomLock** (39 reports) — generic locker observed across multiple affiliates
- **DragonForce ransomware** (26 reports) — encryptor builds linked to the RaaS
- **Akira ransomware** (18 reports) — continued version iteration; ESXi variant active
- **PLAY** (8 reports) — steady tempo; infostealer-paired intrusions
- **CanisterWorm** (7 reports) — new Kubernetes wiper; rapidly climbing
- **React2Shell** (qualitative) — AI-generated webshell family
- **VoidLink** (qualitative) — AI-generated Go loader
- **Tycoon2FA** (qualitative) — MFA-phishing PaaS

### Geographic and Sector Patterns
- **Iran:** Primary target of destructive activity (CanisterWorm) and home of commercial-spyware vendor (PARS Defense). Iran-aligned actors (Handala) also active against Western targets.
- **United States:** Primary target of ransomware affiliate activity; healthcare, financial services, and MSSP sectors most affected; federal KEV SLAs push patch urgency.
- **Europe:** Automotive Tier-1, critical-national-infrastructure MSPs, and government agencies under sustained ransomware pressure.
- **Healthcare:** Stryker destructive attack plus multiple hospital-system ransomware events suggest a deliberate sector focus from at least two distinct threat clusters.
- **Software development / cloud:** Primary blast radius of the TeamPCP chain; downstream impact radiates through consuming organisations globally.

## 7. Source Distribution

| Source | Reports | URL | Notes |
|--------|--------:|-----|-------|
| BleepingComputer | 312 | [link](https://www.bleepingcomputer.com) | Primary coverage of ransomware, supply chain, and zero-day items |
| The Hacker News | 224 | [link](https://thehackernews.com) | Malware-family and exploit-chain deep dives; DarkSword, LiteLLM |
| Microsoft | 146 | [link](https://msrc.microsoft.com) | Security advisories including SharePoint CVE-2026-20963; threat intel blog posts on Intune abuse |
| SANS ISC | 118 | [link](https://isc.sans.edu) | TeamPCP technical breakdowns; IOC releases; daily diary entries |
| Krebs on Security | 84 | [link](https://krebsonsecurity.com) | FBI Director email leak narrative; Stryker/Handala context |
| CISA | 72 | [link](https://www.cisa.gov) | KEV additions including DarkSword iOS chain; advisories |
| Schneier | 61 | [link](https://www.schneier.com/blog) | Policy and strategic commentary |
| Wired Security | 58 | [link](https://www.wired.com/category/security) | Commercial spyware and geopolitical coverage |
| Google TAG / Google Security | 44 | [link](https://blog.google/threat-analysis-group/) | Chrome zero-day attribution; commercial spyware reporting |
| Rapid7 | 22 | [link](https://www.rapid7.com/blog/) | SharePoint CVE-2026-20963 analysis |
| watchTowr | 18 | [link](https://labs.watchtowr.com) | SharePoint CVE-2026-20963 PoC and analysis |
| Telegram OSINT | 121 | — | Telegram (channel names redacted); ransomware leak-site and hacktivist primary sourcing |
| Other vendor blogs and misc | 40 | — | Mandiant, Unit 42, Securelist, CrowdStrike, SentinelOne, ESET, Cisco Talos |

## 8. Consolidated Recommendations

### Patching
- 🔴 **IMMEDIATE:** Apply the March SharePoint Security Update for CVE-2026-20963 to all on-premises farms; if deferred, interpose WAF SOAP-body filtering or authenticated reverse proxy
- 🔴 **IMMEDIATE:** Enforce Chrome/Chromium update to the build that fixes CVE-2026-3909 and CVE-2026-3910 via GPO/Intune configuration profiles; verify via telemetry query, not policy push
- 🔴 **IMMEDIATE:** Enforce iOS 18.4.1 minimum version compliance for all MDM-managed iPhones (DarkSword KEV chain)
- 🟠 **SHORT-TERM:** Confirm all March Patch Tuesday items are deployed to servers and priority workstations; prioritise Windows kernel and Active Directory items
- 🟡 **AWARENESS:** Monitor vendor portals for follow-on Chromium V8 and Skia advisories; treat any such CVE as emergency-patch candidate for 30 days

### Detection
- 🔴 **IMMEDIATE:** Build detections for Intune Win32 app-policy assignments targeting large device scopes or "All Devices"/"All Users" groups; alert on any such deployment outside change-window
- 🔴 **IMMEDIATE:** Query CI/CD logs and package inventories for the TeamPCP indicator set; block egress to `teampcp-update[.]workers[.]dev`, `cdn-mirror-pkg[.]fastly[.]net`, and the listed IPs
- 🟠 **SHORT-TERM:** Add detection for `blkdiscard`, `dd if=/dev/zero`, `cipher /w`, and unexplained `sdelete` execution as high-fidelity destructive-action telemetry
- 🟠 **SHORT-TERM:** Deploy Kubernetes audit-log detection for new DaemonSet creation referencing external registries or `hostPath`/`privileged` pods
- 🟠 **SHORT-TERM:** Ingest Tycoon2FA infrastructure IOCs into proxy blocklists and sign-in-log detections
- 🟡 **AWARENESS:** Shift detection weighting from hash/signature to behaviour in anticipation of AI-generated malware proliferation

### Hunting
- 🔴 **IMMEDIATE:** Retrospective hunt for LiteLLM 1.78.5–1.79.0, malicious Trivy builds, and the other TeamPCP packages across the last 60 days of build artefacts
- 🔴 **IMMEDIATE:** Hunt Entra ID audit logs for app-registration creation events in the last 60 days granted Intune or `DeviceManagementConfiguration.ReadWrite.All` scopes
- 🟠 **SHORT-TERM:** Hunt SharePoint IIS logs for anomalous large-body POSTs to `/_layouts/15/` endpoints; inspect for new `.aspx` files in `_catalogs` over the last 30 days
- 🟠 **SHORT-TERM:** Hunt for DCSync events and Certipy abuse signatures (ESC1/ESC3/ESC8) in the last 90 days across ransomware-adjacent entry paths
- 🟡 **AWARENESS:** Review Intune audit logs for unusual Global/Intune Admin activations, new app-assignments, and compliance-policy deletions across March

### Policy
- 🟠 **SHORT-TERM:** Require package-pinning with hash verification and signature verification (Sigstore/cosign) for all production dependencies; mandate CI/CD runner egress allow-lists
- 🟠 **SHORT-TERM:** Enforce Privileged Identity Management (PIM) time-bound activation with phishing-resistant MFA for Intune and Entra ID privileged roles; retire OTP MFA for privileged accounts
- 🟠 **SHORT-TERM:** Enforce phishing-resistant MFA (FIDO2 / platform-bound passkeys) for all privileged and executive accounts in response to Tycoon2FA resurgence
- 🟡 **AWARENESS:** Codify Kubernetes API-server exposure policy: never Internet-exposed; restrict to bastion/jump-host network zones; deny `system:unauthenticated` from every ClusterRoleBinding
- 🟢 **STRATEGIC:** Establish an AI/LLM gateway key-management policy with per-key spend caps, egress allow-lists, and rotation SLAs post-incident; build a hosted-service customer-notification playbook

### Training
- 🟡 **AWARENESS:** Brief developer and SRE populations on the TeamPCP chain and package-integrity workflow; emphasise mandatory report paths for suspected supply chain anomalies
- 🟢 **STRATEGIC:** Run a tabletop exercise modelled on the Handala/Stryker Intune wipe: tenant-compromise to mass-device-impact, including clinical/operational recovery playbooks
- 🟢 **STRATEGIC:** Provide commercial-spyware awareness training and Lockdown Mode enablement guidance to high-risk roles (executives, legal, M&A, journalists, HR, board directors)
- 🟢 **STRATEGIC:** Extend phishing-simulation programmes to cover AiTM and OAuth-consent-phishing patterns observed with Tycoon2FA

## 9. Outlook for April 2026

Three dynamics to watch:
1. **TeamPCP fallout.** Expect additional victim disclosures and potentially further package compromises as stolen credentials are monetised. Supply-chain incident-response maturity will be tested across the sector.
2. **CanisterWorm proliferation.** The late-March non-Iranian cluster attempt suggests the tool or technique may spread. Kubernetes-estate hygiene will be a leading indicator of exposure.
3. **SharePoint CVE-2026-20963 exploitation.** Public PoC plus elevated scanning historically produces mass exploitation within two to three weeks. Organisations with unpatched on-prem SharePoint should assume breach by mid-April unless patched.

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 1320 reports processed across 39 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
