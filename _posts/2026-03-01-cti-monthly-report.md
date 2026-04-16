---
layout: post
title:  "CTI Monthly Report: March 2026 - TeamPCP Supply Chain Siege, CanisterWorm Iran Wiper, Handala Stryker Intrusion, DarkSword iOS KEV, Ransomware Surge"
date:   2026-04-16 09:00:00 +0000
description: "March 2026 saw a historic supply chain campaign by TeamPCP across Trivy, LiteLLM, Checkmarx KICS, Telnyx, Axios, and OpenVSX; the CanisterWorm Kubernetes wiper targeting Iranian infrastructure; Handala's destructive wipe of 80,000 Stryker medical devices via Intune; CISA KEV additions for the DarkSword iOS exploit chain; and a sustained ransomware surge led by Qilin, The Gentlemen, Nightspire, TeamPCP, and DragonForce."
category: monthly
tags: [cti, monthly-report, teampcp, canisterworm, handala, qilin, darksword, cve-2026-20963, cve-2026-3909, cve-2026-3910]
classification: TLP:CLEAR
reporting_period_start: "2026-03-01"
reporting_period_end: "2026-03-31"
generated: "2026-04-16"
severity: "critical"
draft: true
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
  - Telegram OSINT
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-03-01 to 2026-03-31 (March 2026) | TLP:CLEAR | 2026-04-16 |

## 1. Executive Summary

March 2026 was dominated by a single theme: **trusted software supply chains weaponised at scale**. The TeamPCP group chained compromises across at least six widely deployed developer and infrastructure projects — Trivy, LiteLLM, Checkmarx KICS, Telnyx, Axios, and OpenVSX — seeding credential-stealing payloads into CI/CD pipelines used by thousands of downstream organisations. In parallel, a previously unreported worm dubbed **CanisterWorm** exploited misconfigured Kubernetes DaemonSets to deploy destructive wipers across Iranian industrial and telecommunications infrastructure, and the **Handala** operation publicly claimed an Intune-borne wipe of approximately 80,000 Stryker-managed medical devices alongside a leak of FBI Director Patel's personal email. CISA added six vulnerabilities underpinning the **DarkSword** iOS exploit chain to the KEV catalogue after operator UNC6353 (Russia-linked) and UNC6748 (a PARS Defense customer) were observed in active deployments. On the commodity front, ransomware activity remained at record volumes with Qilin (55 reports), The Gentlemen (48), Nightspire (37), TeamPCP ransomware sibling (32), and DragonForce (27) leading victim counts, while Chrome shipped emergency patches for two in-the-wild zero-days (CVE-2026-3909 in Skia, CVE-2026-3910 in V8) and Microsoft remediated an unauthenticated SharePoint RCE (CVE-2026-20963, CVSS 9.8). Across the month the CognitiveCTI pipeline processed **1,320 reports across 39 correlation batches**, with critical-severity reporting concentrated on supply chain, destructive attacks, and zero-day exploitation.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 142 | TeamPCP supply chain chain-compromise; CanisterWorm Iran wiper; Handala/Stryker; DarkSword iOS CISA KEV; Chrome CVE-2026-3909/3910; SharePoint CVE-2026-20963 |
| 🟠 **HIGH** | 318 | Qilin/Akira/Nightspire/DragonForce/PLAY ransomware operations; FBI Director Patel email leak; LiteLLM PyPI compromise; Tycoon2FA PaaS resurgence |
| 🟡 **MEDIUM** | 602 | Chromium batch advisories; AI-generated malware (React2Shell, VoidLink); Coinbase Cartel/The Gentlemen extortion claims; RegPwn registry analysis |
| 🟢 **LOW** | 178 | SmartApeSG loader variants; Samsung One UI compatibility issues; vendor low-severity advisories |
| 🔵 **INFO** | 80 | Defend4Container research; pipeline telemetry notes; threat landscape backgrounders |

## 3. Priority Intelligence Items

### 3.1 TeamPCP Supply Chain Siege Across Six Ecosystems
**Source:** [BleepingComputer](https://www.bleepingcomputer.com), [The Hacker News](https://thehackernews.com), [SANS ISC](https://isc.sans.edu)

Throughout March, a threat cluster tracked as **TeamPCP** executed staged compromises of multiple developer tooling and infrastructure supply chains. Confirmed affected projects include **Trivy** (container scanner), **LiteLLM** (PyPI package, malicious versions 1.78.5–1.79.0), **Checkmarx KICS** (IaC scanner), **Telnyx** (telecom API SDK), **Axios** (HTTP client), and **OpenVSX** (VS Code extension registry). Implants harvested CI/CD secrets (GitHub/GitLab tokens, AWS keys, npm publish tokens) and in several cases used the stolen credentials to pivot into downstream projects — extending the blast radius beyond the initial compromise. Post-compromise behaviour included outbound staging to Cloudflare Workers and Fastly edge endpoints before callback to actor infrastructure, consistent with living-off-trusted-infrastructure tradecraft.

**Affected sectors:** Software development, cloud, MSSPs, any organisation consuming the listed packages. MITRE ATT&CK: **T1195.002** (Supply Chain Compromise: Software Supply Chain), **T1552.001** (Credentials in Files), **T1213** (Data from Information Repositories).

#### Indicators of Compromise
```
LiteLLM malicious versions: 1.78.5, 1.78.6, 1.78.7, 1.79.0
Staging domain: teampcp-update[.]workers[.]dev
C2: 185.234.52[.]183:443
SHA256 (litellm payload): 3f9ac7b1e0d84c2a5fe8b927d6e41cb0a2f5d3e89c07b12a4e61cfa38d72b905
```

> **SOC Action:** Immediately query package-inventory and CI/CD logs for installations of LiteLLM versions 1.78.5 through 1.79.0, Trivy builds installed between 2026-03-08 and 2026-03-22, and the affected Checkmarx KICS, Telnyx SDK, Axios, and OpenVSX extensions published in that window. Rotate all CI/CD secrets exposed to those runners. Block egress to `teampcp-update[.]workers[.]dev` and the listed IP. Enforce package-pinning, mandatory signature verification, and runner egress allow-lists.

### 3.2 CanisterWorm Kubernetes DaemonSet Wiper Targets Iran
**Source:** [BleepingComputer](https://www.bleepingcomputer.com), [Wired Security](https://www.wired.com)

A self-propagating destructive tool dubbed **CanisterWorm** used exposed Kubernetes API servers and misconfigured RBAC to schedule malicious **DaemonSets** across every node in a cluster, then invoked `dd` and `blkdiscard` against mounted block devices to destroy data. Observed targets were concentrated in Iranian telecommunications, petrochemical, and port operator environments. No ransom note was dropped — the intent was destruction, not extortion — and the activity aligns temporally with ongoing Israel–Iran regional tensions. MITRE ATT&CK: **T1610** (Deploy Container), **T1485** (Data Destruction), **T1078** (Valid Accounts).

#### Indicators of Compromise
```
Container image: registry-proxy[.]cdn-cf[.]net/canworm:v3
DaemonSet name pattern: kube-node-metrics-*
C2: 193.178.170[.]155:443
Domain: retrypoti[.]top
SHA256 (wiper binary): b170ffc861d8e5ac42fb903d7ee15c89a64ff2fb61a3c7d9e204187cfa3e8d51
```

> **SOC Action:** Audit Kubernetes API-server exposure and enforce network segmentation so that only bastion/jump hosts can reach the API. Remove the `system:unauthenticated` group from any cluster role bindings. Hunt for DaemonSets that mount `hostPath` or `privileged: true` containers and that reference untrusted registries. Alert on `blkdiscard` or `dd if=/dev/zero` executions in container runtime logs.

### 3.3 Handala Wipes ~80,000 Stryker Medical Devices via Intune; FBI Director Email Leaked
**Source:** [BleepingComputer](https://www.bleepingcomputer.com), [Krebs on Security](https://krebsonsecurity.com)

The Iran-aligned **Handala** group claimed a destructive intrusion against Stryker that used a compromised Intune tenant to push a Win32 app policy triggering `cipher /w` across approximately 80,000 managed endpoints — including surgical-navigation and imaging workstations in hospitals globally. No custom malware was deployed; the attack relied entirely on abuse of legitimate Intune configuration rights (MITRE **T1484.001** Group Policy Modification, **T1485** Data Destruction, **T1078.004** Valid Accounts: Cloud Accounts). The same actor separately dumped a cache of emails allegedly from FBI Director Patel's personal Gmail account, driving significant press attention but limited operational IOCs.

> **SOC Action:** Audit Intune Global Administrator and Intune Administrator role assignments; enforce Privileged Identity Management time-bound activation with MFA. Review all Win32 app deployment assignments for the last 60 days and alert on new deployments targeting large device groups. Enable Microsoft Entra ID Protection risk-based policies for identities with device-management rights. For healthcare: validate offline/immutable backup recoverability for clinical workstations.

### 3.4 DarkSword iOS Exploit Chain — Six CVEs Added to CISA KEV
**Source:** [CISA](https://www.cisa.gov), [The Hacker News](https://thehackernews.com), [Wired Security](https://www.wired.com)

CISA added six CVEs underpinning the **DarkSword** commercial iOS exploit chain to the Known Exploited Vulnerabilities catalogue after corroborated observations of deployment by Russia-linked **UNC6353** and **UNC6748** (a customer of Iranian vendor PARS Defense). The chain achieved zero-click RCE and sandbox escape against iOS 18.x prior to Apple's emergency point release. Victimology centred on journalists, exiled dissidents, and defence-industrial-base personnel. MITRE ATT&CK: **T1204** (User Execution — not required for zero-click variant), **T1068** (Exploitation for Privilege Escalation), **T1055** (Process Injection).

> **SOC Action:** Enforce iOS 18.4.1 minimum OS version in MDM compliance policies for all managed iPhones. Enable Apple Lockdown Mode for high-risk roles (executives, journalists, legal, M&A). Ingest the six KEV CVEs into vulnerability management and apply federal 2026 KEV-due-date SLAs. Monitor for unusual iCloud backup exfiltration patterns against at-risk accounts.

### 3.5 Chrome Zero-Days CVE-2026-3909 (Skia) and CVE-2026-3910 (V8)
**Source:** [BleepingComputer](https://www.bleepingcomputer.com), [The Hacker News](https://thehackernews.com)

Google shipped an emergency Chrome Stable channel update addressing two in-the-wild zero-days: **CVE-2026-3909** (heap corruption in Skia, used for sandbox escape) and **CVE-2026-3910** (type confusion in V8, used for initial RCE). Exploitation chains were attributed by Google TAG to a commercial spyware vendor targeting civil society. Edge, Brave, Opera, and Vivaldi shipped downstream fixes within 72 hours. MITRE ATT&CK: **T1189** (Drive-by Compromise), **T1203** (Exploitation for Client Execution).

> **SOC Action:** Force Chrome/Chromium-based browser updates to the remediated build via GPO/Intune configuration profile within 24 hours. Query EDR for browser processes spawning `cmd.exe`, `powershell.exe`, `wscript.exe`, or unknown children. Ingest TAG-published IOCs into web proxy blocklists. Consider site-isolation-enforcement and SmartScreen enhancements for high-risk user populations.

### 3.6 SharePoint Unauthenticated RCE — CVE-2026-20963 (CVSS 9.8)
**Source:** [Microsoft](https://msrc.microsoft.com), [BleepingComputer](https://www.bleepingcomputer.com)

Microsoft patched **CVE-2026-20963**, a pre-authentication remote code execution affecting on-premises SharePoint Server Subscription Edition and SharePoint 2019. The vulnerability allows a remote unauthenticated attacker to execute arbitrary code in the SharePoint service account context via a crafted SOAP payload. Active exploitation had not been confirmed at month-end, but Rapid7 and watchTowr published technical analyses and PoC code was released mid-month — historically a reliable precursor to mass exploitation. MITRE ATT&CK: **T1190** (Exploit Public-Facing Application), **T1505.003** (Server Software Component: Web Shell).

> **SOC Action:** Apply the March Security Update to all on-prem SharePoint farms within 48 hours. If patching is blocked, place affected farms behind authenticated reverse proxy or WAF with SOAP body filtering. Hunt in IIS logs (`LAYOUTS/15/*.aspx`) for anomalous POSTs with large XML bodies and for new `.aspx` files dropped under `_layouts` or `_catalogs`.

### 3.7 LiteLLM PyPI Package Compromise (Sub-Campaign of TeamPCP)
**Source:** [The Hacker News](https://thehackernews.com), [SANS ISC](https://isc.sans.edu)

Although covered under §3.1, the **LiteLLM** compromise warrants standalone treatment given the package's pervasive use in LLM gateway deployments. Affected versions carried a post-install hook that exfiltrated environment variables — including OpenAI, Anthropic, Azure, and AWS Bedrock API keys — to actor infrastructure. Downstream impact included third-party AI services whose hosted LiteLLM gateway passed customer keys through the malicious runtime. MITRE ATT&CK: **T1195.002**, **T1552.001**, **T1552.005** (Credentials from Password Stores: Cloud Credentials).

> **SOC Action:** In addition to §3.1 remediation, rotate **all** third-party LLM API keys that passed through a LiteLLM gateway during the compromise window. Audit cloud-provider CloudTrail/Activity Log/Audit Log for anomalous inference calls from new source IPs. Enforce per-key spend caps and egress allow-lists on LLM gateway egress.

### 3.8 Ransomware Surge — Qilin, The Gentlemen, Nightspire, DragonForce, Coinbase Cartel
**Source:** [BleepingComputer](https://www.bleepingcomputer.com), Telegram (channel name redacted)

March saw sustained ransomware activity with **Qilin** posting 55 victim disclosures, **The Gentlemen** 48, **Nightspire** 37, **TeamPCP** ransomware sibling 32, **DragonForce** 27, **Coinbase Cartel** 26, and **Akira** 22. Notable single victims included a US regional hospital system (Qilin), a European automotive Tier 1 (DragonForce), and a UK critical-national-infrastructure MSP (Akira). Tradecraft commonalities across affiliates included ScreenConnect/AnyDesk for persistence, Impacket for lateral movement, and Rclone to MEGA for exfiltration. MITRE ATT&CK: **T1486** (Data Encrypted for Impact), **T1567.002** (Exfiltration to Cloud Storage), **T1219** (Remote Access Software).

> **SOC Action:** Detect unauthorised RMM installs (ScreenConnect, AnyDesk, Atera, Splashtop) via application-control and EDR. Block Rclone execution outside approved admin workstations. Audit external-facing VPN and Citrix portals for weak/absent MFA; these remain the dominant affiliate entry path. Validate immutable backup restore times against 4h RTO targets.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Supply chain cross-pollination — credentials stolen from one package compromise used to seed the next | TeamPCP chain: Trivy → LiteLLM → Checkmarx KICS → Telnyx → Axios → OpenVSX, tracked across six discrete correlation batches in March |
| 🔴 **CRITICAL** | Kubernetes-native destructive attacks emerge as a distinct TTP | CanisterWorm DaemonSet wiper; second cluster attempted against non-Iranian target late March; aligns with Microsoft Threat Intel advisory on Kubernetes RBAC abuse |
| 🔴 **CRITICAL** | Destructive wiping via legitimate endpoint-management planes | Handala/Stryker Intune abuse mirrors earlier SCCM-abuse patterns; expands the "no malware needed" destructive playbook to cloud EDM tooling |
| 🟠 **HIGH** | Commercial spyware proliferation — two operators sharing one vendor chain | DarkSword used by both UNC6353 (Russian-linked) and UNC6748 (PARS Defense customer); CISA KEV additions formalise state-level concern |
| 🟠 **HIGH** | AI-generated malware moves from proof-of-concept to observed in-the-wild | React2Shell and VoidLink families analysed by multiple vendors in March; both show hallmarks of LLM-assisted development (unusual comment style, uncommon import patterns) |
| 🟠 **HIGH** | MFA-phishing-as-a-service resurgence | Tycoon2FA returns post-takedown with new infrastructure; higher volume than pre-takedown baseline |
| 🟡 **MEDIUM** | Chromium-adjacent advisories clustering around V8 and rendering engines | Two zero-days plus four critical-severity advisories in March alone |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors
- **Qilin** (55 reports) — dominant ransomware brand of the month; prolific leak-site disclosures
- **The Gentlemen** (48 reports) — extortion-only collective; no confirmed encryption payload
- **Nightspire** (37 reports) — ransomware affiliate; heavy US/EU footprint
- **TeamPCP** (32 reports) — supply chain operator; also runs a ransomware sibling brand
- **DragonForce** (27 reports) — ransomware-as-a-service; manufacturing-heavy victimology
- **Coinbase Cartel** (26 reports) — cryptocurrency-themed extortion outfit
- **DragonForce** (25 reports; capitalisation variant) — same operator cluster, separate leak-site identity
- **Qilin** (22 reports; secondary spelling) — duplicate cluster against same brand
- **Akira** (22 reports) — long-running RaaS with renewed VPN-abuse tradecraft
- **shadowbyt3$** (20 reports) — newer mixed-motive actor; hacktivism plus data resale

### Malware Families
- **RansomLock** (39 reports) — generic locker observed across multiple affiliates
- **DragonForce ransomware** (26 reports) — encryptor builds linked to the RaaS
- **Akira ransomware** (18 reports) — continued version iteration; ESXi variant active
- **PLAY** (8 reports) — steady tempo; infostealer-paired intrusions
- **CanisterWorm** (7 reports) — new Kubernetes wiper; rapidly climbing

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|--------:|-----|-------|
| BleepingComputer | 312 | [link](https://www.bleepingcomputer.com) | Primary coverage of ransomware, supply chain, and zero-day items |
| The Hacker News | 224 | [link](https://thehackernews.com) | Malware-family and exploit-chain deep dives; DarkSword, LiteLLM |
| Microsoft | 146 | [link](https://msrc.microsoft.com) | Security advisories including SharePoint CVE-2026-20963 |
| SANS ISC | 118 | [link](https://isc.sans.edu) | TeamPCP technical breakdowns; IOC releases |
| Krebs on Security | 84 | [link](https://krebsonsecurity.com) | FBI Director email leak narrative; Stryker/Handala context |
| CISA | 72 | [link](https://www.cisa.gov) | KEV additions including DarkSword iOS chain |
| Schneier | 61 | [link](https://www.schneier.com/blog) | Policy and strategic commentary |
| Wired Security | 58 | [link](https://www.wired.com/category/security) | Commercial spyware and geopolitical coverage |
| Telegram OSINT | 121 | — | Telegram (channel names redacted); ransomware leak-site and hacktivist primary sourcing |
| Other vendor blogs and miscellaneous | 124 | — | Rapid7, watchTowr, Google TAG, Mandiant, Unit 42, Securelist |

## 7. Consolidated Recommendations

### Patching
- 🔴 **IMMEDIATE:** Apply the March SharePoint Security Update for CVE-2026-20963 to all on-premises farms; if deferred, interpose WAF SOAP-body filtering or authenticated reverse proxy
- 🔴 **IMMEDIATE:** Enforce Chrome/Chromium update to the build that fixes CVE-2026-3909 and CVE-2026-3910 via GPO/Intune configuration profiles
- 🟠 **SHORT-TERM:** Enforce iOS 18.4.1 minimum version compliance for all MDM-managed iPhones (DarkSword KEV chain)
- 🟡 **AWARENESS:** Monitor vendor portals for follow-on Chromium V8 and Skia advisories; treat any such CVE as emergency-patch candidate for 30 days

### Detection
- 🔴 **IMMEDIATE:** Build detections for Intune Win32 app-policy assignments targeting large device scopes; alert on any such deployment outside change-window
- 🔴 **IMMEDIATE:** Query CI/CD logs and package inventories for the TeamPCP indicator set; block egress to `teampcp-update[.]workers[.]dev` and `193.178.170[.]155`
- 🟠 **SHORT-TERM:** Add detection for `blkdiscard`, `dd if=/dev/zero`, and `cipher /w` as high-fidelity destructive-action telemetry
- 🟠 **SHORT-TERM:** Deploy Kubernetes audit-log detection for new DaemonSet creation referencing external registries or `hostPath`/`privileged` pods

### Hunting
- 🔴 **IMMEDIATE:** Retrospective hunt for LiteLLM 1.78.5–1.79.0, malicious Trivy builds, and the other TeamPCP packages across the last 60 days of build artefacts
- 🟠 **SHORT-TERM:** Hunt SharePoint IIS logs for anomalous large-body POSTs to `/_layouts/15/` endpoints; inspect for new `.aspx` files in `_catalogs`
- 🟡 **AWARENESS:** Review Intune audit logs for unusual Global/Intune Admin activations, new app-assignments, and compliance-policy deletions across March

### Policy
- 🟠 **SHORT-TERM:** Require package-pinning and signature verification for all production dependencies; mandate CI/CD runner egress allow-lists
- 🟠 **SHORT-TERM:** Enforce Privileged Identity Management (PIM) time-bound activation with MFA for Intune and Entra ID privileged roles
- 🟡 **AWARENESS:** Codify Kubernetes API-server exposure policy: never Internet-exposed; restrict to bastion/jump-host network zones; deny `system:unauthenticated`
- 🟢 **STRATEGIC:** Establish an AI/LLM gateway key-management policy with per-key spend caps, egress allow-lists, and rotation SLAs post-incident

### Training
- 🟡 **AWARENESS:** Brief developer and SRE populations on the TeamPCP chain and package-integrity workflow; emphasise mandatory report paths for suspected supply chain anomalies
- 🟢 **STRATEGIC:** Run a tabletop exercise modelled on the Handala/Stryker Intune wipe: tenant-compromise to mass-device-impact, including clinical/operational recovery playbooks
- 🟢 **STRATEGIC:** Provide commercial-spyware awareness training and Lockdown Mode enablement guidance to high-risk roles (executives, legal, M&A, journalists, HR)

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 1320 reports processed across 39 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
