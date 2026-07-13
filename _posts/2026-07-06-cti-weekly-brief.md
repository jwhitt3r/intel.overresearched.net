---
layout: post
title:  "CTI Weekly Brief: 2026-07-06 to 2026-07-12 - Actively-exploited ColdFusion RCE, 15-year Linux root bug (GhostLock), and cross-sector ransomware surge"
date:   2026-07-13 08:30:00 +0000
description: "563 reports across 15 sources: CISA emergency directives on Adobe ColdFusion and Langflow, GhostLock and Januscape Linux kernel flaws, Injective npm supply-chain compromise, GodDamn/PoisonX BYOVD ransomware, and sustained pressure from The Gentlemen, Qilin, DragonForce, and Anubis ransomware operations."
category: weekly
tags: [cti, weekly-brief, the-gentlemen, qilin, dragonforce, anubis, coldfusion, ghostlock, cve-2026-48282, cve-2026-43499]
classification: TLP:CLEAR
reporting_period_start: "2026-07-06"
reporting_period_end: "2026-07-12"
generated: "2026-07-13"
draft: false
severity: critical
report_count: 563
sources:
  - Microsoft
  - RansomLook
  - BleepingComputer
  - RecordedFutures
  - AlienVault
  - SANS
  - CISA
  - Schneier
  - Wired Security
  - Upwind
  - Wiz
  - Crowdstrike
  - Cisco Talos
  - Unit42
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-07-06 to 2026-07-12 (7d) | TLP:CLEAR | 2026-07-13 |

## 1. Executive Summary

The pipeline processed 563 reports across 15 sources over the reporting period, with 44 rated critical and 305 rated high. The week was dominated by three parallel storylines: two CISA emergency-directive-grade actively-exploited vulnerabilities (Adobe ColdFusion CVE-2026-48282 and the Langflow authentication bypass), a cluster of long-dormant Linux kernel flaws surfaced by AI-driven bug-hunting (GhostLock CVE-2026-43499 and Januscape VM-escape, both undetected for 15–16 years), and sustained ransomware pressure across manufacturing, healthcare, retail, and critical-infrastructure sectors. DragonForce, Anubis, Qilin, The Gentlemen, and M3rx accounted for the bulk of the 148 RansomLock-sourced victim postings.

Supply-chain and AI-tooling risk also stood out: the Injective Labs SDK was compromised on npm to steal cryptocurrency wallet seed phrases, Wiz disclosed GhostApproval — a symlink-following/UI-misrepresentation flaw affecting six major AI coding assistants — and SANS observed a distributed scan probing for exposed Model Context Protocol (MCP) servers and AI-assistant credential files. Microsoft's July patch cycle shipped fixes for a Defender zero-day (RoguePlanet), an Edge RCE (CVE-2026-58281), and a large Chromium batch including V8 type-confusion, use-after-free, and ANGLE/Skia memory-corruption issues. CISA also issued ICS advisories for Siemens SINEC OS, OpenPLC v3, and the Hydro-Québec Le Circuit Electrique charging-station backend.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 44 | Chromium V8/ANGLE/Skia batch; Adobe ColdFusion RCE (exploited); GhostLock & Januscape Linux kernel; Injective npm supply chain; GodDamn/PoisonX ransomware; Langflow auth bypass (KEV); U-Boot; Gitea Docker; Zimbra XSS; Ubiquiti UniFi OS; BeyondTrust RS/PRA; RoguePlanet Defender 0-day; OpenPLC v3, Siemens SINEC OS, Hydro-Québec (ICS) |
| 🟠 **HIGH** | 305 | RansomLock victim postings (DragonForce, Anubis, M3rx, Qilin, The Gentlemen, Lockbit5, Akira); RedHook Android malware; Chromium high-tier CVEs; The Gentlemen ransomware profile; d1r Bosch/ARM/Synopsys leak |
| 🟡 **MEDIUM** | 136 | Chromium DevTools/policy CVEs; MCP/AI-assistant credential scanning; Roundcube exploitation of academics; regional advisories |
| 🟢 **LOW** | 14 | Minor product bulletins and hardening notices |
| 🔵 **INFO** | 64 | Vendor commentary, retrospectives, and pipeline meta-reports |

## 3. Priority Intelligence Items

### 3.1 Adobe ColdFusion CVE-2026-48282 actively exploited; CISA orders federal patching

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/max-severity-adobe-coldfusion-flaw-now-exploited-in-attacks/), [BleepingComputer](https://www.bleepingcomputer.com/news/security/cisa-orders-feds-to-patch-max-severity-coldfusion-flaw-by-friday/), Telegram (channel name redacted)

The Canadian Center for Cyber Security (CCCS) reported active in-the-wild exploitation of CVE-2026-48282, a maximum-severity remote code execution flaw in Adobe ColdFusion's Remote Development Service (RDS). CISA followed with a directive requiring federal agencies to patch by Friday of the reporting week. A public proof-of-concept was circulated on Telegram, lowering the bar for opportunistic exploitation. The vulnerability enables unauthenticated attackers to gain full control of affected servers. Techniques observed align with **T1190** (Exploit Public-Facing Application), **T1068** (Exploitation for Privilege Escalation), and **T1106** (Native API).

> **SOC Action:** Inventory all internet-exposed ColdFusion instances and confirm patch level against Adobe's July 2026 bulletin. Disable the RDS component in production configurations where it is not required. Hunt web-access logs for anomalous POST activity to RDS endpoints and correlate with unexpected `cfusion.exe` child processes such as `cmd.exe`, `powershell.exe`, or `w3wp.exe` spawning shells.

### 3.2 GhostLock (CVE-2026-43499) and Januscape — 15-year-old Linux kernel flaws surface

**Source:** [Wired Security](https://www.wired.com/story/security-news-this-week-ai-found-a-root-bug-in-linux-that-everyone-missed-for-15-years/), [BleepingComputer](https://www.bleepingcomputer.com/news/linux/new-januscape-linux-kernel-flaw-allows-vm-escape-on-intel-amd-devices/), Telegram (channel name redacted)

Nebula Security published exploit code for **GhostLock (CVE-2026-43499)**, a use-after-free bug that shipped by default in essentially every mainstream Linux distribution since 2011. The flaw allows any logged-in user to gain root on an unpatched machine, escapes containers, and was 97% reliable in Nebula's testing (kernelCTF payout: $92,337). It was fixed upstream in April 2026, but Ubuntu's 24.04/22.04/20.04 LTS lines were still listed as vulnerable or in-progress as of early July — defenders should confirm the fixed package version rather than assume distro pickup. A separate **Januscape** flaw (also ~16 years old) permits VM escape on Intel and AMD hardware from within a guest Linux kernel. Both were surfaced by AI-driven code-review tooling (Nebula's VEGA), continuing a 2026 trend of automated tools rediscovering long-latent kernel bugs. MITRE reference: **T1068**.

> **SOC Action:** Query package inventory (osquery `deb_packages`/`rpm_packages`, MDM, or CMDB) for kernel versions below the distribution-specific fixed release and prioritise multi-tenant hosts, container hosts, and hypervisors. Treat any host still shipping the vulnerable kernel as a privilege-escalation risk regardless of user hardening. Consider AppArmor/SELinux enforcement and disable unused kernel subsystems where the exploit primitive is known.

### 3.3 Injective Labs SDK compromised on npm — cryptocurrency wallet stealer

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/injective-sdk-on-npm-infected-with-cryptocurrency-wallet-stealer/)

Attackers compromised the Injective Labs SDK's GitHub project and pushed a malicious npm release that exfiltrated cryptocurrency wallet private keys and mnemonic seed phrases from downstream developers. The abuse of a trusted publishing channel makes this a classic upstream supply-chain compromise, with the exfiltration piggy-backing on the SDK's ordinary network calls. MITRE references: **T1195.002** (Compromise Software Supply Chain), **T1071** (Application Layer Protocol), **T1566** (Phishing — for maintainer-account compromise vectors).

> **SOC Action:** Audit `package-lock.json`/`yarn.lock` across engineering repositories for `@injectivelabs/sdk-ts` and pin to a version confirmed clean by the maintainer's post-incident advisory. Rotate any developer-held crypto wallet seeds handled on machines that installed the package during the compromise window, and hunt for outbound connections from Node build agents to anomalous domains.

### 3.4 Langflow authentication bypass added to CISA KEV, federal patch deadline set

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/cisa-orders-feds-to-prioritize-patching-langflow-auth-bypass-flaw/)

CISA gave federal agencies until Friday of the reporting week to patch an actively-exploited authentication bypass in the Langflow visual framework used to build AI agents. Exploitation grants unauthenticated access to and control over hosted AI agents, opening a lateral path to any credentials, data stores, or downstream tooling the agent is wired into. This addition, combined with SANS's observation of scanning for exposed MCP servers and AI-assistant configuration files, indicates active adversary reconnaissance against the emerging AI-agent tooling stack.

> **SOC Action:** Identify any Langflow deployments (public or internal), patch to the fixed release, and place them behind authenticated network paths. Rotate any API keys, database credentials, or cloud tokens configured into Langflow agents. Add detections for unauthenticated `POST /api/v1/*` sequences and any Langflow calls originating from unexpected source ranges.

### 3.5 Chromium / Microsoft Edge critical batch (V8, ANGLE, Skia, Safe Browsing, Edge RCE)

**Source:** [Microsoft MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-58281)

Microsoft published a large Chromium security update covering multiple critical memory-safety and logic issues: CVE-2026-14431 (V8 type confusion), CVE-2026-14430 (V8 integer overflow), CVE-2026-14394 and CVE-2026-14393 (V8 use-after-free), CVE-2026-14427 (Skia heap buffer overflow), CVE-2026-14386 and CVE-2026-14400 (ANGLE out-of-bounds read/write), CVE-2026-13974 (Safe Browsing integer overflow), and CVE-2026-13927 (untrusted-input validation in the UI). Separately, CVE-2026-58281 is a critical Edge (Chromium-based) RCE via deserialization of untrusted data. There is no confirmed in-the-wild exploitation reported for this batch, but the concentration of V8/ANGLE/Skia bugs makes drive-by exploit chains historically plausible. MITRE references: **T1189** (Drive-by Compromise), **T1203** (Exploitation for Client Execution).

> **SOC Action:** Push Edge/Chromium to the fixed build via management tooling and confirm client compliance within 72 hours. For unmanaged bring-your-own devices touching corporate SaaS, gate access at the identity layer on browser version until compliance is verified.

### 3.6 Gitea Docker image auth bypass — active exploitation

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/hackers-exploit-critical-auth-bypass-in-gitea-docker-image/)

Attackers are actively exploiting a critical authentication bypass in the official Gitea Docker image that permits impersonation of any user — including administrators — of the self-hosted Git service. Compromise gives an attacker full read/write access to source repositories and CI configuration, an ideal pivot to downstream software supply chains. MITRE references: **T1078** (Valid Accounts), **T1552.001** (Unsecured Credentials).

> **SOC Action:** Rebuild any self-hosted Gitea container from the fixed image tag and audit the admin user table, SSH keys, webhooks, and CI runner registrations for unauthorised additions since 1 July. Review Git push/pull logs for admin-level activity from unexpected IPs and rotate all deploy tokens.

### 3.7 GodDamn ransomware (Hyadina) — signed PoisonX kernel driver disables defenses

**Source:** [AlienVault OTX](https://otx.alienvault.com/pulse/6a4f99c77bfb2dde4f69e174)

AlienVault detailed **GodDamn**, the third-generation ransomware from the Hyadina crew (following Monster in 2022 and Beast in 2024). A June 2026 intrusion showed operators using **AnyDesk** for remote access, NirSoft-based credential harvesting, **PsExec** for lateral movement, and a Microsoft-signed kernel driver named **PoisonX** to terminate endpoint-security processes at ring 0 — a bring-your-own-vulnerable-driver (BYOVD) pattern. A four-day dwell period preceded encryption across at least 10 hosts. Observed MITRE techniques include **T1003.001** (LSASS credential dumping), **T1543.003** (Windows service creation), **T1562.001** (Impair Defenses), **T1486** (Data Encrypted for Impact), and **T1490** (Inhibit System Recovery).

#### Indicators of Compromise

```
Malware families: GodDamn, Beast, Monster, PoisonX (driver), Mimikatz
Actor:           Hyadina
Legitimate tools abused: AnyDesk, PsExec, NirSoft utilities
SHA256 (selection):
  141b2190f51397dbd0dfde0e3904b264c91b6f81febc823ff0c33da980b69944
  17fb52476016677db5a93505c4a1c356984bc1f6a4456870f920ac90a7846180
  19bab15a34d5ad838ccf4d187eb40379c335fa56446d0f9621865b2767d4ac7d
  31eb1de7e840a342fd468e558e5ab627bcb4c542a8fe01aec4d5ba01d539a0fc
  45126297c07c6ef56b51440cd0dc30acf7b3b938e2e9e656334886fe2f81f220
  8e4b218bdbd8e098fff749fe5e5bbf00275d21f398b34216a573224e192094b8
  b29f91a440527fb621d106a2048f6379fff3263c60aeda9c82ff8c1d5ae880a8
  c92580318be4effdb37aa67145748826f6a9e285bc2426410dc280e61e3c7620
  ece33e4b7e2d26eeca8ad9db4439f9801a7a77e332611116156738b1b0316046
  faca9e856c369b63d6698c74b1d59b062a9a8d9fe84b8f753c299c9961026395
```

> **SOC Action:** Deploy Microsoft's vulnerable-driver blocklist and confirm HVCI/Memory Integrity is enforced on all endpoints. In EDR, hunt for new kernel-driver loads with signature mismatches or unexpected signing chains, and alert on `PsExec.exe`/`paexec.exe` invoked from non-administrator sessions and on `anydesk.exe` running outside sanctioned support hours. Add the SHA256 set above to file-hash blocklists.

### 3.8 UAT-7810 (China-nexus) continues building ORB relay network via router 0-days

**Source:** [AlienVault OTX](https://otx.alienvault.com/pulse/6a4d0a8afd30c55d7e2c19d5)

AlienVault attributes to **UAT-7810** (a China-nexus intrusion set also tracked as ORB Networks / Dogleash) a continued build-out of Operational Relay Box infrastructure using custom backdoors — **SHORTLEASH**, **LONGLEASH**, **DOGLEASH** (C), **JARLEASH** (Java admin backdoor), and **LEASHTEST** (MIPS test binary). Targeting focuses on unpatched Ruckus wireless routers and ASUS AiCloud devices across MIPS, ARM, and x64. UAT-7810 rents the relay network to secondary actors who use it for downstream attacks on high-value targets. Four command servers were identified, including one in Hong Kong. Referenced CVEs: **CVE-2020-22653**, **CVE-2020-22658**, **CVE-2023-25717**, **CVE-2025-2492**. MITRE references include **T1190**, **T1071.001**, **T1090** (Proxy), **T1573** (Encrypted Channel), **T1572** (Protocol Tunneling).

#### Indicators of Compromise

```
Actor:      UAT-7810 (also ORB Networks / Dogleash)
Malware:    SHORTLEASH, LONGLEASH, DOGLEASH, JARLEASH, LEASHTEST
Targets:    Ruckus wireless routers, ASUS AiCloud (MIPS/ARM/x64)
CVEs:       CVE-2020-22653, CVE-2020-22658, CVE-2023-25717, CVE-2025-2492
SHA256 (selection):
  2e0e43776e2e1a37d882a1b2ebb7d337ee88950177e43831dae645a367824feb
  d4861088161fc72b9922abf933b4ea664a807105ec1eab4a173253aa60bfe6d7
  bafba443170e54ef7fd431ce7f1b5e202719f3fd022e4ef70788904f574d2cdf
  0352f3e338261d98895df4c7b7a76b296485b2290c72bce56603351d167d0601
  1660536f448b8b9f086ce9ea3ce4e9deefc59a76711ea53ee6d8f08fc8c1bb99
```

> **SOC Action:** Inventory perimeter and branch-office SOHO/edge networking gear (particularly Ruckus and ASUS AiCloud) and confirm firmware is current against the CVEs above; retire unsupported hardware. In perimeter logs, hunt for outbound long-lived TLS connections to Hong Kong and low-reputation VPS ranges from unusual internal source hosts, and alert on residential-router models beaconing to cloud infrastructure. Block the listed SHA256s at EDR/AV.

### 3.9 GhostApproval — trust-boundary flaw in six major AI coding assistants

**Source:** [Wiz](https://www.wiz.io/blog/ghostapproval-a-trust-boundary-gap-in-ai-coding-assistants)

Wiz disclosed **GhostApproval**, a systematic vulnerability pattern in six leading AI coding assistants — Amazon Q Developer (CVE-2026-12958, fixed), Google Antigravity (fixed), Cursor (CVE-2026-50549, fixed), Anthropic Claude Code (rejected as out-of-threat-model), Augment (in progress), and Windsurf (in progress). A malicious repository can place a symlink (CWE-61) inside its workspace so that when the agent asks the user for permission to edit an in-workspace file, the underlying write lands on a sensitive path such as `~/.ssh/authorized_keys`. In several cases the agent's internal reasoning explicitly recognises the dangerous target while the confirmation UI conceals it (CWE-451). Practical impact ranges from credential theft to code execution on the developer's workstation. MITRE reference: **T1078.004** (Valid Accounts: Cloud Accounts / local variants).

> **SOC Action:** Update all AI coding assistants deployed on developer workstations to the fixed versions listed by each vendor. Where a fix is not available, restrict the assistants to trusted repositories and block them from opening cloned third-party projects until patched. Add file-integrity monitoring on developer machines for writes to `~/.ssh/*`, `~/.aws/*`, and shell rc files originating from IDE/assistant processes.

### 3.10 Additional actively-exploited or notable critical vulnerabilities

The pipeline also reported the following critical items during the week; each warrants an owner and a patch or mitigation:

- **RoguePlanet** Microsoft Defender zero-day, patched out-of-band after June Patch Tuesday. Confirm Defender platform update rollout — [BleepingComputer](https://www.bleepingcomputer.com/news/microsoft/microsoft-patches-rogueplanet-defender-zero-day-vulnerability/).
- **Ubiquiti UniFi OS** — seven critical CVEs including a max-severity command injection — [BleepingComputer](https://www.bleepingcomputer.com/news/security/ubiquiti-warns-of-new-max-severity-unifi-os-vulnerability/).
- **BeyondTrust** Remote Support and Privileged Remote Access — critical authentication-bypass flaws — [BleepingComputer](https://www.bleepingcomputer.com/news/security/beyondtrust-warns-of-critical-flaws-in-remote-access-software/).
- **Zimbra** Classic Web Client — critical XSS — [BleepingComputer](https://www.bleepingcomputer.com/news/security/zimbra-urges-customers-to-patch-critical-web-client-xss-flaw/).
- **Tenda** router firmware — hidden authentication bypass backdoor — [BleepingComputer](https://www.bleepingcomputer.com/news/security/hidden-backdoor-in-tenda-router-firmware-grants-admin-access/).
- **U-Boot** bootloader — six flaws enabling stealthy firmware attacks — [BleepingComputer](https://www.bleepingcomputer.com/news/security/new-u-boot-flaws-could-enable-stealthy-firmware-attacks/).
- **OpenPLC v3** CVE-2026-14480 — authenticated file write leading to code execution — [CISA ICSA-26-190-01](https://www.cisa.gov/news-events/ics-advisories/icsa-26-190-01).
- **Siemens SINEC OS** (< V4.0) — multiple memory, race, path-traversal, and auth-bypass issues — [CISA ICSA-26-188-05](https://www.cisa.gov/news-events/ics-advisories/icsa-26-188-05).
- **Hydro-Québec Le Circuit Electrique** charging-station backend — unauthenticated websocket connections, no auth throttling — [CISA ICSA-26-188-01](https://www.cisa.gov/news-events/ics-advisories/icsa-26-188-01).

> **SOC Action:** Assign each item above to the responsible platform team with a patch window this week. For network and firmware items (Ubiquiti, Tenda, U-Boot, SINEC OS, OpenPLC), confirm exposure at the perimeter and consider ACL restrictions until patched.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Increased focus on memory-safety issues (use-after-free, out-of-bounds) in mainstream software | Chromium CVE-2026-13915 (UAF, Chrome for iOS); Chromium CVE-2026-14385 (heap overflow in ANGLE); GhostLock (CVE-2026-43499); Januscape |
| 🔴 **CRITICAL** | Exploitation of software/protocol flaws for privilege escalation | GhostLock Linux kernel; CVE-2026-58252 NATS Server subscribe-authz bypass; Adobe ColdFusion RCE |
| 🔴 **CRITICAL** | Wave of exploitation of critical cross-platform vulnerabilities | U-Boot firmware flaws; CVE-2026-47291 Windows HTTP.sys integer overflow; ColdFusion RDS |
| 🔴 **CRITICAL** | Supply-chain phishing/dependency-poisoning targeting finance and crypto | Injective SDK npm compromise; Not-so-anonymous telemetry — @injectivelabs/sdk-ts backdoor |
| 🔴 **CRITICAL** | Ransomware targeting critical infrastructure | OpenPLC v3; Schneider Electric Easergy MiCOM Px40 |
| 🔴 **CRITICAL** | The Gentlemen ransomware group targeting diverse sectors at high tempo with multiple malware variants | CSIR Structural Engineering Research Centre; Royal Foods; Pro-Tech Technology; Technical Solutions Group |
| 🟠 **HIGH** | Increased ransomware activity across multiple sectors with overlapping actors and tactics | DragonForce (Al-Saidi, STEP Oiltools); Anubis (Casper Orthopedics, Surtifamiliar, Community Advocates) |
| 🟠 **HIGH** | Ransomware activity focused on hospitality and technology | M3rx (eclective.ie, foreconinc.com, wrtworld.com); D1r (Bosch, ARM, Synopsys) |
| 🟠 **HIGH** | Widespread vulnerabilities in Chromium-based browsers | CVE-2026-13994 (Credential Management); CVE-2026-58281 Edge RCE |
| 🟠 **HIGH** | Sophisticated phishing using AI and multi-ecosystem strategies | Forg365 AI-powered phishing kit vs. Microsoft 365; coordinated npm and PyPI typosquats of payment libraries |
| 🟠 **HIGH** | Sustained targeting of the education sector | Mount Royal University breach; Roundcube exploited to spy on academic researchers |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **The Gentlemen** (109 reports) — highest-volume ransomware operator this cycle; consistent use of Tox1 encryption and phishing across legal, retail, accounting, construction, and hardware retail sectors.
- **Qilin** (74 reports) — active RaaS with high tempo across manufacturing, healthcare, IT, and agriculture; recent victims include Retelit SpA PIVA and Carolina Agri-Power.
- **Deadlock** (66 reports) — steady leak-site activity, malware family of the same name.
- **Lockbit5** (36 reports) — expanding across education and engineering sectors (hotel-bourse.com, magna.com.do).
- **Akira** (22 reports) — sustained double-extortion campaigns; recent victims include RISE Architecture and Excalibur Rentals.
- **DragonForce** (19 reports) — evolved from hacktivist origins to financially-motivated RaaS; posted Al-Saidi Factory and STEP Oiltools this week.
- **ShinyHunters** (17 reports) — continued data-broker activity.
- **Nova** (17 reports) — persistent leak-site presence.
- **Anubis** (16 reports) — banking-trojan lineage now paired with ransomware; posted Casper Orthopedics, Surtifamiliar, Community Advocates this week.
- **Inc Ransom** (14 reports); **Cmd Organization** (13); **Krybit** (12) — mid-tier operators maintaining cadence.
- **Hyadina** — attribution point for GodDamn/PoisonX BYOVD ransomware.
- **UAT-7810 / ORB Networks (Dogleash)** — China-nexus intrusion set building relay infrastructure.

### Malware Families

- **RansomLook** (150 reports) — aggregator source rather than a single family, but the volume signals sustained double-extortion pressure.
- **Tox1** (74) and **Tox** (45) — heavily associated with The Gentlemen operations.
- **Other1** (46) — internal grouping used across multiple RaaS families this week.
- **Anubis ransomware** (14) and **Anubis banking trojan** (12) — continuing convergence of Anubis's fraud and extortion arms.
- **Deadlock** (12); **The Gentlemen Ransomware** (12); **Akira ransomware** (11); **Qilin/Qilin Ransomware** (10 + 8); **LockBit** (9); **Nova** (9).
- **GodDamn / PoisonX / Beast / Monster** — Hyadina's family tree, newly detailed by AlienVault.
- **SHORTLEASH / LONGLEASH / DOGLEASH / JARLEASH / LEASHTEST** — UAT-7810 relay-network implants.

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| Microsoft | 254 | [msrc.microsoft.com](https://msrc.microsoft.com/update-guide) | Bulk Chromium CVE ingestion + Edge RCE + Defender zero-day; largest single feed |
| RansomLook | 148 | [ransomlook.io](https://www.ransomlook.io/) | Leak-site victim postings from DragonForce, Anubis, M3rx, Qilin, The Gentlemen, Lockbit5, Akira |
| BleepingComputer | 46 | [bleepingcomputer.com](https://www.bleepingcomputer.com) | Primary coverage of ColdFusion exploitation, Gitea, Ubiquiti, BeyondTrust, Zimbra, Januscape, Tenda |
| RecordedFutures | 21 | [recordedfuture.com](https://www.recordedfuture.com) | Intelligence briefs and analytic commentary |
| AlienVault | 21 | [otx.alienvault.com](https://otx.alienvault.com) | GodDamn/PoisonX and UAT-7810 ORB Networks deep-dives |
| SANS | 14 | [isc.sans.edu](https://isc.sans.edu) | MCP/AI-assistant credential scanning diary |
| CISA | 11 | [cisa.gov](https://www.cisa.gov) | ICS advisories (Siemens SINEC OS, OpenPLC v3, Hydro-Québec) and KEV directives |
| Unknown | 8 | — | Telegram-sourced OSINT (channel name redacted) — ColdFusion PoC, HTTP.sys RCE, GhostLock write-up, eBPF rootkits |
| Schneier | 6 | [schneier.com](https://www.schneier.com) | Squidbleed and commentary |
| Wired Security | 6 | [wired.com](https://www.wired.com/category/security/) | GhostLock long-read |
| Upwind | 5 | [upwind.io](https://www.upwind.io) | Cloud posture and detection notes |
| Wiz | 4 | [wiz.io](https://www.wiz.io/blog) | GhostApproval AI-coding-assistant flaw |
| Crowdstrike | 3 | [crowdstrike.com](https://www.crowdstrike.com/blog) | Actor-tracking notes |
| Cisco Talos | 3 | [blog.talosintelligence.com](https://blog.talosintelligence.com) | ClamAV CVE technical detail |
| Unit42 | 2 | [unit42.paloaltonetworks.com](https://unit42.paloaltonetworks.com) | Campaign analysis |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Patch Adobe ColdFusion against CVE-2026-48282 across all external and internal ColdFusion RDS deployments; if patching is not possible within 24 hours, disable the RDS component and block RDS network paths at the perimeter (ties to §3.1).
- 🔴 **IMMEDIATE:** Confirm Langflow instances are patched per the CISA KEV directive and rotate credentials configured into any hosted AI agents (ties to §3.4).
- 🔴 **IMMEDIATE:** Verify Linux kernel package versions on all servers, container hosts, and hypervisors are at or beyond the GhostLock/Januscape fixed release; treat any lagging distribution kernel as a hard privilege-escalation risk regardless of user hardening (ties to §3.2).
- 🔴 **IMMEDIATE:** Rebuild any self-hosted Gitea Docker deployment from the fixed image and audit admin users, SSH keys, deploy tokens, and webhooks for unauthorised additions (ties to §3.6).
- 🟠 **SHORT-TERM:** Push the July Chromium/Edge critical batch (V8/ANGLE/Skia + CVE-2026-58281) to fleet within 72 hours; gate SaaS access on browser compliance where feasible (ties to §3.5).
- 🟠 **SHORT-TERM:** Enforce Microsoft's vulnerable-driver blocklist and HVCI/Memory Integrity across the endpoint estate to blunt PoisonX-class BYOVD attacks; add the GodDamn SHA256 IOCs to detection controls (ties to §3.7).
- 🟠 **SHORT-TERM:** Audit `package-lock.json` / `yarn.lock` for `@injectivelabs/sdk-ts`, rotate any developer-held crypto wallet seeds handled on affected workstations, and treat build-agent egress as an incident-hunting priority for the reporting window (ties to §3.3).
- 🟡 **AWARENESS:** Update all AI coding assistants (Q Developer, Cursor, Antigravity, Claude Code, Augment, Windsurf) to fixed versions where available; restrict assistants from opening untrusted repositories and add FIM on developer machines for writes into `~/.ssh`, `~/.aws`, and shell rc files (ties to §3.9).
- 🟡 **AWARENESS:** Inventory internet-exposed edge network gear (Ruckus, ASUS AiCloud, Tenda, Ubiquiti, BeyondTrust) and treat the CVEs referenced in §3.8 and §3.10 as priority remediation for the perimeter team.
- 🟢 **STRATEGIC:** Track the AI-agent tooling stack (Langflow, MCP servers, AI coding assistants) as an emerging attack surface with its own asset inventory, credential handling, and monitoring expectations; SANS scanning telemetry and GhostApproval both point to adversary reconnaissance and exploitation of this layer.

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 563 reports processed across 14 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
