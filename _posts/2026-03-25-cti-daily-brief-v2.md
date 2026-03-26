---
layout: post
title: "CTI Daily Brief: 2026-03-25 — TeamPCP Supply Chain Campaign Widens With CISA KEV Addition; Qilin Ransomware Surge Across Multiple Sectors"
date: 2026-03-26 21:04:00 +0000
description: "155 reports processed across 15 sources. Dominant themes include the expanding TeamPCP supply chain campaign with CISA KEV entry for CVE-2026-33634, mass exploitation of Magento PolyShell targeting 56% of vulnerable stores, the Coruna iOS exploit framework linked to Operation Triangulation, and a surge in Qilin ransomware claims across healthcare, manufacturing, and retail."
category: daily
tags: [cti, daily-brief, teampcp, qilin, coruna, voidlink, polyshell, cve-2026-33634]
classification: TLP:CLEAR
reporting_period: "2026-03-25"
generated: "2026-03-26"
severity: critical
draft: true
report_count: 155
sources:
  - Microsoft
  - RansomLock
  - BleepingComputer
  - RecordedFutures
  - SANS
  - CISA
  - Wired Security
  - Cisco Talos
  - HaveIBeenPwned
  - AlienVault
  - Elastic Security Labs
  - Wiz
  - Sysdig
  - Schneier
  - RedCanary
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-03-25 (24h) | TLP:CLEAR | 2026-03-26 |

## 1. Executive Summary

The pipeline processed 155 reports from 15 sources in the last 24 hours, with 30 rated critical, 36 high, 81 medium, 7 low, and 1 informational. The dominant theme is the continued expansion of the TeamPCP supply chain campaign: SANS published an update confirming all 91 Checkmarx `ast-github-action` tags were compromised (not just `v2.3.28`), and CISA added CVE-2026-33634 to the Known Exploited Vulnerabilities catalogue with a federal remediation deadline of April 3, 2026. Separately, BleepingComputer reported that PolyShell exploitation hit 56.7% of all vulnerable Magento/Adobe Commerce stores, deploying a novel WebRTC-based payment skimmer. Kaspersky researchers linked the Coruna iOS exploit framework to the Operation Triangulation espionage campaign, now expanded to target Apple A17/M3 chips and iOS 17.2. Elastic Security Labs published a deep technical analysis of VoidLink, an AI-developed Linux rootkit combining LKM and eBPF for kernel-level persistence. Ransomware activity surged with Qilin claiming 12 victims across healthcare, manufacturing, and retail, while DragonForce and Inc Ransom added further claims.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 30 | TeamPCP supply chain update + CISA KEV; Coruna iOS framework; PTC Windchill RCE (CVE-2026-4681); WAGO switch compromise (CVE-2026-3587); strongSwan underflow (CVE-2026-25075); PolyShell mass exploitation; VoidLink rootkit; Linux kernel CVEs; Qilin/ShinyHunters/DragonForce/Interlock ransomware claims |
| 🟠 **HIGH** | 36 | Qilin ransomware (12 victims); CipherForce targeting BMW/Sportradar; Inc Ransom claims; TikTok Business phishing; Bearlyfy custom ransomware; RedLine admin extradition; LeakBase forum takedown; Scarlet Goldfinch ClickFix evolution; CISA OC Messaging advisory |
| 🟡 **MEDIUM** | 81 | Microsoft CVE batch (kernel, WiFi, BPF, netfilter); Eraleign/APT73 claims; Pear ransomware; financial fraud analysis |
| 🟢 **LOW** | 7 | Minor vulnerability disclosures; compatibility advisories |
| 🔵 **INFO** | 1 | AI infrastructure security commentary |

## 3. Priority Intelligence Items

### 3.1 TeamPCP Supply Chain Campaign — All 91 Checkmarx Tags Compromised, CISA KEV Addition

**Source:** [SANS ISC](https://isc.sans.edu/diary/rss/32834)

The TeamPCP supply chain campaign expanded significantly. An independent researcher provided primary evidence that all 91 published tags of the Checkmarx `ast-github-action` were overwritten with credential-stealing composite actions — not just the single `v2.3.28` tag that initial reporting anchored on. Each malicious commit was individually crafted with version-appropriate backdated timestamps and fake commit messages. Three malicious commits remain publicly visible on GitHub (`f1d2a3477e0d`, `f58de2470825`, `aa52a82cddf2`).

CISA added CVE-2026-33634 (CVSS 9.4) to the Known Exploited Vulnerabilities catalogue, confirming active exploitation. Federal agencies must remediate by April 3, 2026. Safe versions: Trivy binary ≥ v0.69.2, `trivy-action` v0.35.0 (or pin to SHA `57a97c7e7821a5776cebc9bb984fa69cba8f1`), `setup-trivy` v0.2.6.

**MITRE ATT&CK:** T1195.002 (Supply Chain Compromise: Compromise Software Supply Chain), T1059 (Command and Scripting Interpreter)

> **SOC Action:** Search all CI/CD workflow logs for ANY reference to `checkmarx/ast-github-action` that executed between 12:58 and 19:16 UTC on March 23, 2026. If found, treat all secrets accessible to that workflow as compromised and rotate immediately. Audit for use of Trivy, `trivy-action`, and `setup-trivy` — verify pinned versions match safe hashes.

### 3.2 PolyShell Mass Exploitation Targets 56% of Vulnerable Magento Stores

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/polyshell-attacks-target-56-percent-of-all-vulnerable-magento-stores/)

Mass exploitation of the PolyShell vulnerability in Magento Open Source and Adobe Commerce began on March 19, two days after public disclosure. Sansec confirmed that 56.7% of all vulnerable stores have been hit. The flaw resides in Magento's REST API, which accepts file uploads as cart item custom options, enabling polyglot files to achieve RCE or stored XSS.

Attackers deployed a novel WebRTC-based payment card skimmer that uses DTLS-encrypted UDP for data exfiltration, bypassing Content Security Policy `connect-src` directives. The skimmer connects to hardcoded C2 via forged SDP exchange and executes second-stage payloads by reusing existing script nonces. Sansec detected the skimmer on the e-commerce site of a car manufacturer valued at over $100 billion.

Adobe released a fix in version 2.4.9-beta1 on March 10, but no stable-branch patch exists yet.

**MITRE ATT&CK:** T1059 (Command and Script Execution), T1020 (Exfiltration)

> **SOC Action:** Audit all Magento/Adobe Commerce instances for version currency. If running any version prior to 2.4.9-beta1, apply the Sansec virtual patch immediately. Monitor WAF logs for polyglot file upload attempts via the REST API (`/rest/V1/carts/*/items`). Inspect JavaScript resources for unexpected WebRTC `RTCPeerConnection` initialisation calls.

### 3.3 Coruna iOS Exploit Framework Linked to Operation Triangulation

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/coruna-ios-exploit-framework-linked-to-triangulation-attacks/)

Kaspersky researchers determined that the Coruna exploit kit is a continuously maintained evolution of the framework used in Operation Triangulation, the 2023 zero-click iMessage espionage campaign. Coruna contains five full iOS exploit chains leveraging 23 vulnerabilities (including CVE-2023-32434 and CVE-2023-38606), now expanded to target Apple A17, M3, M3 Pro, and M3 Max chips and iOS versions up to 17.2.

The attack chain begins in Safari with a stager that fingerprints the device, selects suitable RCE and PAC exploits, retrieves encrypted metadata, downloads additional components encrypted with ChaCha20/LZMA, and deploys a spyware implant. Coruna has also been observed in financially-motivated campaigns stealing cryptocurrency via fake exchange websites.

A separate exploit kit, DarkSword, was disclosed earlier this month and is now publicly available, increasing the risk to unpatched iOS devices.

> **SOC Action:** Ensure all managed iOS devices are updated to iOS 17.2 or later. MDM administrators should enforce minimum OS version policies and monitor for unusual Safari-initiated network connections to unknown domains. Organisations handling cryptocurrency should alert staff to fake exchange sites.

### 3.4 VoidLink: AI-Developed Linux Rootkit with Hybrid LKM/eBPF Architecture

**Source:** [Elastic Security Labs](https://www.elastic.co/security-labs/illuminating-voidlink)

Elastic Security Labs published a detailed analysis of VoidLink, a cloud-native Linux rootkit framework attributed to a Chinese-speaking threat actor. VoidLink combines traditional Loadable Kernel Modules (LKMs) with eBPF programs in a hybrid design that provides kernel-level persistence while hiding network connections from `ss` by manipulating Netlink socket responses.

The rootkit features syscall hooking via ftrace, an ICMP-based covert C2 channel, anti-debugging timers, process kill protection, and XOR-obfuscated module names. At least four generations were identified, spanning CentOS 7 through Ubuntu 22.04. The most recent variant, dubbed "Ultimate Stealth v5" by its developers, introduces delayed hook installation. The source code contains AI-development artefacts (phased annotations, tutorial-style comments) confirming AI-assisted development using the TRAE IDE.

**MITRE ATT&CK:** T1014 (Rootkit), T1027 (Obfuscated Files), T1574 (Hijack Execution Flow), T1095 (Non-Application Layer Protocol), T1205 (Traffic Signalling)

> **SOC Action:** On Linux hosts, check for unexpected kernel modules with `lsmod` — look for modules named `vl_stealth` or `amd_mem_encrypt`. Monitor for anomalous ICMP traffic patterns to external hosts. Deploy eBPF-aware detection (e.g., Elastic Defend) and audit for unexpected eBPF programs via `bpftool prog list`. Prioritise patching CentOS 7 through Ubuntu 22.04 kernels.

### 3.5 CISA ICS Advisories — PTC Windchill RCE and WAGO Switch Compromise

**Source:** [CISA ICSA-26-085-03](https://www.cisa.gov/news-events/ics-advisories/icsa-26-085-03), [CISA ICSA-26-085-01](https://www.cisa.gov/news-events/ics-advisories/icsa-26-085-01)

CISA issued two critical ICS advisories:

**PTC Windchill (CVE-2026-4681, CVSS 10.0):** A deserialization-based RCE vulnerability affecting Windchill PDMLink versions 11.0 through 13.1.3.0 and FlexPLM versions 11.0 through 13.0.3.0. PTC is developing a fix; interim mitigations include restricting public access and applying HTTP server configuration updates. The Critical Manufacturing sector is the primary target.

**WAGO Industrial Switches (CVE-2026-3587, CVSS 10.0):** An unauthenticated remote attacker can exploit a hidden CLI function to escape the restricted interface and fully compromise the device. Affected firmware spans 30+ hardware/firmware combinations across the 852-series switch portfolio. Sectors impacted include Critical Manufacturing, Energy, and Transportation Systems.

> **SOC Action:** Immediately audit for PTC Windchill and WAGO 852-series switches in asset inventories. For Windchill, restrict public-facing access and apply the vendor-recommended HTTP server configuration hardening. For WAGO switches, update firmware to the patched versions listed in ICSA-26-085-01 and isolate any switches that cannot be immediately patched behind network segmentation.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Supply chain vulnerabilities exploited by TeamPCP, affecting critical manufacturing sectors | TeamPCP supply chain update (SANS); PTC Windchill RCE (CISA); WAGO switch compromise (CISA) |
| 🔴 **CRITICAL** | Mass exploitation of vulnerabilities in widely used software platforms | PolyShell attacks on 56% of Magento stores; CISA KEV addition for CVE-2026-33634 |
| 🟠 **HIGH** | Ransomware surge by Qilin and DragonForce across healthcare, retail, and manufacturing | 12 Qilin victim claims; 3 DragonForce claims; Louise Medical Center, Washoe Tribe, Bedrosians targeted |
| 🟠 **HIGH** | Phishing campaigns prevalent in financial and technology sectors | TikTok Business account phishing; TeamPCP credential harvesting; modern fraud attack patterns |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **Qilin** (18 reports) — Prolific ransomware operator claiming 12 new victims in 24 hours across healthcare, manufacturing, retail, and energy
- **TeamPCP** (21 reports, combined) — Supply chain threat actor behind the Checkmarx/Trivy/LiteLLM compromise chain; CISA KEV entry confirms active exploitation
- **Nightspire** (11 reports) — Ransomware group with recent multi-sector targeting
- **ShinyHunters** (6 reports) — Data breach actor; ZenBusiness, Inc. claimed as victim
- **Inc Ransom** (5 reports) — Ransomware affiliate claiming law firm and industrial targets
- **Scarlet Goldfinch / SmartApeSG** (reported by Red Canary) — ClickFix/paste-and-run initial access cluster deploying NetSupport Manager and Remcos RAT
- **Bearlyfy** (reported by Recorded Future) — Pro-Ukrainian group escalating ransomware against Russian companies with custom GenieLocker malware

### Malware Families

- **Qilin ransomware** (7 reports) — Primary payload in Qilin operator campaigns
- **Akira ransomware** (6 reports) — Persistent ransomware-as-a-service operation
- **CanisterWorm** (5 reports) — Worm with recent activity spike
- **Coruna** (4 reports) — iOS exploit framework evolved from Operation Triangulation
- **VoidLink** (reported by Elastic) — AI-developed Linux rootkit with hybrid LKM/eBPF architecture
- **Remcos RAT** (4 reports) — Deployed by Scarlet Goldfinch in ClickFix campaigns
- **TeamPCP Cloud Stealer** (4 reports) — Credential-stealing payload from TeamPCP supply chain

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| Microsoft | 84 | [link](https://msrc.microsoft.com) | Bulk CVE disclosures (Linux kernel, strongSwan, network subsystems) |
| RansomLock | 30 | [link](https://ransomlock.com) | Ransomware victim claim monitoring (Qilin, DragonForce, Inc Ransom, CipherForce, ShinyHunters) |
| BleepingComputer | 9 | [link](https://www.bleepingcomputer.com) | Coruna iOS framework, PolyShell exploitation, TikTok phishing, RedLine extradition |
| RecordedFutures | 6 | [link](https://therecord.media) | China scam compounds, Bearlyfy ransomware, LeakBase takedown, UK crypto sanctions |
| SANS | 4 | [link](https://isc.sans.edu) | TeamPCP supply chain campaign update with CISA KEV details |
| CISA | 3 | [link](https://www.cisa.gov) | ICS advisories for PTC Windchill, WAGO switches, OpenCode Systems |
| Wired Security | 3 | [link](https://www.wired.com/category/security/) | $20B crypto scam crackdown reporting |
| Cisco Talos | 3 | [link](https://blog.talosintelligence.com) | TP-Link/Canva/HikVision vulnerabilities; 2025 Talos insights |
| Elastic Security Labs | 2 | [link](https://www.elastic.co/security-labs) | VoidLink rootkit analysis; BRUSHWORM/BRUSHLOGGER |
| HaveIBeenPwned | 2 | [link](https://haveibeenpwned.com) | Data breach monitoring |
| AlienVault | 2 | [link](https://otx.alienvault.com) | VoidLink rootkit IOCs |
| RedCanary | 1 | [link](https://redcanary.com/blog) | Scarlet Goldfinch ClickFix evolution report |
| Wiz | 1 | [link](https://www.wiz.io/blog) | Cloud security analysis |
| Sysdig | 1 | [link](https://sysdig.com/blog) | Container/cloud threat detection |
| Schneier | 1 | [link](https://www.schneier.com) | Security commentary |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Audit all CI/CD pipelines for references to `checkmarx/ast-github-action` and Trivy-related actions. Rotate all secrets from any workflow that executed between 12:58–19:16 UTC on March 23, 2026. Verify Trivy binary is ≥ v0.69.2 and actions are pinned to safe SHAs. CISA KEV deadline for CVE-2026-33634 is April 3, 2026.

- 🔴 **IMMEDIATE:** Patch or apply virtual patching for Magento/Adobe Commerce instances vulnerable to PolyShell. Monitor for WebRTC-based skimmer activity on e-commerce platforms. No stable-branch fix from Adobe exists yet — Sansec's virtual patch is the current mitigation.

- 🔴 **IMMEDIATE:** Audit asset inventories for PTC Windchill PDMLink/FlexPLM and WAGO 852-series industrial switches. Apply vendor-recommended mitigations for CVE-2026-4681 (CVSS 10.0) and CVE-2026-3587 (CVSS 10.0). Restrict public-facing access to Windchill instances and isolate unpatched WAGO switches behind network segmentation.

- 🟠 **SHORT-TERM:** Ensure all managed iOS devices are updated to iOS 17.2+ to mitigate Coruna exploit chains. Enforce MDM minimum OS version policies. Alert cryptocurrency-facing staff to fake exchange sites linked to Coruna's financially-motivated operations.

- 🟠 **SHORT-TERM:** On Linux infrastructure, hunt for VoidLink indicators: unexpected kernel modules (`vl_stealth`, `amd_mem_encrypt`), anomalous ICMP C2 traffic, and unrecognised eBPF programs. Deploy eBPF-aware endpoint detection across cloud workloads running CentOS 7 through Ubuntu 22.04.

- 🟡 **AWARENESS:** Monitor for Qilin and DragonForce ransomware activity — 15 combined victim claims in 24 hours indicate an operational surge. Ensure healthcare, retail, and manufacturing sector clients have current backups and incident response playbooks tested.

- 🟡 **AWARENESS:** Brief users on TikTok Business phishing campaign using Cloudflare-hosted reverse proxies to steal credentials and session cookies, bypassing 2FA via adversary-in-the-middle techniques. Recommend passkey adoption for high-value advertising accounts.

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 155 reports processed across 4 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
