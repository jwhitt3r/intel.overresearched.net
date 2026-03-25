---
layout: post
title: "CTI Daily Brief: 2026-03-24 — TeamPCP Supply Chain Campaign Escalates; SharePoint RCE Added to CISA KEV; VoidLink Rootkit Framework Exposed"
date: 2026-03-25 21:02:00 +0000
description: "77 reports processed across 15 sources. Dominant theme: TeamPCP supply chain campaign targeting AI/cloud tooling (LiteLLM, Trivy). Critical SharePoint RCE (CVE-2026-20963) confirmed exploited in the wild and added to CISA KEV. VoidLink AI-developed Linux rootkit framework analysed. Nightspire ransomware group claims 4 new victims."
category: daily
tags: [cti, daily-brief, teampcp, voidlink, cve-2026-20963, torg-grabber, nightspire]
classification: TLP:CLEAR
reporting_period: "2026-03-24"
generated: "2026-03-25"
draft: true
severity: critical
report_count: 77
sources:
  - Microsoft
  - BleepingComputer
  - RansomLock
  - RecordedFutures
  - AlienVault
  - SANS
  - Wired Security
  - CertEU
  - Schneier
  - Sysdig
  - Unit42
  - Wiz
  - Elastic Security Labs
  - Crowdstrike
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-03-24 (24h) | TLP:CLEAR | 2026-03-25 |

## 1. Executive Summary

The pipeline processed 77 reports from 15 sources over the past 24 hours, with 16 rated critical and 21 rated high. The dominant theme is the escalation of the **TeamPCP supply chain campaign**, which compromised the widely-used LiteLLM PyPI package (3.4 million daily downloads) and continues to ripple outward from the earlier Trivy and Checkmarx breaches. CERT-EU issued advisory 2026-004 confirming that **CVE-2026-20963**, a CVSS 9.8 unauthenticated RCE in Microsoft SharePoint, is being **exploited in the wild** and has been added to the **CISA Known Exploited Vulnerabilities catalogue**. Elastic Security Labs published a deep technical analysis of the **VoidLink rootkit framework**, an AI-developed, modular Linux rootkit combining LKM and eBPF techniques attributed to a Chinese-speaking threat actor. Ransomware operations remain highly active, with **Nightspire** claiming four new victims across healthcare, environmental services, and manufacturing sectors.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 16 | TeamPCP supply chain (LiteLLM, Trivy); SharePoint RCE KEV; VoidLink rootkit; TP-Link auth bypass; PTC Windchill RCE; wolfSSL CVEs |
| 🟠 **HIGH** | 21 | SmartApeSG RAT campaign; Citrix NetScaler flaws; Nightspire ransomware cluster; KslKatz credential dumper; botnet operator sentencing |
| 🟡 **MEDIUM** | 33 | wolfSSL TLS vulnerabilities; tar-rs symlink chmod; Python webbrowser.open flaw; satellite data weaponisation analysis |
| 🟢 **LOW** | 2 | Miscellaneous advisories |
| 🔵 **INFO** | 5 | AI security tooling; underground marketplace reporting |

## 3. Priority Intelligence Items

### 3.1 TeamPCP Supply Chain Campaign Compromises LiteLLM and Trivy Ecosystems

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/popular-litellm-pypi-package-compromised-in-teampcp-supply-chain-attack/), [RecordedFutures](https://therecord.media/supply-chain-attack-hits-widely-used-ai-package), [Microsoft](https://www.microsoft.com/en-us/security/blog/2026/03/24/detecting-investigating-defending-against-trivy-supply-chain-compromise/), [AlienVault](https://otx.alienvault.com/pulse/69c3bb29c62248c6ffd0b50c)

TeamPCP continued its supply chain rampage by compromising LiteLLM versions 1.82.7 and 1.82.8 on PyPI. LiteLLM is a gateway library to multiple LLM providers with over 3.4 million daily downloads. The injected payload deploys the "TeamPCP Cloud Stealer," harvesting SSH keys, cloud credentials (AWS, GCP, Azure), Kubernetes secrets, cryptocurrency wallets, and `.env` files. Version 1.82.8 introduced a `.pth` file persistence mechanism that executes malicious code whenever the Python interpreter starts, regardless of whether LiteLLM is imported. Microsoft published detection and remediation guidance for the upstream Trivy compromise that initiated this campaign, confirming TeamPCP exploited mutable GitHub tags and commit identity spoofing. Approximately 500,000 data exfiltrations have been reported, though many are believed to be duplicates. ATT&CK techniques: T1195.002 (Supply Chain Compromise), T1078 (Valid Accounts), T1059.006 (Python), T1552.001 (Credentials in Files), T1041 (Exfiltration Over C2).

#### Indicators of Compromise
```
Domain: checkmarx[.]zone
Domain: aquasecurtiy[.]org (typosquat)
Host: scan[.]aquasecurtiy[.]org
Host: plug-tab-protective-relay[.]trycloudflare[.]com
Host: tdtqy-oyaaa-aaaae-af2dq-cai[.]raw[.]icp0[.]io
IP: 45[.]148[.]10[.]122
IP: 45[.]148[.]10[.]212
Malicious packages: litellm 1.82.7, litellm 1.82.8
Persistence file: litellm_init.pth
```

> **SOC Action:** Audit all Python environments for LiteLLM versions 1.82.7 and 1.82.8. Search for the presence of `litellm_init.pth` in Python site-packages directories. Query DNS logs for `checkmarx[.]zone` and `aquasecurtiy[.]org`. Scan CI/CD pipelines for Trivy and Checkmarx GitHub Actions pinned to mutable tags rather than commit SHAs. Review systemd user services for entries named "System Telemetry Service."

### 3.2 CVE-2026-20963: SharePoint Unauthenticated RCE Exploited in the Wild (CISA KEV)

**Source:** [CERT-EU](https://cert.europa.eu/publications/security-advisories/2026-004/)

CERT-EU advisory 2026-004 confirms that CVE-2026-20963, a CVSS 9.8 unauthenticated remote code execution vulnerability in Microsoft SharePoint, is being actively exploited. The flaw arises from deserialization of untrusted data and requires no user interaction or privileges. Microsoft updated the advisory on 17 March to raise the CVSS score and confirm unauthenticated exploitability; CISA added it to the KEV catalogue on 18 March. Three additional SharePoint RCE vulnerabilities (CVE-2026-26106, CVE-2026-26113, CVE-2026-26114) were also patched in the March 2026 release. Affected products include SharePoint Server Subscription Edition, SharePoint Server 2019, and SharePoint Enterprise Server 2016.

> **SOC Action:** Patch all SharePoint Server instances immediately, prioritising internet-facing deployments. Enable AMSI in Full Mode on SharePoint servers. Deploy EDR on SharePoint hosts. Rotate ASP.NET machine keys and restart IIS via `iisreset.exe`. Conduct a compromise assessment on internet-facing SharePoint assets, searching for webshells and unusual deserialization activity.

### 3.3 VoidLink: AI-Developed Linux Rootkit Framework with Hybrid LKM-eBPF Architecture

**Source:** [Elastic Security Labs](https://www.elastic.co/security-labs/illuminating-voidlink)

Elastic Security Labs published a technical deep-dive on VoidLink, a sophisticated Linux rootkit framework attributed to a Chinese-speaking threat actor. VoidLink combines traditional Loadable Kernel Modules with eBPF programs in a hybrid design. The LKM component performs syscall hooking via ftrace and maintains an ICMP-based covert command channel, while a companion eBPF program hides network connections by manipulating Netlink socket responses. The framework spans at least four generations, from CentOS 7 (direct syscall table patching) to Ubuntu 22.04 ("Ultimate Stealth v5" with delayed hook installation, anti-debugging timers, process kill protection, and XOR-obfuscated module names). The source code confirms the framework was developed through AI-assisted workflows using the TRAE IDE, with a single developer producing the implant from concept to deployment in under a week.

> **SOC Action:** On Linux infrastructure, audit loaded kernel modules for names matching `vl_stealth` or `amd_mem_encrypt`. Monitor for unexpected eBPF program attachments using `bpftool prog list`. Inspect ICMP traffic for anomalous payloads. Check for ftrace hooks on critical syscalls (`getdents64`, `kill`, `recvmsg`). Verify kernel module signing is enforced.

### 3.4 PTC Windchill/FlexPLM Critical RCE — German Federal Police Issue Emergency Alerts

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/ptc-warns-of-imminent-threat-from-critical-windchill-flexplm-rce-bug/)

PTC disclosed CVE-2026-4681, a critical RCE vulnerability in Windchill and FlexPLM product lifecycle management systems caused by deserialization of trusted data. No patch is available yet. The severity prompted Germany's BKA (federal police) to dispatch agents directly to affected companies over the weekend, reportedly waking system administrators in the middle of the night. PTC states there is "credible evidence of an imminent threat by a third-party group to exploit the vulnerability." PLM systems are used extensively in weapons system design, industrial manufacturing, and critical supply chains.

#### Indicators of Compromise
```
Files: GW.class, payload.bin, dpr_<8-hex-digits>.jsp
Request patterns: run?p= / .jsp?c= with unusual User-Agent
Log signatures: GW, GW_READY_OK, unexpected gateway exceptions
```

> **SOC Action:** Apply PTC's Apache/IIS rule to deny access to the affected servlet path on all Windchill/FlexPLM deployments, including file/replica servers. Prioritise internet-facing instances. If mitigation is not possible, disconnect affected instances from the internet. Monitor web server logs for the IOC patterns listed above, specifically `GW.class` and `dpr_*.jsp` webshells.

### 3.5 SmartApeSG Campaign Delivers Multi-RAT Payload via ClickFix

**Source:** [SANS ISC](https://isc.sans.edu/diary/rss/32826)

SANS ISC documented a SmartApeSG (ZPHP/HANEYMANEY) campaign observed on 24 March deploying a four-stage malware chain via the ClickFix technique: Remcos RAT (C2 at 17:12 UTC), NetSupport RAT (17:16 UTC), StealC (18:18 UTC), and Sectop RAT/ArechClient2 (19:36 UTC). Initial access uses fake CAPTCHA pages injected into compromised legitimate websites, tricking users into executing a clipboard-hijacked PowerShell command. ATT&CK techniques: T1566 (Phishing), T1059.001 (Execution via HTA).

#### Indicators of Compromise
```
Domain: fresicrto[.]top (fake CAPTCHA hosting)
Domain: urotypos[.]com (initial malware hosting)
C2: 95[.]142[.]45[.]231:443 (Remcos RAT)
C2: 185[.]163[.]47[.]220:443 (NetSupport RAT)
C2: 89[.]46[.]38[.]100:80 (StealC)
C2: 195[.]85[.]115[.]11:9000 (Sectop RAT)
SHA256: 212d8007a7ce374d38949cf54d80133bd69338131670282008940f1995d7a720 (HTA)
SHA256: a6a748c0606fb9600fdf04763523b7da20b382b054b875fdd1ef1c36fc16079a (Remcos ZIP)
```

> **SOC Action:** Block the listed domains and IPs at the network perimeter. Query EDR for `mshta.exe` spawning from user temp directories or `AppData\Local`. Search proxy logs for connections to `urotypos[.]com` and `fresicrto[.]top`. Alert on PowerShell execution initiated from clipboard paste operations. Hunt for NetSupport RAT artefacts under `C:\ProgramData\UpdateInstaller\`.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Supply chain attacks targeting AI and cloud environments are intensifying | TeamPCP compromised LiteLLM (PyPI), Trivy, Checkmarx KICS, and deployed CanisterWorm against Kubernetes clusters. 4 correlated reports, confidence 0.90. Shared TTPs: T1078, T1059.006, T1552.001. |
| 🟠 **HIGH** | Ransomware operations targeting healthcare and insurance sectors | Nightspire claimed 4 victims; Medusa hit Live! Casino; Inc Ransom targeted Glenmark Pharma and PWNA Plains; Payload group hit Vancompare Insurance. 7 correlated reports across 4 ransomware groups. |
| 🟠 **HIGH** | Geopolitical tensions driving cyber activity involving Iran and Russia | Russian botnet operator (Ilya Angelov) sentenced for IcedID/BitPaymer operations. TeamPCP's CanisterWorm deploys Kubernetes wiper targeting Iran-configured systems. |
| 🟡 **MEDIUM** | Phishing remains the dominant initial access vector across campaigns | SmartApeSG ClickFix campaign, Torg Grabber ClickFix delivery, recruiter impersonation scams, and multiple ransomware groups all leveraging T1566. 17 correlated reports. |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **TeamPCP** (15 reports) — Supply chain attack group behind Trivy, LiteLLM, and Checkmarx compromises; deploys CanisterWorm and Cloud Stealer
- **Nightspire** (11 reports) — Ransomware group with 4 new victims this period spanning healthcare, manufacturing, and environmental services
- **Handala** (9 reports) — Pro-Palestinian hacktivist group linked to prior operations against Israeli infrastructure
- **Akira** (7 reports) — Ransomware-as-a-service group maintaining steady operational tempo across multiple sectors
- **Qilin** (6 reports) — Ransomware group with recent healthcare sector targeting
- **ShinyHunters** (5 reports) — Data extortion group; claimed Berkadia Commercial Mortgage breach this period
- **UNC6353** (5 reports) — Threat cluster tracked across multiple recent campaigns

### Malware Families

- **Akira ransomware** (6 reports) — RaaS variant with broad sector targeting
- **CanisterWorm** (5 reports) — TeamPCP's Kubernetes backdoor with Iran-targeted wiper capability
- **Remcos RAT** (4 reports) — Deployed via SmartApeSG ClickFix campaign alongside other RATs
- **PLAY ransomware** (4 reports) — Hive-affiliated ransomware variant observed in new attacks
- **TeamPCP Cloud Stealer** (4 reports) — Credential harvester deployed via supply chain compromises
- **Torg Grabber** (new) — Rapidly evolving infostealer targeting 728 crypto wallets, 103 password managers

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| Microsoft | 33 | [link](https://msrc.microsoft.com/update-guide) | wolfSSL, Valkey, and tar-rs CVE advisories |
| RansomLock | 11 | [link](https://www.ransomlook.io) | Nightspire, Medusa, Inc Ransom, Payload, ShinyHunters, Chaos victim claims |
| BleepingComputer | 8 | [link](https://www.bleepingcomputer.com) | LiteLLM supply chain, Torg Grabber, TP-Link, PTC Windchill, Citrix NetScaler |
| RecordedFutures | 6 | [link](https://therecord.media) | Supply chain attack coverage, botnet operator sentencing |
| AlienVault | 3 | [link](https://otx.alienvault.com) | PyPI supply chain IOC pulses, Trivy detection guidance |
| SANS | 3 | [link](https://isc.sans.edu) | SmartApeSG ClickFix campaign IOCs |
| Unknown | 3 | — | Telegram-sourced intelligence including KslKatz credential dumper analysis |
| Wired Security | 2 | [link](https://www.wired.com/category/security) | Satellite data weaponisation, AI account marketplace |
| CertEU | 1 | [link](https://cert.europa.eu) | SharePoint CVE-2026-20963 exploitation advisory |
| Schneier | 1 | [link](https://www.schneier.com) | Security commentary |
| Sysdig | 1 | [link](https://sysdig.com) | Cloud security analysis |
| Unit42 | 1 | [link](https://unit42.paloaltonetworks.com) | Recruiting impersonation phishing scheme |
| Wiz | 1 | [link](https://www.wiz.io) | Cloud security research |
| Elastic Security Labs | 1 | [link](https://www.elastic.co/security-labs) | VoidLink rootkit framework technical analysis |
| Crowdstrike | 1 | [link](https://www.crowdstrike.com) | Agentic AI security tooling |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Audit all Python environments and CI/CD pipelines for compromised LiteLLM (1.82.7/1.82.8), Trivy, and Checkmarx KICS GitHub Actions. Pin all dependency references to immutable commit SHAs. Search for `litellm_init.pth` persistence artefacts and `checkmarx[.]zone` DNS queries.

- 🔴 **IMMEDIATE:** Patch Microsoft SharePoint Server against CVE-2026-20963 (CVSS 9.8, actively exploited, CISA KEV). Enable AMSI Full Mode, deploy EDR, rotate ASP.NET machine keys, and conduct compromise assessments on internet-facing instances.

- 🔴 **IMMEDIATE:** Apply PTC's vendor-provided servlet path blocking rule to all Windchill and FlexPLM deployments (CVE-2026-4681). Disconnect internet-facing instances if the mitigation cannot be applied. Monitor for webshell indicators (`GW.class`, `dpr_*.jsp`).

- 🟠 **SHORT-TERM:** Patch Citrix NetScaler ADC and Gateway to versions 13.1-62.23 or 14.1-66.59 to remediate CVE-2026-3055 (CitrixBleed-class memory overread). Review SAML IDP configurations for indicators of session token theft. Update TP-Link Archer NX routers to address CVE-2025-15517 authentication bypass.

- 🟡 **AWARENESS:** Brief SOC analysts on the SmartApeSG ClickFix technique. The campaign weaponises clipboard hijacking via fake CAPTCHA pages on compromised sites. Hunt for `mshta.exe` execution from user temp directories and connections to the listed C2 IPs. Torg Grabber's rapid evolution (334 samples in 3 months) warrants monitoring for new C2 infrastructure.

- 🟢 **STRATEGIC:** The VoidLink rootkit demonstrates that AI-assisted malware development has reached production-grade rootkit capabilities. Ensure Linux fleet has kernel module signing enforced, eBPF programme visibility via `bpftool`, and ICMP anomaly detection. Review organisational posture against AI-accelerated threat development.

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 77 reports processed across 4 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
