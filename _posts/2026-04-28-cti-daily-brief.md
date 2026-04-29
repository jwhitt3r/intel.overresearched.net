---
layout: post
title:  "CTI Daily Brief: 2026-04-28 - LiteLLM SQLi (CVE-2026-42208) actively exploited; ProFTPD CVE-2026-42167 PoC released; TeamPCP linked to VECT 2.0 wiper"
date:   2026-04-29 20:05:00 +0000
description: "Two critical vulnerabilities under active or PoC exploitation (LiteLLM CVE-2026-42208, ProFTPD CVE-2026-42167); TeamPCP threat group ties LiteLLM exploitation to broken VECT 2.0 ransomware acting as a wiper; sustained ransomware extortion against healthcare and property management; phishing remains the dominant initial-access vector."
category: daily
tags: [cti, daily-brief, teampcp, gachiloader, inc-ransom, m3rx, cve-2026-42208, cve-2026-42167]
classification: TLP:CLEAR
reporting_period: "2026-04-28"
generated: "2026-04-29"
draft: true
severity: critical
report_count: 14
sources:
  - BleepingComputer
  - AlienVault OTX
  - RansomLook
  - SANS ISC
  - Telegram (channel name redacted)
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-04-28 (24h) | TLP:CLEAR | 2026-04-29 |

## 1. Executive Summary

The pipeline ingested 14 reports across 5 sources in the last 24 hours, dominated by ransomware leak-site postings (RansomLook, 8 reports) and rounded out by two critical vulnerability items. The headline finding is in-the-wild exploitation of **CVE-2026-42208**, a pre-authentication SQL injection in the LiteLLM AI gateway that began roughly 36 hours after public disclosure and is targeting stored API keys and provider credentials directly. A second critical, **CVE-2026-42167** in ProFTPD, surfaced via Telegram with a proof-of-concept attached (TLP:AMBER+STRICT — details redacted). Threat group **TeamPCP** features in three correlated reports: the LiteLLM exploitation, prior supply-chain compromises, and a partnership announcement with the operators of VECT 2.0 ransomware — which Check Point has shown destroys data above 128 KB due to flawed nonce handling, effectively functioning as a wiper. Outside vulnerability work, phishing remained the dominant TTP across seven distinct reports, including the GachiLoader/Rhadamanthys campaign abusing AI-agent skill formats and a fake-DHL credential-theft kit using EmailJS exfiltration. No CISA KEV additions were observed in the collection window.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 2 | LiteLLM CVE-2026-42208 active exploitation; ProFTPD CVE-2026-42167 PoC |
| 🟠 **HIGH** | 10 | VECT 2.0 wiper-by-flaw; GachiLoader AI-skill lure; fake-DHL phishing; ransomware leak-site postings (worldleaks, inc ransom, m3rx, everest, chaos, insomnia) |
| 🟡 **MEDIUM** | 1 | Inc Ransom secondary leak post (fulcrumre.com) |
| 🔵 **INFO** | 1 | SANS ISC Stormcast (no specific threats highlighted) |

## 3. Priority Intelligence Items

### 3.1 LiteLLM CVE-2026-42208 — pre-auth SQLi actively exploited against AI-gateway secrets

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/hackers-are-exploiting-a-critical-litellm-pre-auth-sqli-flaw/)

Sysdig observed targeted exploitation of CVE-2026-42208 beginning roughly 36 hours after disclosure on 24 April. The flaw is in LiteLLM's proxy API-key verification path: an unauthenticated attacker sends a crafted `Authorization: Bearer` header to any LLM API route (e.g. `/chat/completions`) and triggers SQL injection that allows reading and modification of the proxy database. Observed attacks went straight to tables holding API keys, virtual/master keys, and provider credentials for OpenAI, Anthropic, and Bedrock — there were no probes against benign tables, indicating prior knowledge of the schema. The operator switched IP addresses between phases, consistent with evasion. A fix is shipped in **LiteLLM 1.83.7**, replacing string concatenation with parameterised queries; the maintainer-suggested workaround for those unable to upgrade is `disable_error_logs: true` under `general_settings`. The same project was previously the target of a TeamPCP supply-chain attack against its PyPI distribution. Affected: LiteLLM proxy/gateway operators; downstream AI applications relying on it for credential brokerage.

> **SOC Action:** Inventory all internet-exposed LiteLLM instances and confirm version ≥ 1.83.7; treat any pre-1.83.7 instance with public exposure as potentially compromised. Rotate every virtual API key, master key, and provider credential (OpenAI, Anthropic, Bedrock, etc.) stored in those instances. Hunt web/proxy logs for `Authorization: Bearer` values containing SQL-injection markers (`'`, `union`, `select`, `--`) on `/chat/completions` and other LLM API routes. ATT&CK: T1190, T1078.

### 3.2 CVE-2026-42167 in ProFTPD — PoC circulating via Telegram

**Source:** Telegram (channel name redacted) — TLP:AMBER+STRICT; technical detail withheld

A critical vulnerability in ProFTPD tracked as **CVE-2026-42167** was disseminated on a Telegram channel with a proof-of-concept attached. The originating post is classified TLP:AMBER+STRICT and exploitation specifics are not redistributed in this brief. Vendor confirmation, official CVE record, and patch availability could not be corroborated from the Telegram-only source at the time of collection. Affected: organisations exposing ProFTPD instances on the perimeter or to untrusted networks.

> **SOC Action:** Enumerate all ProFTPD instances (any version) and prioritise internet-exposed hosts. Subscribe to the ProFTPD security advisories list and MITRE/NVD for CVE-2026-42167 publication. Until a vendor advisory lands, restrict ProFTPD listeners to allow-listed source ranges, enable verbose authentication logging, and alert on anomalous command sequences (`SITE`, `STAT`, long arguments). Consider compensating controls: pcap of FTP control channel, WAF/IPS signature updates, and short-term migration of high-value transfers to SFTP behind a bastion. ATT&CK: T1190.

### 3.3 VECT 2.0 ransomware — broken nonce handling turns it into a data wiper; TeamPCP partnership

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/broken-vect-20-ransomware-acts-as-a-data-wiper-for-large-files/)

Check Point reverse-engineering of VECT 2.0 (advertised on a recent BreachForums iteration) found that all chunk encryptions reuse the same memory buffer for nonce output, so each new nonce overwrites the previous one. Only the final nonce is written to disk, leaving 75% of any file above the **128 KB** threshold permanently unrecoverable — the lost nonces are not transmitted to the attacker either, so paying the ransom yields nothing. The flaw is present across Windows, Linux, and ESXi variants. VECT operators have publicly partnered with **TeamPCP** (the same actor tied to the LiteLLM, Trivy, and Telnyx supply-chain compromises and an attack on the European Commission), with stated plans to deploy VECT against TeamPCP supply-chain victims. Affected: any organisation hit by a TeamPCP-affiliated supply-chain compromise, plus VECT-affiliate targets generally.

> **SOC Action:** Treat VECT 2.0 incidents as data-destruction events, not negotiable encryption — escalate immediately to disaster-recovery rather than ransom-handling playbooks. Validate offline/immutable backup integrity for VM disks, databases, mailboxes, and document stores (anything above 128 KB). For TeamPCP supply-chain exposure: re-audit recently installed Trivy, LiteLLM, and Telnyx packages against vendor checksums; review CI/CD pipelines for unexpected dependency pulls in the past 30 days. ATT&CK: T1486, T1490 (Inhibit System Recovery), T1070.003.

### 3.4 GachiLoader uses AI-agent "skill" packages to deliver Rhadamanthys

**Source:** [AlienVault OTX](https://otx.alienvault.com/pulse/69f16bcf526f3511990485b6)

Threat actors are abusing the OpenClaw AI-agent skill format as a social-engineering wrapper. The skill file itself contains no malicious code; it instructs the user to download a Windows binary from a fake GitHub repository. Two delivery paths converge on the same payload: a Node.js Single Executable Application and an Electron dropper. The loader (GachiLoader) performs anti-VM, sandbox detection, privilege escalation, and fileless injection of **Rhadamanthys** infostealer. C2 resolution is performed via a **Polygon blockchain smart contract**, complicating takedown and DNS-based blocking. Affected: developers and power-users experimenting with AI agent skill ecosystems; corporate endpoints permitting Node.js SEAs and Electron-packaged installers.

#### Indicators of Compromise

```
Domain:  onfinality[.]pro
Domain:  biotechgroup[.]net
SHA-256: 076ba40e7fbf2910dff87f0c25862a70001d8ad81d23d8beae9fb9b29b603829
SHA-256: 1753d2f90bd4ac6c0c91e76322ae1d0cc8034842a61dc175c7aba3e1aa944c90
SHA-256: 1831db8fe19efbd12997f63bc76da79858f87995b9ebd8a05757670e5e52c1f2
SHA-256: 1f24e75c1e6d6777e970f64ebf18e8bf1dd1dcaab692adf4062c8fad6a6df42c
SHA-256: 539ac28b816ed0ab17879712a460396bd812221b93540590eccdb89c8196db96
SHA-256: 8abec84db36ee18b3299b5fd9406f8d99a5be7dd0a4e93536e39bb406fce97a6
SHA-256: 9fb2ea25254ae53f93e0e13abb59a76a6c1ed512cdf1c1deafafa4d2758117f6
SHA-256: a981ace958944914e9ea697aff6066d6152820aeea5a6a14a9a7fa6aa31c38a6
SHA-256: f583f8307468dc5eacc7be7137dc5c7dbab5fc30ca89b03cf6c67b4de030b05d
```

> **SOC Action:** Block the listed domains and SHA-256s at proxy and EDR. Hunt for child processes of `node.exe` and Electron-shell binaries spawning from `%LOCALAPPDATA%`, `%TEMP%`, or download-folder paths and writing executables. Add detections for unsigned Node.js SEAs and Electron apps installed by non-admin users. Block traffic to Polygon RPC endpoints from non-developer endpoints. ATT&CK: T1566, T1204, T1055, T1027, T1059.001, T1140, T1497.001, T1071.001.

### 3.5 Fake-DHL phishing kit harvests credentials via EmailJS exfiltration

**Source:** [AlienVault OTX](https://otx.alienvault.com/pulse/69f11f15737a6a70e077e9d7)

A consumer-targeted credential-theft operation impersonates DHL with spoofed shipment notifications. The 11-step chain routes victims through a client-side-generated OTP page (no server interaction) to build false trust, then to a DHL-branded credential portal that captures the password alongside IP, device details, browser fingerprint, and geolocation. Exfiltration uses **EmailJS** — a legitimate browser-side mail-sending service — to forward stolen data to an attacker-controlled **Tutamail** address, evading typical egress-data inspection. Victims are then redirected to the legitimate DHL site to suppress suspicion. Affected: consumers and enterprise users with personal-mail-bridged inboxes; brands trusted in shipment workflows.

#### Indicators of Compromise

```
Domain: biotechgroup[.]net
Domain: perfectgoc[.]com
URL:    hxxp[:]//biotechgroup[.]net/
Exfil:  api[.]emailjs[.]com (legitimate; abuse vector)
Mailbox: attacker-controlled @tutamail[.]com
```

> **SOC Action:** Block `biotechgroup[.]net` and `perfectgoc[.]com` at web gateway. Add a rule against POSTs from user browsers to `api.emailjs.com` from unmanaged or non-developer endpoints — this is a recurring exfiltration channel for client-side phishing kits. Brief help-desk staff on DHL-branded OTP lures and remind users that legitimate carriers do not request password-style OTPs on shipment-tracking flows. ATT&CK: T1566, T1589, T1567 (web service exfiltration).

### 3.6 Sustained ransomware leak-site activity — eight extortion postings across six groups

**Sources:** [RansomLook — worldleaks](https://www.ransomlook.io//group/worldleaks), [inc ransom](https://www.ransomlook.io//group/inc%20ransom), [m3rx](https://www.ransomlook.io//group/m3rx), [everest](https://www.ransomlook.io//group/everest), [chaos](https://www.ransomlook.io//group/chaos), [insomnia](https://www.ransomlook.io//group/insomnia)

Eight new victim postings were observed across six ransomware/extortion brands in 24 hours. **Worldleaks** (formerly Hunters International, now operating data-extortion-as-a-service without encryption) listed Mediaworks Kft. **Inc Ransom** posted nbd3pl.com and a secondary post for fulcrumre.com. **M3rx** posted boxtopia.co.uk and osoftec.com (correlated by shared infrastructure). **Everest** listed an Indonesian customs analytics platform — a notable government-data target. **Chaos** RaaS (multi-platform, Windows/Linux/ESXi/NAS) posted cadencepetroleum.com. **Insomnia** posted a US nephrology practice, continuing the group's healthcare focus. Sectors with multiple hits in the same window: **healthcare** (Mediaworks, Nephrology Associates, fulcrumre.com), **property management** (boxtopia, osoftec), and **manufacturing**.

> **SOC Action:** For organisations in healthcare, real estate/property management, and manufacturing supply chains, run focused Tor-egress and dark-web-mention checks for your domain and subsidiaries. Validate that public-facing apps are patched (Everest's documented initial access is exploitation of vulnerable public apps + phishing). Confirm MFA and conditional access on remote-access surfaces (RDP, VPN, Citrix) — credential theft is a documented Everest TTP. ATT&CK: T1566, T1190, T1078, T1486.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Ransomware-aligned actors exploiting critical vulnerabilities for initial access and data exfiltration | LiteLLM CVE-2026-42208 (TeamPCP-linked); ProFTPD CVE-2026-42167 PoC |
| 🟠 **HIGH** | Phishing remains the dominant initial-access vector across diverse sectors | GachiLoader AI-skill lure; fake-DHL credential theft; inc ransom (nbd3pl.com); Everest (Indonesia customs); m3rx (boxtopia.co.uk); chaos (cadencepetroleum.com); insomnia (Nephrology Associates) |
| 🟠 **HIGH** | TeamPCP is consolidating multiple operations: supply-chain compromises, vulnerability exploitation, and partnership with VECT 2.0 ransomware | LiteLLM exploitation; broken VECT 2.0; correlation entry 561 (TeamPCP shared across ProFTPD and LiteLLM reports); correlation entry 562 (TeamPCP shared across both VECT items) |
| 🟡 **MEDIUM** | Healthcare remains the most-correlated victim sector across ransomware groups | Worldleaks (Mediaworks), Insomnia (Nephrology Associates), Inc Ransom (fulcrumre.com), Everest (Indonesia analytics) — sector-correlation entries 568, 571 |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **Qilin** (75 reports, last seen 2026-04-28) — leading RaaS by leak-site volume; not in today's window but dominates 30-day trend
- **The Gentlemen** (58 reports) — active extortion brand
- **Coinbase Cartel** (37 reports) — financially motivated cluster
- **DragonForce** (28 reports) — RaaS group with sustained pace
- **ShinyHunters** (21 reports, last seen 2026-04-27) — data-extortion brand recently linked to Vimeo and Pitney Bowes leaks
- **TeamPCP** (today's correlated actor across LiteLLM, VECT 2.0, ProFTPD; supply-chain track record)

### Malware Families

- **RansomLock / RansomLook** (87 reports combined) — leak-site aggregator entities, not malware proper
- **Qilin ransomware** (10 reports)
- **DragonForce ransomware** (20 reports)
- **Gentlemen ransomware** (9 reports)
- **GachiLoader → Rhadamanthys infostealer** (today's emerging chain; Polygon-blockchain C2)
- **VECT 2.0** (today; effectively a wiper due to nonce-handling flaw)

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| RansomLook | 8 | [ransomlook.io](https://www.ransomlook.io/) | Leak-site aggregation; worldleaks, inc ransom (×2), m3rx (×2), everest, chaos, insomnia |
| AlienVault OTX | 2 | [otx.alienvault.com](https://otx.alienvault.com/) | GachiLoader/Rhadamanthys; fake-DHL phishing kit |
| BleepingComputer | 2 | [bleepingcomputer.com](https://www.bleepingcomputer.com/news/security/hackers-are-exploiting-a-critical-litellm-pre-auth-sqli-flaw/) | LiteLLM CVE-2026-42208 exploitation; VECT 2.0 wiper analysis |
| SANS ISC | 1 | [isc.sans.edu](https://isc.sans.edu/diary/rss/32932) | Daily Stormcast; no specific threats highlighted |
| Telegram (channel name redacted) | 1 | — | ProFTPD CVE-2026-42167 PoC (TLP:AMBER+STRICT) |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Patch all LiteLLM instances to **1.83.7** or apply the `disable_error_logs: true` workaround. Treat any pre-1.83.7 internet-exposed instance as compromised and rotate every virtual key, master key, and provider credential (OpenAI / Anthropic / Bedrock). Trace-back from finding 3.1.
- 🔴 **IMMEDIATE:** Inventory ProFTPD deployments, restrict to allow-listed sources, and watch for vendor advisory on **CVE-2026-42167**. Trace-back from finding 3.2.
- 🟠 **SHORT-TERM:** Audit the past 30 days of CI/CD dependency pulls for Trivy, LiteLLM, and Telnyx (TeamPCP supply-chain track record); validate offline/immutable backups for VM disks, DBs, and mailboxes against the VECT 2.0 wiper scenario. Trace-back from finding 3.3.
- 🟠 **SHORT-TERM:** Push EDR/proxy blocks for the GachiLoader IOC set (10 SHA-256s, `onfinality[.]pro`, `biotechgroup[.]net`) and add a hunting query for Node.js SEAs and Electron-packaged installers writing executables from user-writable paths. Trace-back from finding 3.4.
- 🟡 **AWARENESS:** Brief help-desk and end-users on the fake-DHL OTP lure pattern; add a network rule against client-side `api.emailjs.com` posts from non-developer estates. Trace-back from finding 3.5.
- 🟢 **STRATEGIC:** For healthcare, property-management, and manufacturing-adjacent organisations, fund a focused dark-web/Tor monitoring capability — six distinct extortion brands posted victims in these sectors in a single 24-hour window. Trace-back from finding 3.6.

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 14 reports processed across 1 correlation batch. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
