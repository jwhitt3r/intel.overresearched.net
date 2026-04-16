---
layout: post
title:  "CTI Daily Brief: 2026-04-15 - In-the-wild exploitation of Marimo (CVE-2026-39987) and Nginx UI (CVE-2026-33032); ShinyHunters leaks 13.5M McGraw Hill records"
date:   2026-04-16 20:06:01 +0000
description: "48 reports processed across two correlation batches. Three critical vulnerabilities under active exploitation or requiring urgent customer action (Marimo, Nginx UI, Cisco Webex). ShinyHunters publishes 13.5M McGraw Hill records from Salesforce misconfiguration. UAC-0247 targets Ukrainian hospitals with new AgingFly malware. WordPress EssentialPlugin suite backdoored; ATHR AI-driven vishing platform observed."
category: daily
tags: [cti, daily-brief, shinyhunters, uac-0247, nkabuse, agingfly, cve-2026-39987, cve-2026-33032]
classification: TLP:CLEAR
reporting_period: "2026-04-15"
generated: "2026-04-16"
draft: true
severity: critical
report_count: 48
sources:
  - BleepingComputer
  - RecordedFutures
  - Cisco Talos
  - RansomLock
  - AlienVault
  - Microsoft
  - SANS
  - Sysdig
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-04-15 (24h) | TLP:CLEAR | 2026-04-16 |

## 1. Executive Summary

48 reports were processed across 2 correlation batches, dominated by ransomware leak-site activity (14 RansomLock entries) and active exploitation of two freshly disclosed vulnerabilities. Three critical items anchor the day: attackers are weaponising the Marimo RCE (CVE-2026-39987) to deploy a new NKAbuse variant hosted on Hugging Face Spaces; the Nginx UI auth-bypass (CVE-2026-33032) is confirmed under active exploitation with ~2,600 exposed instances; and Cisco has patched four critical Webex/ISE flaws, with CVE-2026-20184 (Webex SSO impersonation) requiring manual SAML certificate upload. ShinyHunters published 13.5 million McGraw Hill records exfiltrated via a Salesforce misconfiguration, while Ukraine's CERT-UA attributed an espionage campaign against emergency services and hospitals to UAC-0247 using the new AgingFly RAT. AI-driven cybercrime tooling continues to mature: the ATHR platform automates voice-phishing end-to-end using AI voice agents. No CISA KEV additions were observed in the reporting window.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 3 | Marimo RCE/NKAbuse; Cisco Webex SSO impersonation; Nginx UI MCP auth bypass |
| 🟠 **HIGH** | 29 | RansomLock activity (payload, dragonforce, qilin, lamashtu, vect/TeamPCP, shinyhunters); AgingFly/UAC-0247; McGraw Hill breach; ATHR vishing; WordPress EssentialPlugin backdoor; PowMix botnet |
| 🟡 **MEDIUM** | 3 | Cisco Talos Q1 vulnerability pulse; Windows Server 2025 April update failures; McGraw Hill HIBP notification |
| 🔵 **INFO** | 13 | Microsoft advisories (CVE-2026-32223, CVE-2025-64669); Wiz AI-APP launch; CrowdStrike/OpenAI; Sekoia APT28/.NET research |

## 3. Priority Intelligence Items

### 3.1 Marimo CVE-2026-39987 weaponised to deploy NKAbuse via Hugging Face Spaces

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/hackers-exploit-marimo-flaw-to-deploy-nkabuse-malware-from-hugging-face/), [Sysdig via AlienVault](https://www.sysdig.com/blog/cve-2026-39987-update-how-attackers-weaponized-marimo-to-deploy-a-blockchain-botnet-via-huggingface)

Sysdig TRT observed 12 unique source IPs across 10 countries generating 662 exploit events between April 11 and 14 against the Marimo reactive Python notebook RCE (CVE-2026-39987), roughly 9 hours 41 minutes after public disclosure. One operator (38.147.173.172) staged a typosquatted Hugging Face Space named `vsccode-modetx` hosting an `install-linux.sh` dropper and a `kagent` binary — a previously undocumented NKAbuse variant that uses the NKN decentralised peer-to-peer blockchain for C2 and functions as a RAT with shell-command execution. Another operator (159.100.6.251, Germany) attempted 15+ reverse-shell techniques before pivoting to PostgreSQL via leaked `.env` credentials; a Hong Kong operator (160.30.128.96) enumerated all 16 Redis databases. Affected: any Marimo instance exposing `/terminal/ws`; upgrade to 0.23.0 or later. MITRE: T1190, T1078, T1083, T1105, T1071.004, T1573.002.

#### Indicators of Compromise

```
C2 IPs: 38.147.173[.]172, 159.100.6[.]251, 92.208.115[.]60, 111.90.145[.]139,
        45.147.97[.]11, 60.249.14[.]39, 120.227.46[.]184, 160.30.128[.]96,
        185.187.207[.]193, 185.225.17[.]176
DNS:    bskke4[.]dnslog[.]cn
SHA256: 25e4b2c4bb37f125b693a9c57b0e743eab2a3d98234f7519cd389e788252fd13
SHA256: 27c62a041cc3c88df60dfceb50aa5f2217e1ac2ef9e796d7369e9e1be52ebb64
SHA256: f2960805f89990cb28898e892bbdc5a2f86b6089c68f4ab7f2f5e456a8d0c21d
Hosting: hxxps[:]//huggingface[.]co/spaces/<typosquatted-space>/vsccode-modetx
```

> **SOC Action:** Block egress to the Hugging Face Space slug above at the proxy. Upgrade all Marimo deployments to ≥0.23.0; where upgrade is blocked, firewall `/terminal/ws` externally. Query EDR for `curl|wget` fetching `install-linux.sh` followed by systemd/cron persistence for a binary named `kagent`. Hunt for outbound traffic to `nkn://` or NKN seed nodes from notebook/Python workloads. Rotate all credentials resident in `.env`, `docker-compose.yml`, and environment variables on any potentially-exposed Marimo host.

### 3.2 Nginx UI auth-bypass (CVE-2026-33032) under active in-the-wild exploitation

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/critical-nginx-ui-auth-bypass-flaw-now-actively-exploited-in-the-wild/)

Recorded Future's CVE Landscape report confirms active exploitation of CVE-2026-33032 in Nginx UI with Model Context Protocol (MCP) support. The `/mcp_message` endpoint is unprotected, allowing unauthenticated attackers to establish an SSE connection, open an MCP session, and invoke all 12 MCP tools — including 7 destructive ones — to read, modify, or delete nginx configuration files and trigger automatic reloads, achieving complete nginx service takeover. Pluto Security AI identified ~2,600 publicly exposed instances (concentrated in China, US, Indonesia, Germany, Hong Kong). Patched in nginx-ui 2.3.4 (March 15); current secure release is 2.3.6. MITRE: T1190, T1204.

> **SOC Action:** Inventory all nginx-ui deployments via Shodan/internal scanning (`nginx-ui` favicon hash, port 9000/9001 common). Upgrade immediately to ≥2.3.6. Block external network access to `/mcp_message` at WAF/reverse proxy. Review nginx configuration file integrity against a known-good baseline; any unexplained `server` blocks, new `location` directives, or writes to `/etc/nginx/conf.d/` in the last 30 days warrant investigation. Restrict nginx-ui management interface to bastion/VPN access only.

### 3.3 Cisco Webex (CVE-2026-20184) and ISE critical patches — customer action required

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/cisco-says-critical-webex-services-flaw-requires-customer-action/)

Cisco disclosed four critical vulnerabilities. CVE-2026-20184 is an improper certificate validation flaw in the Webex Services SSO integration with Control Hub, allowing unauthenticated remote attackers to impersonate any user via a crafted token. While Cisco has patched the cloud service, customers using SSO **must upload a new SAML certificate** for their identity provider to Control Hub to avoid service interruption. Three further critical flaws (CVE-2026-20147, CVE-2026-20180, CVE-2026-20186) in the Identity Services Engine (ISE) permit arbitrary command execution on the underlying OS but require administrative credentials. Cisco PSIRT reports no observed in-the-wild exploitation. MITRE: T1078, T1136, T1190.

> **SOC Action:** Identity/platform teams must upload a refreshed SAML IdP certificate to Webex Control Hub this week to preserve SSO availability. For ISE, prioritise patching admin-accessible appliances and rotate admin credentials used on those systems. Enable Webex audit-log forwarding and review logins in the 72 hours prior to patch for tokens signed by unexpected IdP certificate thumbprints.

### 3.4 ShinyHunters leak 13.5M McGraw Hill records via Salesforce misconfiguration

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/data-breach-at-edtech-giant-mcgraw-hill-affects-135-million-accounts/), [HaveIBeenPwned](https://haveibeenpwned.com/Breach/McGrawHill)

ShinyHunters publicly released over 100 GB of data stolen from McGraw Hill's Salesforce environment after the company declined to pay ransom. HIBP confirmed 13,500,136 unique email addresses plus names, physical addresses, and phone numbers. McGraw Hill attributes the compromise to a Salesforce platform misconfiguration that has affected multiple organisations, not to a compromise of core systems. ShinyHunters is simultaneously leaking Rockstar Games data stolen from a Snowflake environment and was linked to the European Commission, Infinite Campus, Hims & Hers, Telus Digital, and Match Group breaches earlier in 2026. Correlates at 0.90 confidence with the 2.5M record leak from Alert 360 Opco (alert360.com) posted to the same leak site today.

> **SOC Action:** If your organisation uses Salesforce Experience Cloud / public-facing Salesforce sites, audit guest-user permissions (Lightning Platform guest profile, site page public access, guest sharing rules) against Salesforce's hardening guidance. Expect spear-phishing against the 13.5M affected users referencing McGraw Hill course enrolment; deploy inbound mail rules flagging "McGraw" + password-reset lure patterns. If your customer base overlaps, push a breach notification and enforce MFA/password rotation on shared identities.

### 3.5 UAC-0247 / AgingFly espionage against Ukrainian hospitals and emergency services

**Source:** [Recorded Future](https://therecord.media/aging-fly-espionage-campaign-targets-ukraine-emergency-services), [BleepingComputer](https://www.bleepingcomputer.com/news/security/new-agingfly-malware-used-in-attacks-on-ukraine-govt-hospitals/)

CERT-UA tracks UAC-0247 running phishing campaigns against municipal authorities, clinical hospitals, and emergency medical services with humanitarian-aid-themed lures. Archives deliver AgingFly (RAT — remote commands, file download, screen capture, keystroke logging), SilentLoop (executes commands and retrieves C2 address via Telegram channel), ChromeElevator (browser credential theft), and ZapixDesk (WhatsApp account exploitation), with XMRig cryptojacking observed in at least one incident. Some lures used AI-generated fake organisational websites or XSS chains on legitimate sites. CERT-UA warned Defence Forces members have been targeted with Signal-delivered "drone operator software updates" that sideload AgingFly. A separate Reuters-reported campaign attributed to APT28 (Fancy Bear / BlueDelta / Forest Blizzard) compromised 170+ email accounts of Ukrainian prosecutors and Balkan/NATO targets (attribution by Ctrl-Alt-Intel). MITRE: T1566, T1204, T1078, T1071.001.

> **SOC Action:** Healthcare and government SOCs in NATO/EU: alert on HTA file execution from user temp directories, AES-CBC WebSocket traffic to non-corporate endpoints, and outbound Telegram bot API traffic (`api.telegram[.]org`) from non-user workstations. Block execution of unsigned `.hta` via ASR rule "Block all Office applications from creating child processes". Validate Signal/third-party messenger file policies for Defence-adjacent and humanitarian-sector users.

### 3.6 WordPress EssentialPlugin suite backdoored — 30+ plugins, hundreds of thousands of installs

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/wordpress-plugin-suite-hacked-to-push-malware-to-thousands-of-sites/)

Austin Ginder (Anchor Hosting) and PatchStack identified a supply-chain backdoor planted in August 2025 — immediately after a six-figure acquisition of the EssentialPlugin project — affecting 30+ plugins across the catalogue. The dormant backdoor activated this week, fetching `wp-comments-posts.php` (note the extra `s` vs legitimate `wp-comments-post.php`) and injecting malware into `wp-config.php`. The injected code uses Ethereum-based C2 address resolution for evasion and serves spam links, redirects, and fake pages only to Googlebot. Activation gate: a malicious serialized response from `analytics.essentialplugin[.]com`. WordPress.org has closed the plugins and pushed forced updates, but `wp-config.php` is **not** cleaned automatically. MITRE: T1071, T1496.

> **SOC Action:** Any site running an EssentialPlugin product since August 2025 should (1) pull a fresh copy of `wp-config.php` and diff against VCS or a known-good backup, (2) search the webroot recursively for `wp-comments-posts.php` and any unexplained PHP files containing `eth_call`, `0x` hex strings >32 bytes, or base64-encoded `eval`, (3) block outbound DNS and HTTPS to `analytics.essentialplugin[.]com` and any Ethereum RPC endpoints (`mainnet.infura[.]io`, `cloudflare-eth[.]com`) from web servers, and (4) rotate any database and admin credentials stored in `wp-config.php`.

### 3.7 ATHR — AI-driven vishing-as-a-service platform

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/new-athr-vishing-platform-uses-ai-voice-agents-for-automated-attacks/)

Abnormal identified ATHR, a cybercrime platform advertised on underground forums at $4,000 + 10% commission that automates the full telephone-oriented attack delivery (TOAD) chain against Google, Microsoft, Coinbase, Binance, Gemini, Crypto.com, Yahoo, and AOL. The lure is a generic security-alert email with a phone number that routes (Asterisk + WebRTC) to an AI voice agent driven by persona-tunable prompts mimicking support staff; the objective is harvesting the 6-digit MFA/recovery code. A human-operator fallback and real-time dashboard are included. MITRE: T1566, T1189.

> **SOC Action:** Brief helpdesk and finance staff that "security alert → call this number" lures now terminate in AI agents indistinguishable from humans; no MFA/recovery code should ever be read over the phone regardless of caller identity. Hunt mail gateway telemetry for short-lived bursts of identical "account alert" templates from disparate senders containing a single callback number. Move to phishing-resistant MFA (passkeys, hardware keys) for privileged accounts and high-value cryptocurrency platform users.

### 3.8 DPRK "laptop farm" operators sentenced — intelligence context

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/us-nationals-behind-north-korean-it-worker-laptop-farm-sent-to-prison/), [Recorded Future](https://therecord.media/new-jersey-men-sentenced-north-korean-laptop-farms)

DoJ announced 108-month (Kejia Wang) and 92-month (Zhenxing Wang) sentences for running a US-based laptop farm that placed DPRK IT workers into 100+ US firms, including Fortune 500s, using 80+ stolen identities. The operation generated $5M+ for DPRK and $3M in damages (2021–Oct 2024). Nine co-defendants remain at large; State Department offers up to $5M for information. This confirms the operational tempo FBI has flagged since 2023 and underlines ongoing hiring-side exposure.

> **SOC Action:** Coordinate with HR/Talent: require in-person or verified-video identity checks for remote IT hires, validate that residential mailing addresses for company laptops match the worker's claimed residence, and monitor for unusual VPN / residential-proxy patterns on newly-issued endpoints. Review the FBI/OFAC DPRK IT worker indicators for engineering and help-desk hires over the last 24 months.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Exploitation of software supply chain vulnerabilities | Cisco Talos Q1 vulnerability pulse; Marimo/NKAbuse via HuggingFace (CVE-2026-39987) |
| 🔴 **CRITICAL** | Targeting of critical infrastructure and government sectors with sophisticated malware | AgingFly campaign vs. Ukraine govt/hospitals; McGraw Hill breach (13.5M) |
| 🟠 **HIGH** | Increased exploitation of vulnerabilities in widely used software and services | Nginx UI auth bypass (CVE-2026-33032) under active exploitation; Cisco Webex/ISE critical patches |
| 🟠 **HIGH** | Increased use of AI in cybercrime operations | ATHR AI voice-agent vishing platform; Google Gemini AI deployed for malicious-ad detection |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **qilin** (55 reports) — RaaS operator; Clearwater Marine Aquarium leak published today
- **The Gentlemen / the gentlemen** (48 + 21 reports) — ransomware group, Tox1-linked infrastructure
- **nightspire** (37 reports) — ransomware leak activity
- **TeamPCP** (32 reports) — LiteLLM/Trivy campaign (vect), S&P Global, Guesty targeting
- **DragonForce / dragonforce** (27 + 25 reports) — RaaS; today listed Empower Group
- **Coinbase Cartel** (26 reports)
- **ShinyHunters** (2 reports today) — McGraw Hill 13.5M + Alert 360 2.5M leaks
- **UAC-0247** (2 reports today) — AgingFly operator targeting Ukraine
- **APT28 / Fancy Bear** — 170+ Ukrainian prosecutor email accounts compromised
- **DPRK government** — IT worker laptop-farm scheme

### Malware Families

- **RansomLock** (39 reports) — generic leak-site tagging for payload, dragonforce, qilin, lamashtu, vect, shinyhunters entries
- **ransomware / Ransomware** (28 + 11 reports)
- **dragonforce ransomware / DragonForce ransomware** (26 + 9 reports)
- **Akira ransomware** (18 reports)
- **RaaS** (15 reports)
- **Tox1** (10 reports) — common infrastructure tag for several RaaS crews
- **PLAY ransomware** (8 reports)
- **Gentlemen ransomware** (7 reports)
- **NKAbuse** (2 reports today) — blockchain-C2 RAT via Marimo
- **AgingFly** (2 reports today) — UAC-0247 RAT; paired with SilentLoop, ChromeElevator, ZapixDesk
- **PowMix** (1 report today) — Czech workforce botnet; ZipLine-overlap TTPs; Heroku C2

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| RansomLock | 14 | [link](https://www.ransomlook.io/) | Ransomware leak-site aggregation (payload, dragonforce, qilin, lamashtu, vect, shinyhunters, leaknet, payoutsking) |
| BleepingComputer | 11 | [link](https://www.bleepingcomputer.com/news/security/critical-nginx-ui-auth-bypass-flaw-now-actively-exploited-in-the-wild/) | Primary coverage of Nginx UI, Cisco Webex, Marimo, McGraw Hill, WordPress EssentialPlugin, ATHR, DPRK laptop farms |
| RecordedFutures | 4 | [link](https://therecord.media/aging-fly-espionage-campaign-targets-ukraine-emergency-services) | AgingFly/UAC-0247, cargo-theft campaign, DPRK laptop farm sentences, tracking-opt-out research |
| Cisco Talos | 3 | [link](https://blog.talosintelligence.com/powmix-botnet-targets-czech-workforce/) | PowMix botnet; Q1 vulnerability pulse; visual storytelling feature |
| Unknown | 2 | — | Telegram (channel name redacted) — Gunra ransomware mention; VMkatz tool mention |
| SANS | 2 | [link](https://isc.sans.edu/diary/rss/32886) | Compromised DVR guest diary; daily Stormcast |
| Microsoft | 2 | [link](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-32223) | USB Print EoP (CVE-2026-32223); WAC EoP (CVE-2025-64669) |
| AlienVault | 2 | [link](https://www.sysdig.com/blog/cve-2026-39987-update-how-attackers-weaponized-marimo-to-deploy-a-blockchain-botnet-via-huggingface) | Sysdig TRT Marimo deep-dive; cargo-theft actor post-compromise playbook |
| Schneier | 2 | [link](https://www.schneier.com/) | Human trust of AI agents; Constantinople defence-in-depth essay |
| Sekoia | 1 | [link](https://blog.sekoia.io/from-apt28-to-repythonnet-automating-net-malware-analysis/) | APT28 .NET malware analysis tooling |
| Wiz | 1 | [link](https://www.wiz.io/blog/securing-ai-application-from-inception-to-deployment) | AI-APP launch |
| Datadog | 1 | [link](https://securitylabs.datadoghq.com/articles/dependency-cooldowns/) | Dependency cooldowns post-Axios |
| HaveIBeenPwned | 1 | [link](https://haveibeenpwned.com/Breach/McGrawHill) | McGraw Hill 13.5M breach notification |
| Sysdig | 1 | [link](https://webflow.sysdig.com/blog/sysdig-2026-cloud-native-security-and-usage-report) | 2026 Cloud-Native Security and Usage Report |
| Crowdstrike | 1 | [link](https://www.crowdstrike.com/en-us/blog/frontier-ai-for-defenders-crowdstrike-and-openai-tac/) | OpenAI TAC collaboration |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Upgrade Marimo to ≥0.23.0 and Nginx UI to ≥2.3.6, or firewall `/terminal/ws` and `/mcp_message` respectively. Both flaws are under active exploitation; the Marimo campaign is deploying an NKAbuse variant with blockchain C2 and lateral movement to Postgres/Redis via `.env` credentials (see §3.1, §3.2).
- 🔴 **IMMEDIATE:** Identity/platform teams using Cisco Webex SSO must upload a new SAML IdP certificate to Control Hub to avoid service interruption, and patch Cisco ISE against CVE-2026-20147/20180/20186 before admin-credential loss becomes exploitation (see §3.3).
- 🟠 **SHORT-TERM:** Audit Salesforce Experience Cloud / public-site guest-user profiles and sharing rules given the McGraw Hill (13.5M) and Alert 360 (2.5M) ShinyHunters leaks both stemming from Salesforce misconfigurations today (see §3.4).
- 🟠 **SHORT-TERM:** Any site or customer running EssentialPlugin WordPress plugins since August 2025 must manually review `wp-config.php`, hunt for `wp-comments-posts.php`, and block `analytics.essentialplugin[.]com` — forced WP.org updates do not clean the injected config (see §3.6).
- 🟡 **AWARENESS:** Brief helpdesk, finance, and crypto-exchange-heavy user populations that AI voice-agent vishing (ATHR) is now productised at $4K a seat; no MFA code should ever be shared by phone, and phishing-resistant MFA should be enforced on privileged accounts (see §3.7).
- 🟢 **STRATEGIC:** Align HR/Talent with security on DPRK IT-worker detection (identity verification, laptop-shipping-address validation, residential-proxy egress) following this week's US sentencing and the $5M State Department reward signalling continued enforcement (see §3.8). Revisit supply-chain controls on third-party dependencies and acquired open-source projects in light of the EssentialPlugin and npm/Axios patterns highlighted by Datadog and Cisco Talos.

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 48 reports processed across 2 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
