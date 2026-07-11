---
layout: post
title:  "CTI Daily Brief: 2026-07-10 - GhostLock Linux Root Exploit, U-Boot Firmware Flaws, ClamAV Critical Cluster, Qilin/DragonForce Ransomware Wave"
date:   2026-07-11 20:15:00 +0000
description: "48 reports processed across 8 sources. GhostLock (CVE-2026-43499) delivers 15-year-old Linux kernel root; six U-Boot bootloader flaws enable stealthy firmware attacks; ClamAV and NATS Server hit by critical CVE clusters; Qilin, DragonForce, and The Gentlemen accelerate ransomware operations; ShinyHunters leaks Glendale Community College data."
category: daily
tags: [cti, daily-brief, qilin, dragonforce, the-gentlemen, shinyhunters, cve-2026-43499, ghostlock, u-boot, clamav, nats-server]
classification: TLP:CLEAR
reporting_period: "2026-07-10"
generated: "2026-07-11"
draft: true
severity: critical
report_count: 48
sources:
  - Microsoft
  - RansomLook
  - BleepingComputer
  - Schneier
  - SANS
  - HaveIBeenPwned
  - Wired Security
  - Unit42
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-07-10 (24h) | TLP:CLEAR | 2026-07-11 |

## 1. Executive Summary

The pipeline processed 48 reports across 8 sources during the 24-hour window ending 2026-07-11. Seven critical items dominated the day, led by GhostLock (CVE-2026-43499) — a 15-year-old use-after-free in the Linux kernel that Nebula Security's AI-driven VEGA tool surfaced with a 97 percent reliable public exploit granting root from any local account. Bootloader integrity took a second hit as researchers disclosed six new U-Boot flaws that enable stealthy firmware persistence, and a 29-year-old Squid proxy bug — dubbed Squidbleed — resurfaced as an HTTP request leak. Microsoft's advisory feed carried a large ClamAV cluster (7Zip, PESpin, PE, FSG file-format OOB corruption) and a NATS Server authorization-bypass cluster affecting subscribe filters, MQTT queues, and the Route API. Ransomware operations remained brisk: Qilin, DragonForce, and The Gentlemen (Storm-2697, tracked by Unit 42 as an ArmCorp affiliate of Spikey Scorpius/Qilin) posted fresh victims across agriculture, retail, hardware hire, and legal services, with The Gentlemen's 90 percent affiliate payout driving a 6x year-over-year victim increase. No CISA KEV additions were captured in the collection window.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 7 | GhostLock Linux kernel LPE; U-Boot firmware flaws; Squidbleed; ClamAV 7Zip/PESpin OOB; Vim PHP omni-completion RCE; Kubernetes namespace bypass |
| 🟠 **HIGH** | 26 | Qilin/DragonForce/cmd-organization ransomware posts; NATS Server auth-bypass cluster; ClamAV FSG/PE processing; Ghostcommit AI prompt injection; Australia CMS campaign; ShinyHunters Glendale CC breach |
| 🟡 **MEDIUM** | 13 | Mistune XSS/quadratic parsing chain; DBI Perl heap overflow; OpenSSH GSSAPI behaviour; setuptools MANIFEST bypass |
| 🟢 **LOW** | 2 | Wireshark 4.6.7 release; Qilin — Century Equities post |

## 3. Priority Intelligence Items

### 3.1 GhostLock (CVE-2026-43499) — 15-Year-Old Linux Kernel Root Exploit Now Public

**Source:** [Wired Security](https://www.wired.com/story/security-news-this-week-ai-found-a-root-bug-in-linux-that-everyone-missed-for-15-years/)

Nebula Security published working exploit code for GhostLock, a use-after-free bug that has shipped by default in essentially every mainstream Linux distribution since 2011. The flaw was surfaced by Nebula's AI-driven bug-hunting tool VEGA and requires no special permissions or network access — any logged-in local user can escalate to root, and the exploit escaped container sandboxes at 97 percent reliability in testing. The submission earned a $92,337 payout through Google's kernelCTF program. The kernel fix landed in April, but downstream patch availability is uneven: Ubuntu as of early July still listed 24.04, 22.04, and 20.04 LTS as vulnerable or in-progress. Defenders should confirm the fixed package rather than assume a distribution update has closed the gap. MITRE: T1068 (Exploitation for Privilege Escalation).

> **SOC Action:** Inventory Linux hosts (endpoints, servers, container hosts, CI runners) and verify kernel package versions against distribution security tracker entries for CVE-2026-43499. Prioritise multi-tenant systems, container hosts, and any workload exposing shell access to untrusted users. Deploy EDR detections for anomalous root transitions from non-root parent processes, and monitor kernel audit logs (`type=SYSCALL` with `auid` mismatches on `euid=0`). Container escape monitoring should flag processes in a container namespace acquiring host UID 0.

### 3.2 Six New U-Boot Bootloader Flaws Enable Stealthy Firmware Persistence

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/new-u-boot-flaws-could-enable-stealthy-firmware-attacks/)

Researchers disclosed six vulnerabilities in the U-Boot bootloader — used across embedded devices, network appliances, IoT platforms, and single-board computers — that allow arbitrary code execution at the device boot stage. Successful exploitation lets attackers bypass secure-boot and platform-integrity checks, install pre-OS malware, and maintain persistence that survives OS reinstallation. MITRE: T1106 (Boot or Logon Autostart Execution), T1068 (Privilege Escalation), T1051 (Remote Services).

> **SOC Action:** Ask asset owners for a U-Boot inventory across network gear, industrial systems, and embedded fleet devices. Track vendor advisories (particularly for edge routers, storage controllers, and ARM-based appliances) and require signed U-Boot images with hardware root-of-trust verification before deploying firmware updates. Where remote firmware attestation is available, baseline current measurements now so post-compromise drift is detectable.

### 3.3 Squidbleed — 29-Year-Old Squid Proxy HTTP Request Leak

**Source:** [Schneier on Security](https://www.schneier.com/)

Schneier flagged a critical Squid proxy vulnerability, dubbed "Squidbleed," that has been present in the codebase for 29 years and can leak HTTP requests via a buffer overflow condition in HTTP request handling. Given Squid's prevalence in enterprise egress proxies, ISP caching layers, and library/school filtering deployments, disclosed HTTP request content can include internal URLs, session tokens, and application secrets transiting the proxy. MITRE: T1071.001 (Application Layer Protocol: Web Protocols).

> **SOC Action:** Identify Squid deployments (`squid -v` on suspected hosts, or firewall rules terminating on port 3128/8080). Patch to the vendor-supplied fixed release once available; in the interim, restrict Squid management interfaces to loopback, front the proxy with a WAF that inspects for the malformed request pattern, and rotate any long-lived tokens or credentials that traverse the proxy. Sweep proxy access logs for anomalous inbound HTTP methods and oversize header/URI combinations.

### 3.4 ClamAV Critical Cluster — Multiple File-Format OOB Corruption CVEs

**Source:** [Microsoft Security Response Center](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-20215)

Microsoft's advisory feed published a batch of ClamAV vulnerabilities in a single day. Two critical items — CVE-2026-20215 (7Zip) and CVE-2026-20217 (PESpin) — enable remote code execution via out-of-bounds memory corruption when parsing crafted archive files. High-severity siblings include CVE-2026-20213 (PE), CVE-2026-20214 (FSG), CVE-2026-20216 (InstallShield resource exhaustion), CVE-2026-20244 (DMG DoS), and CVE-2026-20243 (ALZ DoS). Because ClamAV frequently scans inbound mail attachments and file-server uploads with elevated privileges, a malicious file delivered through those pipelines can trigger the flaw before any user opens it. MITRE: T1203 (Exploitation for Client Execution), T1496 (Resource Hijacking).

> **SOC Action:** Query patch-management for `clamav`, `clamd`, and `clamav-daemon` versions across mail gateways, file servers, and CI artifact scanners. Apply vendor updates as they land and, until patched, disable scanning of the affected file formats via `clamd.conf` (`ScanArchive`, `ScanPE`) on internet-facing scanners. Confine `clamd` under systemd hardening (`ProtectSystem=strict`, `NoNewPrivileges=yes`) so any RCE lands in a constrained context.

### 3.5 NATS Server — Multi-CVE Authorization Bypass and Crash Cluster

**Source:** [Microsoft Security Response Center](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-58252)

Six NATS Server CVEs published to MSRC on the same day form a coherent hardening batch: CVE-2026-58252 (subscribe authorization bypass via wildcard-overlap), CVE-2026-58253 (Route API auth bypass), CVE-2026-58251 (queue subscribe authorization bypass), CVE-2026-58209 (MQTT retained and QoS replay bypass of subscribe deny filters), CVE-2026-58208 (MQTT-over-WebSocket path crash on WebSocket-only JetStream servers before MQTT is enabled), and CVE-2026-58207 (remote crash via integer overflow in Connz pagination). Collectively they permit unauthorised access to subject streams, replay of retained MQTT messages, and remote crash of unauthenticated attackers. NATS is widely used in microservice meshes and IoT backbones, so subject-level authorisation bypass has direct multi-tenant blast-radius implications. Correlation trend #530 explicitly links this cluster with GhostLock as an "exploitation of vulnerabilities in software and protocols leading to potential privilege escalation" pattern.

> **SOC Action:** Upgrade NATS Server to the fixed release (see vendor advisory `NATS-Server-2026-58252` and siblings). Audit `authorization` blocks for wildcard overlap in subject patterns; where feasible switch to explicit deny-lists and per-account isolation. Front public NATS deployments (particularly WebSocket JetStream) with a rate-limited reverse proxy and reject unauthenticated INFO or Connz probes at the edge.

### 3.6 Ransomware Wave — Qilin, DragonForce, and The Gentlemen Accelerate

**Sources:** [Unit 42 — The Gentlemen](https://unit42.paloaltonetworks.com/the-gentlemen-ransomware/), [RansomLook — Qilin](https://www.ransomlook.io/group/qilin), [RansomLook — DragonForce](https://www.ransomlook.io/group/dragonforce)

Qilin posted four fresh victims to its leak site (Retelit SpA PIVA, Carolina Agri-Power, Allied Plumbing & Heating, Century Equities), DragonForce posted two (Access Equipment Hire and The Schuett Companies), and cmd organization added Golden Star Resources. Unit 42 published a full profile of The Gentlemen (Storm-2697), assessing them as a former ArmCorp affiliate of Qilin (Spikey Scorpius) that morphed into an independent RaaS around September 2025 with an unprecedented 90 percent affiliate payout. Unit 42 counted 580 victims across 77 countries through 7 July 2026 — a >6x increase versus H2 2025 — with 103 in manufacturing. Reported initial-access techniques include edge-device (firewall/VPN) exploitation, credential brute-force, IAB collaboration, and a Go-based backdoor named GentleKiller with a bespoke EDR-killer framework and a suspected zero-day for defence evasion. Correlation batch 224 groups the Qilin posts at 0.95 confidence on shared actor and the DragonForce pair at 0.90 confidence on shared retail/government/logistics/manufacturing sectors. MITRE: T1566 (Phishing), T1071.001 (Web Protocols), T1190 (Public-Facing Application Exploitation).

> **SOC Action:** Patch and harden edge devices (SSL VPN, firewall management planes, on-prem file share gateways) — these remain the primary Qilin/Gentlemen ingress. Sweep EDR telemetry for known `GentleKiller` service-installation patterns, Go-compiled binaries dropping into `%ProgramData%` or `/var/tmp`, and Tox/Tox1 client artifacts on servers. Enforce credential hygiene (rotate all VPN and admin credentials that predate August 2025, enforce phishing-resistant MFA on edge devices), and monitor BreachForums and darknet IAB listings referencing your organisation's ASN or domains.

### 3.7 ShinyHunters "Pay or Leak" — Glendale Community College Breach (793,925 Accounts)

**Source:** [Have I Been Pwned](https://haveibeenpwned.com/Breach/GlendaleCommunityCollege)

Have I Been Pwned added a Glendale Community College breach containing 793,925 unique email addresses plus names, physical addresses, phone numbers, dates of birth, Social Security numbers, government-issued IDs, genders, and academic records. Attribution points to ShinyHunters, which continues its "pay or leak" extortion cadence originally observed on the Salesforce/Salesloft ecosystem earlier in the year. The breach occurred in June 2026; data was published online after non-payment. Affected individuals face compounded downstream fraud risk given the SSN and government-ID exposure. MITRE: T1566 (Phishing) as ShinyHunters' historic initial-access vector.

> **SOC Action:** If your organisation has any HR pipeline, credit check, or student loan integration with Glendale Community College, treat any matching identities as high-fraud-risk for the next 12 months. Monitor for credential-stuffing waves against corporate SSO using the leaked email addresses (particularly on shared-password patterns from `.edu` accounts). If your organisation is a Salesforce/Salesloft tenant, revisit the ShinyHunters extortion IOCs published in Q2 2026 and confirm the previously advised token rotations were completed.

### 3.8 Ghostcommit — Prompt Injection Hidden in PNG Bypasses AI Code Reviewers

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/ghostcommit-hides-prompt-injection-in-images-to-fool-ai-agents-steal-secrets/)

Researchers demonstrated "Ghostcommit," a technique that embeds prompt-injection payloads inside PNG images. AI code-review tools CodeRabbit and Bugbot never open image files, so the payload passes review; a downstream coding agent then reads the payload, opens `.env`, and writes the resulting secrets into the codebase as a list of numeric constants. This is the first credible public example of image-borne prompt injection weaponised against automated code-review agents at commercial scale. MITRE: T1566 (Phishing), TA0002 (Execution).

> **SOC Action:** In any AI-assisted development pipeline, treat committed images with the same distrust as executables — scan PNG/JPEG/SVG metadata for embedded text, reject images in PRs that touch `.env`, secrets managers, or CI config, and require human review of any AI-agent-authored commit that touches environment or credential files. Rotate any secrets that could have been exposed by a coding agent with repo-write access.

### 3.9 Australia (ACSC) Warns of Global Campaign Against Vulnerable CMS Platforms

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/australia-warns-of-global-campaign-targeting-vulnerable-cms-platforms/)

The Australian Cyber Security Centre issued an alert on a global exploitation campaign targeting known vulnerabilities in content management systems and their plugins. Attackers are chaining CMS plugin flaws to gain unauthorised access, drop webshells, and pivot to hosted assets. Correlation trend #531 groups this campaign with Qilin's Carolina Agri-Power posting and cmd organization's Golden Star Resources posting on shared T1566 (Phishing) + T1071.001 (Web Protocols) TTPs, suggesting the CMS beachheads are being fed into ransomware affiliate pipelines. MITRE: T1190 (Public-Facing Application Exploitation), T1071.001 (Web Protocols).

> **SOC Action:** Enumerate public-facing CMS (WordPress, Drupal, Joomla, Adobe Experience Manager) and plugin inventories, verify all plugins are at current versions, and remove unmaintained plugins entirely. Query WAF logs for the top exploitation signatures published in the ACSC advisory (`admin-ajax.php` abuse patterns, `?rest_route=` bypass strings, uploader endpoints receiving PHP content). Sweep webroots for newly created `.php` files with timestamps in the last 30 days.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|--------------------|
| 🔴 CRITICAL | Exploitation of vulnerabilities in software and protocols leading to privilege escalation | GhostLock (CVE-2026-43499) Linux kernel LPE; CVE-2026-58252 NATS Server subscribe authz bypass |
| 🔴 CRITICAL | Increased exploitation of critical vulnerabilities across different platforms | U-Boot bootloader flaws; CVE-2026-47291 Windows HTTP.sys integer overflow RCE |
| 🟠 HIGH | Increased ransomware activity targeting multiple sectors with sophisticated TTPs | Retelit SpA (Qilin); Carolina Agri-Power (Qilin); Access Equipment Hire (DragonForce) |
| 🟠 HIGH | Rise in ransomware activity with innovative affiliate models | The Gentlemen (Storm-2697) 90% affiliate payout; 6x YoY victim increase per Unit 42 |
| 🟡 MEDIUM | Phishing remains a prevalent TTP across various malicious campaigns | Carolina Agri-Power (Qilin); The Schuett Companies (DragonForce); Glendale Community College (ShinyHunters) |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **The Gentlemen** (109 reports) — Storm-2697 RaaS; former Qilin/ArmCorp affiliate turned independent operator with 90 percent payout
- **Qilin** (75 reports) — Spikey Scorpius; RaaS with active posting cadence across agriculture, retail, and industrial sectors
- **Deadlock** (66 reports) — Persistent double-extortion group; consistent leak-site activity through the quarter
- **Lockbit5** (36 reports) — Continuing expansion into education and engineering targets per prior batch trends
- **DragonForce** (24 reports) — Hacktivist-origin RaaS with customisable affiliate portal and shared leak infrastructure
- **Akira** (23 reports) — Tracked by Unit 42 as Howling Scorpius; sustained cross-sector targeting
- **ShinyHunters** (19+17 aliases) — "Pay or leak" extortion; latest victim Glendale Community College (793,925 accounts)
- **Nova** (17 reports) — Emerging leak-site presence
- **Stormous** (16 reports) — Continuing operations

### Malware Families

- **RansomLook** (155 reports) — Aggregated leak-site tracking hits
- **Tox1** (74 reports) — Encrypted C2 channel used by Qilin and The Gentlemen affiliates
- **Other1 / Tox** (46 / 45 reports) — Ancillary anonymised communication channels
- **Akira ransomware** (12 reports) — Howling Scorpius payload family
- **Deadlock** (12 reports) — Custom ransomware family associated with the same-named actor
- **The Gentlemen Ransomware / GentleKiller** (12+10 reports) — C- and Go-based cross-platform encryptors plus custom EDR-killer
- **Qilin ransomware** (11 reports) — Spikey Scorpius payload family
- **Anubis ransomware** (11 reports) — Continuing but slowing cadence
- **Storm-2697** (referenced) — Microsoft alias for The Gentlemen operator cluster

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| Microsoft | 33 | [MSRC Update Guide](https://msrc.microsoft.com/update-guide) | Dominated by NATS Server, ClamAV, Mistune, and DBI (Perl) CVE clusters |
| RansomLook | 7 | [RansomLook](https://www.ransomlook.io/) | Qilin, DragonForce, cmd organization leak-site posts |
| BleepingComputer | 3 | [U-Boot flaws coverage](https://www.bleepingcomputer.com/news/security/new-u-boot-flaws-could-enable-stealthy-firmware-attacks/) | U-Boot, Ghostcommit, ACSC CMS advisory |
| Schneier | 1 | [Schneier on Security](https://www.schneier.com/) | Squidbleed disclosure |
| SANS | 1 | [Wireshark 4.6.7 diary](https://isc.sans.edu/diary/rss/33146) | Wireshark 4.6.7 release addressing 12 CVEs |
| HaveIBeenPwned | 1 | [Glendale CC breach](https://haveibeenpwned.com/Breach/GlendaleCommunityCollege) | ShinyHunters pay-or-leak breach (793,925 accounts) |
| Wired Security | 1 | [GhostLock coverage](https://www.wired.com/story/security-news-this-week-ai-found-a-root-bug-in-linux-that-everyone-missed-for-15-years/) | GhostLock (CVE-2026-43499) Linux LPE |
| Unit 42 | 1 | [The Gentlemen Ransomware](https://unit42.paloaltonetworks.com/the-gentlemen-ransomware/) | Full profile of Storm-2697 / former ArmCorp affiliate |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Patch Linux kernels for CVE-2026-43499 (GhostLock) — confirm fixed package rather than assume distribution catch-up; prioritise container hosts, multi-tenant systems, and any Linux host with untrusted local accounts.
- 🔴 **IMMEDIATE:** Deploy the ClamAV vendor updates addressing CVE-2026-20215, -20217, -20213, -20214, -20216, -20244, and -20243 across all mail gateways and file-server scanners; until patched, disable archive/PE scanning on internet-facing scanners.
- 🟠 **SHORT-TERM:** Upgrade NATS Server to the fixed release covering CVE-2026-58207/58208/58209/58250/58251/58252/58253; audit `authorization` blocks for wildcard-overlap patterns and rate-limit unauthenticated Connz/INFO probes at the edge.
- 🟠 **SHORT-TERM:** Harden edge access (SSL VPN, firewall management planes, exposed file-share gateways) against The Gentlemen / Qilin / DragonForce initial-access playbook; rotate any credentials predating August 2025 and enforce phishing-resistant MFA on all edge devices.
- 🟡 **AWARENESS:** Treat committed images (PNG/JPEG/SVG) as executable content in AI-assisted development pipelines; require human review for any AI-agent commit touching `.env`, secrets, or CI configuration to blunt Ghostcommit-style prompt injection.
- 🟢 **STRATEGIC:** Baseline U-Boot / firmware measurements now on network and embedded fleet devices; require signed images with hardware root-of-trust before deploying vendor firmware, and establish an attestation cadence so post-compromise drift is detectable.

---

*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 48 reports processed across 2 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
