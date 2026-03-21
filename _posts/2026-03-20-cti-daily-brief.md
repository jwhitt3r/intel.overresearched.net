---
layout: post
title: "CTI Daily Brief: 2026-03-20 — Trivy Supply-Chain Compromise Distributes Infostealer via GitHub Actions; Linux Kernel and pyOpenSSL Critical CVEs Published"
date: 2026-03-21 22:01:00 +0000
description: "Supply-chain attack on Trivy vulnerability scanner by TeamPCP dominates a 28-report day alongside critical Linux kernel netfilter and pyOpenSSL vulnerabilities, Azure Monitor callback phishing abuse, and a botnet takedown affecting 3M+ devices."
category: daily
tags: [cti, daily-brief, teampcp, darksword, cve-2026-27448, cve-2026-33017]
classification: TLP:CLEAR
reporting_period: "2026-03-20"
generated: "2026-03-21"
severity: critical
draft: false
report_count: 28
sources:
  - Microsoft
  - BleepingComputer
  - Wired Security
  - Unit42
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-03-20 (24h) | TLP:CLEAR | 2026-03-21 |

## 1. Executive Summary

The CognitiveCTI pipeline processed 28 reports from 5 sources over the past 24 hours. The dominant story is a confirmed supply-chain compromise of the Trivy vulnerability scanner by threat actor TeamPCP, who distributed an infostealer through trojanized GitHub Actions and release binaries — a critical risk to any CI/CD pipeline referencing affected tags. Microsoft published a batch of critical Linux kernel vulnerabilities in netfilter and net/sched components (CVE-2026-23204, CVE-2026-23272, CVE-2026-23274, CVE-2026-23277) alongside critical pyOpenSSL flaws enabling TLS bypass and buffer overflow (CVE-2026-27448, CVE-2026-27459). Callback phishing campaigns are actively abusing Microsoft Azure Monitor's legitimate email infrastructure to bypass SPF/DKIM/DMARC checks. US law enforcement took down four botnets — Aisuru, Kimwolf, JackSkid, and Mossad — that had infected over 3 million devices globally.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 8 | Trivy supply-chain compromise; Linux kernel netfilter/net/sched CVEs; pyOpenSSL TLS bypass; WebKit SOP bypass; Langflow unauthenticated RCE |
| 🟠 **HIGH** | 4 | Azure Monitor callback phishing; Intoxalock cyberattack & botnet takedown; pyOpenSSL DTLS buffer overflow; breached cloud accounts |
| 🟡 **MEDIUM** | 16 | Libsoup CRLF injection cluster; ingress-nginx config injection; nghttp2 DoS; AI-enabled retail fraud; Linux kernel race conditions |

## 3. Priority Intelligence Items

### 3.1 Trivy Vulnerability Scanner Supply-Chain Compromise (TeamPCP)

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/trivy-vulnerability-scanner-breach-pushed-infostealer-via-github-actions/)

Threat actor TeamPCP compromised the Trivy vulnerability scanner's GitHub build process, publishing trojanized binaries in the v0.69.4 release and force-pushing 75 of 76 tags in the `aquasecurity/trivy-action` repository to malicious commits. The infostealer harvested SSH keys, cloud provider credentials (AWS, GCP, Azure, Kubernetes), CI/CD secrets, database configs, cryptocurrency wallets, and shell history. Collected data was encrypted, archived as `tpcp.tar.gz`, and exfiltrated to the typosquatted C2 domain `scan.aquasecurtiy[.]org`. When exfiltration failed, the malware created a public repository named `tpcp-docs` in the victim's GitHub account to stage stolen data. The malware also scraped the GitHub Actions Runner.Worker process memory for live secrets. This attack traces back to an earlier March credential breach that was not fully contained.

**MITRE ATT&CK:** T1195.002 (Supply Chain Compromise: Compromise Software Supply Chain), T1059 (Command and Scripting Interpreter), T1552 (Unsecured Credentials), T1567 (Exfiltration Over Web Service)

#### Indicators of Compromise
```
C2: scan.aquasecurtiy[.]org
Archive: tpcp.tar.gz
Affected release: Trivy v0.69.4
Affected repo: aquasecurity/trivy-action (75/76 tags compromised)
```

> **SOC Action:** Immediately audit all CI/CD pipelines referencing `aquasecurity/trivy-action` or Trivy container images. Pin GitHub Actions to known-good commit SHAs rather than mutable tags. Search artifact registries for Trivy v0.69.4 binaries. Query DNS logs for `aquasecurtiy[.]org` (note typo). Rotate any credentials that may have been exposed in workflows running affected tags since early March.

### 3.2 Linux Kernel Critical Vulnerabilities — netfilter and net/sched

**Source:** [Microsoft MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-23204)

Four critical vulnerabilities were published affecting the Linux kernel's networking subsystem. CVE-2026-23204 is a use-after-free in the cls_u32 classifier that could allow remote code execution with kernel privileges via crafted network packets. CVE-2026-23272 affects nf_tables element insertion, enabling uncontrolled memory manipulation. CVE-2026-23277 is a NULL pointer dereference in TEQL slave transmit that could cause kernel crashes or privilege escalation. CVE-2026-23274 allows unauthorized reuse of ALARM timer labels in xt_IDLETIMER. These vulnerabilities affect systems running affected kernel versions with netfilter or traffic scheduling modules loaded.

> **SOC Action:** Identify all Linux hosts running kernel versions with netfilter or net/sched modules enabled. Prioritise patching internet-facing servers and container hosts. Where immediate patching is not possible, restrict network access to trusted sources and monitor for unusual kernel crash patterns or unexpected nf_tables rule modifications.

### 3.3 pyOpenSSL TLS Bypass and DTLS Buffer Overflow

**Source:** [Microsoft MSRC — CVE-2026-27448](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-27448), [Microsoft MSRC — CVE-2026-27459](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-27459)

CVE-2026-27448 (critical) enables TLS connection bypass through an unhandled callback exception in `set_tlsext_servername_callback`, potentially allowing attackers to intercept or manipulate encrypted communications. CVE-2026-27459 (high) is a buffer overflow in the DTLS cookie callback mechanism that could enable remote code execution. Both vulnerabilities affect applications using the pyOpenSSL library for TLS/DTLS operations, including web servers, API gateways, and IoT device communications.

> **SOC Action:** Inventory all applications using pyOpenSSL (search for `import OpenSSL` in Python codebases and `pyopenssl` in dependency files). Upgrade to the patched version immediately. Review TLS termination configurations and monitor for unexpected TLS handshake failures that may indicate exploitation attempts.

### 3.4 Azure Monitor Alert Abuse in Callback Phishing Campaigns

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/microsoft-azure-monitor-alerts-abused-in-callback-phishing-campaigns/)

Threat actors are creating Azure Monitor alerts with malicious billing-themed descriptions, then configuring them to send emails through Microsoft's legitimate `azure-noreply@microsoft.com` address. Because the emails originate from Azure's infrastructure, they pass SPF, DKIM, and DMARC checks, bypassing most email security gateways. The messages urge recipients to call fraudulent phone numbers for "account security verification." Multiple alert rule patterns have been observed including invoice payment confirmations and funds received notifications.

**MITRE ATT&CK:** T1566 (Phishing), T1583.006 (Acquire Infrastructure: Web Services)

> **SOC Action:** Configure email gateway rules to flag Azure Monitor alert emails containing phone numbers or billing dispute language. Alert the SOC on any `azure-noreply@microsoft.com` messages referencing transaction verification. Educate users that Microsoft does not request callback verification through Azure Monitor alerts. Review Azure subscriptions for unauthorized alert rule creation.

### 3.5 Botnet Takedown and DarkSword Malware Targeting iPhones

**Source:** [Wired Security](https://www.wired.com/story/security-news-this-week-cyberattack-on-a-car-breathalyzer-firm-leaves-drivers-stuck/)

US law enforcement dismantled four botnets — Aisuru, Kimwolf, JackSkid, and Mossad — that collectively infected over 3 million devices, many inside home networks, and were used to conduct record-breaking cyberattacks. Separately, a new tool called DarkSword, attributed to Russian hackers, is reportedly capable of taking over hundreds of millions of iPhones to steal victim data. The same report covers a cyberattack on Intoxalock, a car breathalyzer provider used daily by 150,000 US drivers, which caused system downtime and stranded drivers unable to start their vehicles due to missed calibration windows.

> **SOC Action:** Query network telemetry for traffic associated with Aisuru, Kimwolf, JackSkid, and Mossad botnet infrastructure. Review iOS device fleet for indicators of DarkSword compromise. Monitor for post-takedown infrastructure migration — botnet operators frequently reconstitute on new C2 within days.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | CI/CD environment targeting via supply-chain attacks | Trivy GitHub Actions compromise; widespread GitHub Actions tag compromise (TeamPCP, T1078/T1552/T1567) |
| 🟠 **HIGH** | Phishing campaigns leveraging legitimate services | Azure Monitor alert abuse; Google Advanced Flow sideloading controls |
| 🟠 **HIGH** | Increased exploitation of open-source software vulnerabilities | Libsoup HTTP smuggling/SSRF (CVE-2026-3632); Libsoup CRLF injection (CVE-2026-3633); cls_u32 use-after-free (CVE-2026-23204) |
| 🟠 **HIGH** | Geopolitically-linked phishing campaigns | Breached cloud accounts and SMTP services; FBI links Signal phishing to Russian intelligence |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **Handala** (14 reports) — Iran-linked threat actor active across multiple campaigns over the past two weeks
- **Void Manticore** (5 reports) — Persistent activity linked to destructive operations
- **Aisuru / Kimwolf / JackSkid** (4 reports each) — Botnet operators; infrastructure seized by US law enforcement this period
- **APT28 / Fancy Bear** (4–7 combined reports) — Russian state-sponsored group linked to Signal phishing attacks
- **TeamPCP** (2 reports) — Supply-chain attacker behind the Trivy compromise

### Malware Families

- **Slopoly** (4 reports) — Active across recent campaigns
- **DarkSword** (3 reports) — New iPhone exploitation tool attributed to Russian hackers
- **NodeSnake** (3 reports) — Persistent backdoor activity
- **Perseus** (3 reports) — Recent campaign tool
- **Medusa** (2 reports) — Ransomware family with continued operations

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| Microsoft | 17 | [link](https://msrc.microsoft.com/update-guide) | Linux kernel, pyOpenSSL, and assorted CVE advisories |
| BleepingComputer | 3 | [link](https://www.bleepingcomputer.com) | Trivy supply-chain breach; Azure Monitor phishing; Google APK sideloading |
| Wired Security | 1 | [link](https://www.wired.com/category/security/) | Botnet takedown, DarkSword, Intoxalock cyberattack roundup |
| Unit42 | 1 | [link](https://unit42.paloaltonetworks.com) | AI-enabled retail fraud analysis |
| Telegram (channel name redacted) | 6 | — | CVE-2026-33017 Langflow RCE; CVE-2026-20643 WebKit SOP bypass; ingress-nginx injection; UDP bypass; breach notifications |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Audit all CI/CD pipelines for references to `aquasecurity/trivy-action` or Trivy v0.69.4. Pin all GitHub Actions to immutable commit SHAs. Rotate credentials exposed in any workflow that executed compromised Trivy tags since early March 2026.

- 🔴 **IMMEDIATE:** Apply kernel patches for CVE-2026-23204, CVE-2026-23272, CVE-2026-23277, and CVE-2026-23274 on Linux hosts running netfilter or net/sched modules, prioritising internet-facing and container infrastructure.

- 🟠 **SHORT-TERM:** Upgrade pyOpenSSL across all environments to address CVE-2026-27448 (TLS bypass) and CVE-2026-27459 (DTLS buffer overflow). Inventory all Python applications with pyOpenSSL as a dependency.

- 🟠 **SHORT-TERM:** Implement email gateway detections for Azure Monitor callback phishing — flag `azure-noreply@microsoft.com` messages containing phone numbers, billing dispute language, or transaction verification requests. Review Azure tenant alert rules for unauthorised creation.

- 🟡 **AWARENESS:** Monitor post-takedown activity from Aisuru, Kimwolf, JackSkid, and Mossad botnets. Operators typically reconstitute infrastructure rapidly; update IOC blocklists as new C2 domains emerge.

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 28 reports processed across 2 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
