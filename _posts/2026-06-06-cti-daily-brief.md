---
layout: post
title:  "CTI Daily Brief: 2026-06-06 - Silent Ransom Group targets U.S. law firms; BlackByte Crux ransomware hits professional services; C0XMO botnet exploits DD-WRT routers"
date:   2026-06-07 20:30:00 +0000
description: "21 reports across 5 sources. Silent Ransom Group (UNC3753/Luna Moth) escalates social-engineering attacks against U.S. law firms via callback phishing; BlackByte affiliate Crux ransomware claims Quanticate; C0XMO botnet weaponises CVE-2021-27137 on DD-WRT firmware; ShinyHunters leaks 102,935 Baker Distributing accounts. 13 Microsoft CVE advisories cover Python/Go/Ansible/networking stacks."
category: daily
tags: [cti, daily-brief, blackbyte, shinyhunters, luna-moth, c0xmo, cve-2026-50219]
classification: TLP:CLEAR
reporting_period: "2026-06-06"
generated: "2026-06-07"
draft: true
severity: critical
report_count: 21
sources:
  - Microsoft
  - BleepingComputer
  - RansomLook
  - HaveIBeenPwned
  - Telegram (channel name redacted)
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-06-06 (24h) | TLP:CLEAR | 2026-06-07 |

## 1. Executive Summary

The 24-hour window produced 21 reports across 5 sources, dominated by a Microsoft MSRC vulnerability batch (13 advisories spanning Python, Go, Ansible, FRRouting, libexpat, rrdtool, and cilium ebpf) and three high-severity operational events: the Silent Ransom Group (UNC3753 / Luna Moth / Chatty Spider) actively targeting U.S. law firms through callback phishing and remote-support social engineering, BlackByte's Crux ransomware affiliate listing UK clinical-research firm Quanticate, and a new Gafgyt-derived botnet (C0XMO) propagating via DD-WRT router flaw CVE-2021-27137 while terminating rival malware. ShinyHunters published 102,935 accounts from HVAC/R distributor Baker Distributing, claimed to have been exfiltrated from SharePoint and Salesforce. One critical-severity CVE (libexpat use-after-free, CVE-2026-50219) was disclosed; no CISA KEV additions or in-the-wild exploitation were reported in this period.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 1 | libexpat use-after-free (CVE-2026-50219) |
| 🟠 **HIGH** | 11 | Silent Ransom / law-firm campaign; BlackByte Crux ransomware; C0XMO botnet; Baker Distributing breach; Microsoft CVE batch (pip, Ansible, tarfile, rrdtool, FRR, cilium ebpf) |
| 🟡 **MEDIUM** | 9 | Go crypto/x509, net/textproto, mime CVEs; Perl HTML::Entities UAF; gnutls timing side-channel; three Telegram proxy IOCs |
| 🟢 **LOW** | 0 | — |
| 🔵 **INFO** | 0 | — |

## 3. Priority Intelligence Items

### 3.1 Silent Ransom Group (UNC3753 / Luna Moth) targets U.S. law firms with callback phishing

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/silent-ransom-group-targets-law-firms-with-fake-it-support-calls/)

Mandiant has published technical detail on the Silent Ransom Group — tracked as UNC3753, Luna Moth, and Chatty Spider — following an FBI FLASH advisory the prior week. The group has compromised dozens of legal, financial, and professional-services firms between January and May 2026. Attacks begin with invoice-themed phishing emails from consumer mail accounts that contain no links or attachments; victims are then cold-called by actors impersonating internal IT staff, who direct them into Microsoft Teams, Zoom, Quick Assist, or Microsoft Terminal Services sessions. Once joined, the operators install AnyDesk, Zoho Assist, Bomgar, or SuperOps for persistence. Phishing infrastructure uses naming patterns `<organization>-itdesk[.]com`, `<organization>-it[.]com`, and `<organization>-helpdesk[.]com`, with `privnote[.]com` used to ferry installation links and minimise browser-history artefacts. Exfiltration uses WinSCP or Rclone against document-management and cloud-storage repositories; ransom demands typically land within 30 minutes of attacker egress. MITRE: T1566 (Phishing), T1021 (Remote Services), T1071.001 (Application Layer Protocol: Web Protocols).

#### Indicators of Compromise

```
Phishing patterns: <org>-itdesk[.]com, <org>-it[.]com, <org>-helpdesk[.]com
Anonymous messaging: privnote[.]com
RMM tools abused: AnyDesk, Zoho Assist, Bomgar, SuperOps, Quick Assist
Exfil tooling: WinSCP, Rclone
```

> **SOC Action:** Block inbound/outbound connections to `privnote[.]com` at the proxy; create EDR detections for AnyDesk, Zoho Assist, Bomgar, and SuperOps installer binaries executing under non-admin user contexts; alert on outbound SSH/SFTP via WinSCP or Rclone from endpoints outside the IT support cohort; brief partners and reception staff that no legitimate IT engagement will require joining a remote-support session initiated by an unsolicited phone call.

### 3.2 BlackByte affiliate "Crux" ransomware lists Quanticate; double-extortion against professional services

**Source:** [RansomLook](https://www.ransomlook.io//group/blackbyte-crux)

Crux, a BlackByte-aligned ransomware variant active since July 2025, has added UK clinical-research organisation Quanticate Limited (Hitchin) to its leak portal. Crux operates a double-extortion model with a Tor-hosted leak site and follows a distinctive execution chain: `svchost.exe` → `cmd.exe` → `bcdedit.exe` to disable Windows recovery, followed by file encryption with the `.crux` extension. Ransom notes use the naming pattern `crux_readme_[random].txt`. Confirmed victimology spans agriculture, education, professional services, media, and nonprofits across the U.S. and U.K. MITRE: T1003 (OS Credential Dumping), T1485 (Data Encrypted for Impact), T1496 (Resource Hijacking).

#### Indicators of Compromise

```
Tor leak portal: dounczge5jhw4iztnnpzp54kd4ot3tikhjsimurtcewqssgye6vvrhqd[.]onion
File server: faow6n2hkweyyalp67zvonafn2dzphw36cav653wamj724mwsmtfa5yd[.]onion
Contact: BlackBCruxSupport@onionmail[.]org
Encryption extension: .crux
Ransom note: crux_readme_[random].txt
Execution chain: svchost.exe -> cmd.exe -> bcdedit.exe
```

> **SOC Action:** Build SIEM correlation rules for `bcdedit.exe` executed by `cmd.exe` parented to `svchost.exe` — this sequence has limited legitimate use. Block the onionmail.org contact domain at mail gateway. Verify offline, immutable backups are in place for legal, scientific, and clinical-research data stores. Hunt for the `.crux` extension and `crux_readme_*.txt` file creation across SMB/NAS share telemetry.

### 3.3 C0XMO botnet weaponises DD-WRT flaw, terminates competing malware

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/c0xmo-botnet-spreads-via-dd-wrt-router-flaw-kills-rival-malware/)

Fortinet has identified C0XMO, a new Gafgyt-derived botnet targeting DD-WRT router firmware via CVE-2021-27137 (an unauthenticated buffer overflow leading to RCE). Samples exist for ARM, MIPS, PowerPC, SuperH, x86, and x86_64. The malware deploys a Python scanner (using `requests`, `paramiko`, `beautifulsoup4`) to brute-force SSH/Telnet on ports 22, 23, 80, 443, 7547, 8080, 8443, and 8888. Persistence is established via copies to `/tmp/.sys`, `/var/tmp/.sys`, `/dev/shm/.sys`, cron jobs running every 15 minutes, and shell startup-file modifications. C0XMO enumerates and kills competing botnet clients, red-team tools, and other interfering processes. It supports 19 DDoS methods including UDP/TCP/SYN/ICMP floods, NTP/Memcached amplification, and Discord/Valve-specific floods. The correlation engine flagged this as the period's **critical-risk trend** because of the botnet's aggressive territorial behaviour and modular architecture. MITRE: T1071 (Application Layer Protocol), T1090 (Proxy: Multi-hop Proxy), T1496 (Resource Hijacking).

#### Indicators of Compromise

```
CVE: CVE-2021-27137 (DD-WRT buffer overflow, unauthenticated RCE)
Persistence paths: /tmp/.sys, /var/tmp/.sys, /dev/shm/.sys
Scan ports: 22, 23, 80, 443, 7547, 8080, 8443, 8888
Cron cadence: every 15 minutes
Python deps pulled: requests, paramiko, beautifulsoup4
Affected architectures: ARM, MIPS, PowerPC, SuperH, x86, x86_64
```

> **SOC Action:** Audit and patch any DD-WRT-firmware devices on internal or guest networks; disable WAN-side SSH/Telnet and replace default credentials. Block egress SSH/Telnet from IoT VLANs to the internet. Add EDR file-creation alerts for `*/.sys` binaries in `/tmp`, `/var/tmp`, and `/dev/shm`, and a crontab alert for jobs scheduled at 15-minute intervals on Linux hosts.

### 3.4 Baker Distributing — 102,935 accounts published by ShinyHunters

**Source:** [HaveIBeenPwned](https://haveibeenpwned.com/Breach/BakerDistributing)

In May 2026, HVAC/R wholesale distributor Baker Distributing Company was added to ShinyHunters' "pay or leak" site; in early June the group published data they claim was exfiltrated from Baker's SharePoint and Salesforce tenants. The dump contains 102,935 unique email addresses with associated names, phone numbers, physical addresses, and support tickets — predominantly corporate contact records for the HVAC contractor customer base. ShinyHunters has remained one of the most active extortion actors of the past 30 days (26 reports pipeline-wide). MITRE: T1190, T1566 (Phishing).

> **SOC Action:** Cross-reference the Baker Distributing email-address dump against your HVAC supply chain and identity-provider logs; treat any matched mailboxes as candidates for credential-stuffing and BEC targeting. Force password resets and require step-up authentication for SharePoint Online and Salesforce administrative accounts; review OAuth app consents granted in the last 90 days.

### 3.5 Microsoft MSRC CVE batch — language runtimes and routing stacks

**Source:** [Microsoft Security Response Center](https://msrc.microsoft.com/update-guide)

A single MSRC publication wave on 2026-06-07 covered 13 advisories. The most operationally significant items, grouped to avoid duplication:

- 🔴 **CVE-2026-50219** — libexpat <2.8.2 use-after-free via missing handler call-depth tracking in `XML_GetBuffer`, `XML_Parse`, `XML_ParseBuffer`, `XML_ParserFree`, `XML_ParserReset` during policy-violation handling. *Critical.*
- 🟠 **CVE-2026-11332** — Ansible-core argument injection in `ansible-galaxy role install` enabling arbitrary code execution under the Ansible process identity.
- 🟠 **CVE-2026-8643** — pip extracts `console_scripts` / `gui_scripts` outside the installation directory; weaponisable via malicious wheels to plant executables in attacker-chosen locations.
- 🟠 **CVE-2026-7774** — Python `tarfile.data_filter` path-traversal bypass; permits writing outside the extraction directory.
- 🟠 **CVE-2026-43958** — rrdtool stack buffer overflow allowing local code execution or DoS.
- 🟠 **CVE-2026-37460** — FRRouting stable/10.0–10.6 missing input validation in `rfapiRibBi2Ri()`; DoS via crafted BGP UPDATE.
- 🟠 **CVE-2026-10722** — cilium ebpf integer overflow in `LoadCollectionSpec` / `LoadCollectionSpecFromReader` (`btf.go:loadRawSpec`).
- 🟡 Medium-severity Go standard-library issues: CVE-2026-27145 (`crypto/x509` inefficient hostname parsing), CVE-2026-42507 (`net/textproto` unescaped error inputs), CVE-2026-42504 (quadratic `WordDecoder.DecodeHeader` in `mime`).
- 🟡 CVE-2026-5419 (gnutls PKCS#7 padding timing side-channel), CVE-2026-8829 (Perl HTML::Entities `_decode_entities` reads freed heap memory), CVE-2026-3276 (Python `unicodedata.normalize()` quadratic-complexity DoS).

No in-the-wild exploitation, PoC public release, or CISA KEV inclusion was reported in the data for any of these CVEs.

> **SOC Action:** Prioritise patching of the libexpat CVE in any application that parses untrusted XML (especially XMPP, SAML/SSO middleware, and SOAP services). Pin Ansible-core to a patched release and audit CI/CD systems that invoke `ansible-galaxy role install` against untrusted sources. Inventory build agents and developer workstations for vulnerable pip versions; restrict outbound traffic from build runners to allowlisted package indices. For FRRouting deployments, validate BGP peer ACLs and consider rate-limiting UPDATE message processing until patched.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Advanced exploitation techniques by botnets to spread and eliminate competition, indicating a maturing IoT-threat landscape | C0XMO botnet spreads via DD-WRT router flaw, kills rival malware |
| 🟠 **HIGH** | Increased targeting of professional services across distinct threat vectors and actors | Quanticate (BlackByte / Crux ransomware); Silent Ransom Group targets law firms |
| 🟠 **HIGH** | Increased exploitation of software vulnerabilities across multiple sectors | CVE-2026-8643 (pip); CVE-2026-43958 (rrdtool); CVE-2026-50219 (libexpat) |
| 🟡 **MEDIUM** | Phishing campaigns leveraging Telegram proxies | Baker Distributing breach; three Telegram proxy IOCs (channel name redacted) |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **Qilin** (73 reports) — most-cited ransomware brand in the 30-day window
- **The Gentlemen** (42 reports) — sustained leak-site activity
- **DragonForce** (35 reports) — broad targeting across multiple sectors
- **Akira** (33 reports) — continues high tempo of disclosures
- **TeamPCP** (29 reports) — emerging operator since mid-May
- **ShinyHunters** (26 reports) — last seen today with Baker Distributing publication
- **Genesis** (22 reports) — active leak-site postings through 6 June
- **Nova** (21 reports) — ongoing healthcare/manufacturing targeting
- **Inc Ransom** (19 reports) — steady leak-site cadence
- **Stormous** (17 reports) — sustained operational presence

### Malware Families

- **Tox1 / Tox** (20 + 20 reports) — RaaS infrastructure widely cited
- **Akira ransomware** (18 reports) — paired with Akira actor activity
- **RALord** (12 reports) — leak-site brand
- **Mini Shai-Hulud** (11 reports) — supply-chain implant lineage
- **Nova** (11 reports) — corresponds to Nova actor leak-site posts
- **C0XMO** (1 report, new) — Gafgyt-derived botnet introduced today
- **Crux** (1 report, new) — BlackByte affiliate variant first observed July 2025, fresh victimology this period

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| Microsoft | 13 | [link](https://msrc.microsoft.com/update-guide) | MSRC vulnerability advisory batch covering Python, Go, Ansible, libexpat, rrdtool, FRR, cilium ebpf |
| BleepingComputer | 2 | [link](https://www.bleepingcomputer.com/news/security/silent-ransom-group-targets-law-firms-with-fake-it-support-calls/) | Primary coverage of Silent Ransom Group and C0XMO botnet |
| RansomLook | 2 | [link](https://www.ransomlook.io//group/blackbyte-crux) | BlackByte / Crux and Blackwater leak-site monitoring |
| HaveIBeenPwned | 1 | [link](https://haveibeenpwned.com/Breach/BakerDistributing) | ShinyHunters publication of Baker Distributing dataset |
| Telegram (channel name redacted) | 3 | — | Proxy-server IOCs flagged for possible phishing infrastructure |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Block `privnote[.]com` at the corporate proxy and alert on installation of AnyDesk, Zoho Assist, Bomgar, or SuperOps on legal and professional-services endpoints (Silent Ransom Group / UNC3753 campaign — §3.1).
- 🔴 **IMMEDIATE:** Patch libexpat to ≥2.8.2 across any service handling untrusted XML, prioritising SSO middleware, XMPP, and SOAP gateways (CVE-2026-50219, the only critical-severity CVE in the period — §3.5).
- 🟠 **SHORT-TERM:** Deploy EDR detection for the `svchost.exe → cmd.exe → bcdedit.exe` sequence and validate offline-immutable backup coverage for clinical-research, legal, and SMB-shared document stores ahead of further BlackByte/Crux activity (§3.2).
- 🟠 **SHORT-TERM:** Audit and patch DD-WRT routers (CVE-2021-27137), disable WAN-side SSH/Telnet, and create file-creation alerts for `*/.sys` artefacts in `/tmp`, `/var/tmp`, and `/dev/shm` on Linux hosts (C0XMO — §3.3).
- 🟡 **AWARENESS:** Cross-reference the Baker Distributing email-address dump against HVAC supplier identity-provider logs; force MFA step-up on SharePoint Online and Salesforce administrative accounts (§3.4).
- 🟢 **STRATEGIC:** Establish a vetting workflow for `ansible-galaxy` role and pip dependency sources used in CI/CD; restrict build-runner egress to allowlisted package indices to limit the blast radius of CVE-2026-11332 and CVE-2026-8643 (§3.5).

---

*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 21 reports processed across 2 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
