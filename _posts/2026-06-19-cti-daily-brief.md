---
layout: post
title:  "CTI Daily Brief: 2026-06-19 - ShinyHunters Oracle PeopleSoft zero-day hits JCPenney, Icarus claims Klue OAuth breach, Unit42 warns of FortiBleed credential campaign"
date:   2026-06-20 20:15:00 +0000
description: "53 reports across 7 sources. ShinyHunters exploit Oracle PeopleSoft zero-day to breach JCPenney (368k records). Icarus extortion group claims the Klue OAuth breach with growing victim list (Recorded Future, Tanium, Jamf, Sprout Social, Gong, Insurity). Unit42 warns of large-scale FortiBleed password-spraying campaign against Fortinet, Sophos and MSSQL edge devices. Chromium ships 4 critical and 8 high-severity browser CVEs; OpenSSL batch addresses Bleichenbacher oracle and crypto IV/tag flaws."
category: daily
tags: [cti, daily-brief, shinyhunters, icarus, brain-cipher, krybit, fortibleed, chromium, openssl]
classification: TLP:CLEAR
reporting_period: "2026-06-19"
generated: "2026-06-20"
draft: true
severity: critical
report_count: 53
sources:
  - Microsoft
  - RansomLook
  - BleepingComputer
  - Unit42
  - HaveIBeenPwned
  - Schneier
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-06-19 (24h) | TLP:CLEAR | 2026-06-20 |

## 1. Executive Summary

The pipeline processed 53 reports across 7 sources in the last 24 hours, with the threat picture dominated by active extortion campaigns and a heavy browser/cryptography vulnerability cycle. ShinyHunters has weaponised a critical zero-day in Oracle PeopleSoft to compromise JCPenney HR systems, leaking 368,418 employee records that include SSNs, dates of birth and home addresses. The Icarus extortion group has publicly claimed the Klue OAuth breach, and the disclosed victim list now includes Recorded Future, Tanium, Jamf, Sprout Social, Gong, Huntress and Insurity, all affected via stolen Salesforce OAuth tokens. Unit 42 issued a "FortiBleed" advisory describing internet-wide password spraying against Fortinet, Sophos and MSSQL devices, with offline cracking and configuration extraction used to establish persistent administrative access. Chromium's June batch shipped 4 critical and 8 high-severity CVEs (use-after-free in Browser, heap overflow in WebRTC, Digital Credentials), and an OpenSSL batch addresses a Bleichenbacher oracle in CMS_decrypt/PKCS7_decrypt, ASN.1 heap overflows and AES-OCB/GCM-SIV cryptographic flaws. No CISA KEV additions were observed in the reporting period.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 4 | JCPenney/ShinyHunters PeopleSoft 0-day; Linux net/sched page-cache corruption; Chromium Browser UAF; Chromium WebRTC heap overflow |
| 🟠 **HIGH** | 23 | Klue/Icarus OAuth campaign; FortiBleed; OpenSSL/CMS crypto batch; Chromium Digital Credentials UAF; OpenBSD MPLS kernel disclosure; Krybit & Brain Cipher ransomware |
| 🟡 **MEDIUM** | 19 | Chromium Downloads/Extensions/Passwords; OpenSSL ASN.1 NULL deref; Gravity SMTP WordPress info disclosure (actively exploited) |
| 🟢 **LOW** | 5 | Chromium WebShare/Views/Serial/Updater housekeeping |
| 🔵 **INFO** | 2 | BLACKNET-00 tooling teaser; Schneier squid blog |

## 3. Priority Intelligence Items

### 3.1 ShinyHunters Exploit Oracle PeopleSoft Zero-Day in JCPenney HR Breach

**Source:** [HaveIBeenPwned](https://haveibeenpwned.com/Breach/JCPenney)

JCPenney has confirmed a June 2026 breach exposing 368,418 employee and contractor records after ShinyHunters exploited a critical zero-day in Oracle PeopleSoft to reach internal HR systems. The leaked dataset includes corporate and personal email addresses, full names, dates of birth, Social Security numbers, phone numbers, home addresses, government-issued IDs, job titles and usernames. ShinyHunters operated a "pay or leak" extortion model; when the demand was refused, the data was published. The Oracle PeopleSoft 0-day referenced here matches the wider extortion wave ShinyHunters has been running for several weeks and remains the most operationally significant edge-application risk in the brief. Mapped techniques include T1059 (Command and Scripting Interpreter) and account-discovery activity once inside HR systems.

**Affected:** Oracle PeopleSoft customers (HR/HCM modules); retail and corporate-HR sectors.

> **SOC Action:** Inventory all internet-facing Oracle PeopleSoft / HCM instances and confirm patch status with Oracle support for the cited HR-systems zero-day. Pull 90 days of PeopleSoft web-tier access logs and hunt for anomalous PSFT_HR module calls from non-corporate egress IPs. Force credential rotation and MFA re-enrolment for all HR/payroll admin accounts and add a high-priority alert for bulk SELECTs from PS_PERSON, PS_EMPLOYMENT, and SSN-bearing tables.

### 3.2 Icarus Extortion Group Publicly Claims Klue OAuth Breach; Victim List Expands

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/klue-oauth-breach-victim-list-grows-as-icarus-hackers-claim-attack/)

Market-intelligence platform Klue confirmed that a compromised legacy integration credential allowed attackers to obtain OAuth tokens connecting Klue Battlecards to customer Salesforce environments. The Icarus extortion group has now publicly claimed the attack on its data-leak site and is pressuring victims to negotiate via the Session messenger. ReliaQuest observed Icarus generating fresh OAuth tokens and using Python scripts to query Salesforce APIs over extended periods, exfiltrating business contacts, sales communications and pricing data. Disclosed downstream victims include Recorded Future, Tanium, Jamf, Sprout Social, Gong, Huntress and Insurity. CrowdStrike is engaged for response; Klue states no platform-stored content was impacted. Mapped TTPs: T1078 (Valid Accounts) and OAuth-token abuse against SaaS APIs.

**Affected:** Salesforce customers with Klue Battlecards integration; downstream SaaS supply-chain risk.

> **SOC Action:** In Salesforce Setup, audit Connected Apps and revoke any tokens linked to Klue or Battlecards integrations; force a fresh OAuth consent flow with restricted scopes. Pull Salesforce Event Monitoring for API.LIGHTNING.LOGIN.ATTEMPT and BulkApi events outside normal business hours, particularly Python user-agent strings. Treat extortion emails referencing Session IDs as in-scope incidents and notify legal before any reply.

### 3.3 Unit 42 "FortiBleed" — Internet-Wide Credential Attacks on Edge Devices

**Source:** [Unit 42 / Palo Alto Networks](https://unit42.paloaltonetworks.com/large-scale-credential-attacks/)

Unit 42 is tracking a large-scale password-spraying and credential-theft campaign dubbed "FortiBleed" against Fortinet appliances, with parallel attempts observed against MSSQL services and reports of Sophos devices also targeted. The actors run a three-stage flow: (1) internet-wide password spraying using lists curated from prior breaches; (2) when initial access is gained, exploitation of a privilege-escalation flaw and extraction of device configuration files including stored credentials; (3) offline cracking of those credentials, which are then re-used to broaden the campaign and to log back in as administrators for persistence. An Initial Access Broker on the Russian-language Exploit[.]in forum claimed responsibility and began selling harvested credentials on 16 June 2026. Mapped TTPs: T1078 (Valid Accounts), T1087 (Account Discovery), T1555.001 (Use Alternate Authentication Material).

**Affected:** Fortinet (FortiGate/FortiOS), Sophos, internet-exposed MSSQL services; any organisation exposing edge-device management interfaces.

> **SOC Action:** In Fortinet logs, alert on successful admin logins occurring within 60 minutes of a sustained password-failure burst from the same source ASN; in Sophos Central, do the same for Super-Admin role authentications. Disable WAN-side access to FortiGate/Sophos management interfaces (move to ZTNA or jump host), require MFA on every admin account, and rotate any local-account passwords stored in device config. Block known IAB-seller IPs at the perimeter once published.

### 3.4 Chromium June Security Batch — 4 Critical, 8 High-Severity Browser CVEs

**Source:** [Microsoft Security Update Guide](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-12464)

The Chromium upstream batch ingested by Microsoft Edge ships two critical memory-safety flaws — CVE-2026-12464 (use-after-free in Browser, arbitrary code execution via crafted web content) and CVE-2026-12466 (heap buffer overflow in WebRTC) — plus high-severity use-after-frees in Digital Credentials (CVE-2026-12451, -12440, -12439), Tab Strip (CVE-2026-12455), Chromoting (CVE-2026-12444) and an additional WebRTC heap overflow (CVE-2026-12447) and out-of-bounds read (CVE-2026-12461). No in-the-wild exploitation has been confirmed for this cycle, but historically Chromium UAFs of this class become 1-day exploits within days. Likely delivery via T1566 (Phishing) → malicious URL → T1218 (signed-binary execution) once code execution is achieved in renderer.

**Affected:** Google Chrome, Microsoft Edge (Chromium), and all downstream Chromium-derived browsers/Electron apps.

> **SOC Action:** Push the latest Edge/Chrome channel to all managed endpoints within 24 hours via Intune/SCCM and force-restart browsers at end of day. For Electron-based desktop apps (Slack, Teams, Discord, VS Code) check vendor advisories for matching upstream patches. Add Chromium version `< 138.x` to vulnerability-management severity-elevation rules and hunt for unusual `chrome.exe` / `msedge.exe` child processes (rundll32, mshta) from user temp directories.

### 3.5 OpenSSL/CMS Cryptography Batch — Bleichenbacher Oracle and Crypto Flaws

**Source:** [Microsoft Security Update Guide](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-42768)

Microsoft published a coordinated batch of OpenSSL/cryptography advisories. The most severe is CVE-2026-42768, a Multi-RecipientInfo Bleichenbacher oracle in CMS_decrypt()/PKCS7_decrypt() that exposes plaintext via timing and error-message side channels against crafted ciphertexts. Additional high-severity issues include CVE-2026-7383 (ASN.1 multibyte-string heap buffer overflow), CVE-2026-9076 (CMS password-based decryption OOB read), CVE-2026-45446 (incorrect tag processing for empty messages in AES-GCM-SIV / AES-SIV — authentication-bypass risk) and CVE-2026-45445 (AES-OCB IV ignored on EVP_Cipher() path). Medium-severity issues — CVE-2026-34180 (ASN.1 over-read), CVE-2026-42766/42767 (NULL derefs in password-based / CRMF decryption) and CVE-2026-34183 (unbounded memory growth in QUIC PATH_CHALLENGE) — should be patched in the same cycle.

**Affected:** Any product or appliance shipping vulnerable OpenSSL or opentelemetry-cpp (CVE-2026-44967 unbounded HTTP response in OTLP exporter); CMS/PKCS7 mail and signing pipelines; QUIC servers.

> **SOC Action:** Inventory all OpenSSL versions across servers, network appliances and embedded products; treat anything using CMS/PKCS7 decryption (S/MIME mail relays, code-signing services) as priority patch targets. Re-test S/MIME and PKCS7 decryption services for timing variance using OpenSSL maintainer reproducers. For OTLP, cap HTTP response sizes at the collector to mitigate CVE-2026-44967 until updated builds ship.

### 3.6 Linux Kernel net/sched Page-Cache Corruption (Critical)

**Source:** [Microsoft Security Update Guide](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-46331)

CVE-2026-46331 in Linux `net/sched` allows a partial copy-on-write operation in the `pedit` action to corrupt the page cache, enabling arbitrary in-memory modifications and information leaks. Although exploitation requires the ability to load or manipulate traffic-control rules, success yields powerful primitives against kernel data, with implications for container hosts and multi-tenant systems where `CAP_NET_ADMIN` is reachable.

**Affected:** Linux distributions shipping the affected `net/sched` pedit code path; container hosts, multi-tenant compute, network appliances.

> **SOC Action:** Patch kernels across Linux fleets via vendor advisories (RHEL/Ubuntu/SUSE). On container hosts, ensure workloads do not have `CAP_NET_ADMIN` and that `seccomp`/`AppArmor` profiles block `setsockopt`-style traffic-control manipulation. Audit any internal tooling that programmatically configures `tc pedit` rules.

### 3.7 OpenBSD Remote Kernel MPLS Stack Disclosure (PoC Circulated)

**Source:** Telegram (channel name redacted) — TLP:AMBER+STRICT

CVE-2026-56099 is a remote kernel information-disclosure issue in OpenBSD's MPLS stack with a proof-of-concept circulated on a closed Telegram channel. The flaw enables remote disclosure of kernel memory, providing primitives that meaningfully assist a follow-on remote-code-execution exploit. Treat as credible given the TLP:AMBER+STRICT distribution and PoC availability.

**Affected:** OpenBSD systems with MPLS enabled on internet-exposed interfaces (BGP/MPLS routers, BSD-based network appliances).

> **SOC Action:** Identify OpenBSD-based routers and firewalls; if MPLS is not required, disable the MPLS stack on internet-facing interfaces. Restrict MPLS to trusted backbone segments via ACLs. Subscribe to OpenBSD `errata` and apply the upstream patch as soon as the maintainers publish it; in the interim, monitor northbound logs for anomalous LDP/MPLS control-plane traffic from external peers.

### 3.8 Active Exploitation — Gravity SMTP WordPress Plugin (CVE-2026-4020)

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/hackers-exploit-info-disclosure-bug-in-gravity-smtp-wordpress-plugin/)

Defiant/Wordfence reports active exploitation of CVE-2026-4020, an unauthenticated info-disclosure flaw in Gravity SMTP (≤ 2.1.4, installed on ~100,000 sites). The exposed `/wp-json/gravitysmtp/v1/tests/mock-data` endpoint returns a System Report containing API keys, OAuth tokens and SMTP credentials for Amazon SES, Google, Mailjet, Resend and Zoho, plus WordPress/PHP/DB configuration data. Wordfence has blocked 17 million attempts; activity spiked on 7 June with 4 million requests in a single day. Adjacent advisory CVE-2026-8713 (Avada Builder arbitrary file deletion on 1 million sites) is fixed in 3.15.4 and is a likely next target.

**Affected:** WordPress sites running Gravity SMTP ≤ 2.1.4 or Avada Builder < 3.15.4.

> **SOC Action:** Patch Gravity SMTP to ≥ 2.1.5 and Avada Builder to ≥ 3.15.4. Hunt web-access logs for requests to `/wp-json/gravitysmtp/v1/tests/mock-data` and `?page=gravitysmtp-settings`; for any hit, treat all configured third-party email credentials as compromised and rotate immediately. Add WAF rule to block unauthenticated GETs against `gravitysmtp` REST endpoints.

#### Indicators of Compromise

```
URL path:   /wp-json/gravitysmtp/v1/tests/mock-data
URL param:  ?page=gravitysmtp-settings
TTP:        OAuth-token issuance via Python user-agents (Salesforce/Klue)
TTP:        Burst password-failure → admin success (FortiBleed)
Forum:      Exploit[.]in (IAB credential sale, 2026-06-16)
Ransom contact (Brain Cipher): brain.support@cyberfear[.]com,
                               brain.dataleak@cyberfear[.]com,
                               brain.decrypt@cyberfear[.]com
Telegram PoC:                  channel name redacted (OpenBSD MPLS)
```

### 3.9 Ransomware Activity — Brain Cipher, Krybit, Qilin, The Gentlemen

**Source:** [RansomLook](https://www.ransomlook.io/) (Brain Cipher, Krybit, Qilin, The Gentlemen group pages)

RansomLook ingestion shows continued double-extortion posting from Brain Cipher (themintgaming.com), Krybit (aasa.ae, mupras.com, coemi.com.br across real-estate, manufacturing and Middle-East/LATAM targets), Qilin (Sparkle Pools) and The Gentlemen (Athens Orthopedic Clinic — US healthcare). The latest correlation batch flags this as a critical-risk trend, with Brain Cipher operating LockBit 3.0-based Salsa20/RSA hybrid encryption and demanding up to USD 8M. The BLACKNET-00 Telegram channel announced an updated ransomware builder, suggesting commodity-RaaS supply continues to expand. TTPs across these groups: T1486 (Data Encrypted for Impact), T1566 (Phishing), T1071.001 (web C2).

**Affected:** Government, healthcare (Athens Orthopedic Clinic confirmed), real estate, manufacturing, gaming, education.

> **SOC Action:** For healthcare and gov sectors, validate offline backup restorability this week and confirm AD Tier-0 segregation. Block known Brain Cipher contact mailboxes (`*@cyberfear.com` patterns) at mail gateway. Hunt for LockBit-3.0-derived behaviour: rapid `cmd.exe /c vssadmin delete shadows` activity and Salsa20/RSA hybrid encryption signatures in EDR.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Rising ransomware activity with double-extortion focus, targeting government and healthcare | themintgaming.com (Brain Cipher); mupras.com (Krybit) |
| 🟠 **HIGH** | Increased exploitation of buffer-overflow and use-after-free vulnerabilities in tech / government stacks | CVE-2026-7383 (ASN.1 heap overflow); CVE-2026-12464 (Browser UAF) |
| 🟠 **HIGH** | Cross-report TTP cluster around T1566 Phishing as initial access | OTLP/opentelemetry-cpp advisory; BLACKNET-00 ransomware builder; Brain Cipher posting |
| 🟠 **HIGH** | Cross-report TTP cluster around T1068 Privilege Escalation | CVE-2026-42768 PKCS7 Bleichenbacher; Gravity SMTP exploitation |
| 🟠 **HIGH** | Sector concentration: technology vendors most affected by this cycle | OpenSSL/CMS CVEs; Chromium UAF batch (Chromoting, Media, Digital Credentials) |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **The Gentlemen** (73 reports) — RaaS group with active healthcare and logistics targeting; CAPTCHA-protected leak site.
- **Qilin** (65 reports) — High-volume RaaS operator with redundant onion / FTP infrastructure; new victim Sparkle Pools posted in this cycle.
- **Deadlock** (55 reports) — Recent surge in posting volume across the last 7 days.
- **Lockbit5** (39 reports) — Continuing successor activity to the LockBit ecosystem.
- **DragonForce** (37 reports) — Active across multiple sectors.
- **Akira** (31 reports) — Persistent ransomware operator; healthcare and SMB targeting.
- **Nightspire** (26 reports) — Featured in this week's "EDR-killer framework" reporting.
- **ShinyHunters / Shinyhunters** (45 combined) — Active extortion campaign; this cycle's JCPenney/PeopleSoft breach extends the streak.
- **Inc Ransom** (14 reports) — Ongoing posting activity.

### Malware Families

- **RansomLook** (133 reports) — Source-tag aggregation of leak-site posts; tracks live ransomware ecosystems.
- **Tox1 / Tox** (87 combined) — Tox messenger IDs used as ransomware contact channels.
- **Other1** (32 reports) — RansomLook generic-classifier tag for unattributed leak posts.
- **Lockbit5** (14 reports) — Successor-variant payloads.
- **Akira ransomware** (14 reports) — Encryption tooling.
- **Nightspire** (11 reports) — Group-tied ransomware payload.
- **The Gentlemen** (10 reports) — Group-tied payload tracking.
- **Deadlock** (10 reports) — Group-tied payload tracking.
- **Akira** (10 reports) — Group-tied payload tracking.

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| Microsoft | 39 | [link](https://msrc.microsoft.com/update-guide) | Chromium June batch + OpenSSL/CMS crypto batch + Linux net/sched critical |
| RansomLook | 6 | [link](https://www.ransomlook.io/) | Brain Cipher, Krybit, Qilin, The Gentlemen leak-site postings |
| Unknown | 3 | — | Telegram-sourced (OpenBSD MPLS PoC; BLACKNET-00 builder updates) |
| BleepingComputer | 2 | [link](https://www.bleepingcomputer.com/news/security/klue-oauth-breach-victim-list-grows-as-icarus-hackers-claim-attack/) | Klue/Icarus OAuth breach; Gravity SMTP active exploitation |
| Unit42 | 1 | [link](https://unit42.paloaltonetworks.com/large-scale-credential-attacks/) | FortiBleed credential-theft advisory |
| HaveIBeenPwned | 1 | [link](https://haveibeenpwned.com/Breach/JCPenney) | JCPenney 368k breach (ShinyHunters / PeopleSoft 0-day) |
| Schneier | 1 | [link](https://www.schneier.com/) | Friday squid blog (info) |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Inventory and patch internet-facing Oracle PeopleSoft instances and rotate HR/payroll admin credentials with MFA — direct response to the ShinyHunters JCPenney breach (Section 3.1).
- 🔴 **IMMEDIATE:** In Salesforce, revoke Klue/Battlecards Connected Apps and audit Event Monitoring for Python-user-agent BulkApi exfiltration; treat any Icarus extortion email as an active incident (Section 3.2).
- 🟠 **SHORT-TERM:** Roll out the Chromium June security update (Chrome/Edge) and any Electron app vendor patches within 24 hours; force browser restart at end of day (Section 3.4).
- 🟠 **SHORT-TERM:** Move FortiGate / Sophos / MSSQL management interfaces off the public internet, enforce MFA, and rotate device-stored credentials; subscribe to the IAB IP blocklist when published (Section 3.3).
- 🟠 **SHORT-TERM:** Patch the OpenSSL/CMS batch (CVE-2026-42768, -7383, -9076, -45446, -45445) on signing services and S/MIME pipelines; cap OTLP HTTP response sizes pending opentelemetry-cpp fix (Section 3.5).
- 🟡 **AWARENESS:** Patch Linux kernels for CVE-2026-46331 (net/sched) and restrict `CAP_NET_ADMIN` on container hosts; patch WordPress Gravity SMTP and Avada Builder; harden OpenBSD MPLS exposure pending upstream errata (Sections 3.6, 3.7, 3.8).
- 🟢 **STRATEGIC:** Validate offline-backup restorability for healthcare and government tenants in response to sustained Brain Cipher / Qilin / The Gentlemen activity; review SaaS supply-chain OAuth-grant inventories as a recurring control given the Klue precedent (Section 3.9).

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 53 reports processed across 1 correlation batch. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
