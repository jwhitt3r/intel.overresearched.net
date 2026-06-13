---
layout: post
title:  "CTI Daily Brief: 2026-06-12 - Critical OpenSSL CMS/PKCS7 cluster, Vim Python RCE, and ShadowByt3$ ransomware spree"
date:   2026-06-13 20:15:00 +0000
description: "Four critical CVEs dominate the day: a Bleichenbacher oracle in OpenSSL CMS_decrypt(), a heap UAF in PKCS7_verify(), and two Vim Python omni-completion code-execution flaws. ShadowByt3$ ransomware breaches eight high-profile victims including Nintendo, Starbucks, and University of Georgia. Velvet Ant exposed running a 10-year authentication-flow hijack against an air-gapped network."
category: daily
tags: [cti, daily-brief, shadowbyt3, velvet-ant, 3am, coinbase-cartel, cve-2026-42768, cve-2026-45447, cve-2026-52858, openssl, vim]
classification: TLP:CLEAR
reporting_period: "2026-06-12"
generated: "2026-06-13"
draft: true
severity: critical
report_count: 75
sources:
  - Microsoft
  - RansomLock
  - BleepingComputer
  - Unit42
  - Wired Security
  - Schneier
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-06-12 (24h) | TLP:CLEAR | 2026-06-13 |

## 1. Executive Summary

The pipeline processed 75 reports across 7 sources in the last 24 hours, with 4 critical and 43 high-severity items. The day is dominated by a coordinated batch of OpenSSL cryptographic advisories — a Bleichenbacher oracle in `CMS_decrypt()`/`PKCS7_decrypt()` (CVE-2026-42768) and a heap use-after-free in `PKCS7_verify()` (CVE-2026-45447) — plus two arbitrary code execution flaws in Vim's Python omni-completion (CVE-2026-52858, CVE-2026-52860). On the criminal side, the ShadowByt3$ ransomware group claimed eight victims in a single posting cycle including Nintendo, Starbucks, the University of Georgia, and Syngenta's Cropwise platform, while BleepingComputer disclosed that the Chinese-aligned Velvet Ant cluster maintained a 10-year foothold in an air-gapped network through hijacked Linux PAM modules and Nginx-relayed HTTP execution paths. No CISA KEV additions were observed in the reporting window. The 3AM ransomware family (LockBit fallback) continued its surge with 12 fresh victims overnight using email-bombing + Quick Assist vishing for initial access.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 4 | OpenSSL CMS Bleichenbacher oracle; OpenSSL PKCS7_verify UAF; two Vim Python omni-completion ACE bugs |
| 🟠 **HIGH** | 43 | ShadowByt3$/3am/Coinbase Cartel/Prinz Eugen ransomware; OpenSSL/SQLite/gitoxide/curl CVE batch; Velvet Ant 10-year espionage |
| 🟡 **MEDIUM** | 21 | Cargo credential leakage; OpenSSL ASN.1 read; CRMF NULL deref; AES-GCM-SIV tag; Anthropic export-control story |
| 🟢 **LOW** | 1 | Single low-severity report |
| 🔵 **INFO** | 6 | RansomLook telemetry and infrastructure notes |

## 3. Priority Intelligence Items

### 3.1 OpenSSL/CMS cryptographic cluster — Bleichenbacher oracle and PKCS7 use-after-free

**Source:** [Microsoft MSRC — CVE-2026-42768](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-42768), [Microsoft MSRC — CVE-2026-45447](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45447)

Two critical OpenSSL flaws were disclosed alongside roughly a dozen high- and medium-severity siblings in the same coordinated batch. CVE-2026-42768 is a Bleichenbacher-style padding oracle in `CMS_decrypt()` and `PKCS7_decrypt()` triggered by improper PKCS#1 v1.5 padding validation across Multi-RecipientInfo structures — an attacker with enough oracle queries can recover plaintext from intercepted CMS-encrypted messages. CVE-2026-45447 is a heap use-after-free in `PKCS7_verify()` reachable via crafted signed messages, allowing arbitrary code execution or denial of service in any process that verifies untrusted PKCS#7 signatures (mail clients, code-signing tools, S/MIME gateways). Related high-severity siblings in the same advisory bundle include CVE-2026-42769 (trust-anchor substitution in CMP `rootCaKeyUpdate`), CVE-2026-42766 (NULL deref in password-based CMS decryption), CVE-2026-42764 (NULL deref in QUIC server initial packet), CVE-2026-9076 (out-of-bounds read in CMS password-based decryption), CVE-2026-34182 (CMS `AuthEnvelopedData` accepts forged messages), and CVE-2026-34183 (unbounded memory growth in QUIC `PATH_CHALLENGE`).

**Affected:** Any application linking OpenSSL with CMS/PKCS7 verification or decryption — TLS gateways, email security appliances, code-signing CI runners, S/MIME-enabled mail servers, QUIC servers.

**MITRE ATT&CK:** T1068 (Exploitation for Privilege Escalation), T1071.001 (Application Layer Protocol: Web Protocols).

> **SOC Action:** Enumerate OpenSSL versions across the estate (`openssl version -a`, package inventory across `libssl*` and `libcrypto*`). Prioritise patching on internet-facing systems that terminate CMS/PKCS7 signed payloads (S/MIME relays, code-signing verifiers, OCSP responders). Until patched, restrict ingestion of unauthenticated PKCS#7 messages at the perimeter and disable QUIC on edge proxies that don't require it. Hunt for repeated decryption-failure error patterns in OpenSSL application logs — an attacker working a Bleichenbacher oracle generates thousands of malformed CMS messages per recovered byte.

### 3.2 Vim Python omni-completion — arbitrary code execution on file open

**Source:** [Microsoft MSRC — CVE-2026-52858](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-52858), [Microsoft MSRC — CVE-2026-52860](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-52860), [Microsoft MSRC — CVE-2026-47162](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-47162)

Two critical buffer-overflow flaws in Vim's Python omni-completion mechanism (CVE-2026-52858 and CVE-2026-52860) allow arbitrary code execution with the privileges of the user running Vim when omni-completion is triggered against a crafted Python source file. A related high-severity Vimscript code-injection flaw in `netrw`'s `NetrwBookHistSave()` (CVE-2026-47162) is triggered by crafted directory names, providing a second route to code execution for users who browse hostile directory listings.

**Affected:** Developer and admin workstations and CI runners with Vim/`vim-python3` installed. High exposure where engineers open untrusted source from artifact repos, code review tools, or attachments.

**MITRE ATT&CK:** T1059.001 (Command and Scripting Interpreter: Python), T1204 (User Execution), T1064 (Scripting).

> **SOC Action:** Push the patched Vim package across all developer endpoints and CI worker images via configuration management this week. Until patched, advise developers to open unknown `.py` files with `vim -u NONE -i NONE` or in a non-Python editor, and to use `netrw` only on trusted local paths. Hunt EDR for `vim` processes spawning shells (`bash`, `sh`, `python`) on file-open with no prior keystroke activity — that's the high-fidelity signature for these omni-completion exploits.

### 3.3 ShadowByt3$ ransomware spree — eight victims including Nintendo, Starbucks, UGA

**Source:** [RansomLook — ShadowByt3$](https://www.ransomlook.io//group/shadowbyt3%24)

The ShadowByt3$ extortion group posted eight victims on its leak site in a single 16:00 UTC cycle: Stride Learning, University of Georgia, Starbucks, Hotelogix, Leadership Boulevard, BreachForums (`breachforu.ms`), Nintendo, and Syngenta's Cropwise platform. The University of Georgia post details ~3.2 MB of exfiltrated text covering employee PII, project documentation, GIS critical-infrastructure maps for GEMA/GDOT/Georgia Broadband, and asset-forfeiture records — explicitly naming Subject Matter Experts. The group's ransom demands cluster around US$500,000, paid in Bitcoin or Monero, and the post text references prior breaches dating to 2026-04-01. ShadowByt3$ infrastructure is fragile (3/8 listed leak sites returning HTTP 200 at parse time) but persistent. AI correlation analysis flagged the cluster at 0.95 confidence as a single-actor campaign and identified phishing (T1566) and valid-account abuse (T1078) as the primary access vectors.

**Affected sectors:** Education, retail/QSR, hospitality, manufacturing (agriculture), gaming.

**MITRE ATT&CK:** T1566 (Phishing), T1078 (Valid Accounts), T1048 (Exfiltration Over Alternative Protocol), T1567.002 (Exfiltration to Cloud Storage — S3).

#### Indicators of Compromise

```
Leak site (Tor):  hxxp[:]//shdwbt3ja2ptjt6poluegas44i35727lgmoqqquoww642x3zyocyhuqd[.]onion/leaks
Leak site (Tor):  hxxp[:]//mfbbt65kir2drc7tuoukwibikgvxquauscnzgbeltkmidjtgqlzm2qad[.]onion/leaks.php
Active web host:  45.84.0[.]211
Contact email:    ShadowByt3S@proton[.]me
Reference S3:     starbucks-prod  (closed after breach detection)
```

> **SOC Action:** For Education and Retail customers, query identity providers for anomalous successful logins from unmanaged endpoints with no MFA challenge in the 30 days prior to public disclosure — ShadowByt3$ leans on valid accounts after phishing. Audit public S3 buckets for naming patterns of business-critical prod buckets (`*-prod`, `*-data`, `*-backup`) and confirm bucket policies block anonymous listing. Block egress to `45.84.0.211` and the listed Tor leak-site addresses at the proxy/firewall layer.

### 3.4 Velvet Ant — 10-year auth-flow hijack of an air-gapped critical-infrastructure network

**Source:** [BleepingComputer — Chinese hackers hijack auth flow, spy on isolated network for a decade](https://www.bleepingcomputer.com/news/security/chinese-hackers-hijack-auth-flow-spy-on-isolated-network-for-a-decade/)

Sygnia disclosed "Operation Highland," a Velvet Ant (China-nexus) campaign that has sat on an undisclosed organisation's network since 2016. After compromising internet-facing servers, the actor deployed a modified GS-Netcat reverse shell disguised as a system daemon, then built a SOCKS5 tunnel and abused Nginx + FastCGI (`fcgiwrap`) to relay HTTP POST requests into a segregated network with no direct internet path. Persistence and credential theft were achieved by replacing legitimate `pam_unix.so` Linux PAM modules with nine distinct backdoored variants — some collecting credentials, some accepting hardcoded passwords. Velvet Ant was previously linked (2024) to a 3-year F5 BIG-IP campaign and the Cisco NX-OS zero-day exploited in Nexus switches.

**Affected sectors:** Critical infrastructure (unnamed), telecom, network appliance vendors.

**MITRE ATT&CK:** T1021 (Remote Services), T1071 (Application Layer Protocol), T1546.023 (Boot or Logon Initialization Scripts), T1556.003 (Modify Authentication Process: PAM), T1568 (Dynamic Resolution).

> **SOC Action:** Baseline and monitor `/lib*/security/pam_unix.so` and `/etc/pam.d/*` file hashes on all Linux servers — `find /lib*/security -name 'pam_*.so' -exec sha256sum {} \;` should match the distro package, and the file's package owner should match `rpm -qf` / `dpkg -S`. Audit Nginx and Apache configurations for `fastcgi_pass` or `proxy_pass` directives pointing at non-standard internal hosts. Query EDR for processes named `smbd -D` running outside Samba install paths (Velvet Ant's SOCKS5 proxy masquerade). Pivot to authentication logs and look for successful logins with the user `root` from internal IPs that have no other login activity.

### 3.5 3AM ransomware — Quick Assist vishing wave continues

**Source:** [RansomLook — 3am](https://www.ransomlook.io//group/3am)

The Rust-based 3AM ransomware family (formerly a LockBit fallback) posted 12 new victims overnight across Croatia, Argentina, Brazil, Belgium, Australia, and Vietnam, spanning aerospace machining, town governments, insurtech, agro-industry, law firms, and energy. The intrusion pattern documented in external Sophos and Tripwire write-ups is consistent: email-bombing the target user inbox, followed by a vishing call requesting that the user accept a Microsoft Quick Assist session, which is then used to deploy a virtual machine carrying the backdoor. Files are encrypted with the `.threeamtime` extension, tagged with the `0x666` marker, and Volume Shadow Copies are deleted. Data is exfiltrated before encryption for double extortion.

**MITRE ATT&CK:** T1566 (Phishing — voice-driven), T1219 (Remote Access Software — Quick Assist), T1486 (Data Encrypted for Impact), T1490 (Inhibit System Recovery).

#### Indicators of Compromise

```
Leak site (Tor): hxxp[:]//threeamkelxicjsaf2czjyz2lc4q3ngqkxhhlexyfcp2o6raw4rphyad[.]onion
Chat (Tor):      hxxp[:]//threeam7fj33rv5twe5ll7gcrp3kkyyt6ez5stssixnuwh4v3csxdwqd[.]onion/
Contact:         threeam@onionmail[.]org
Extension:       .threeamtime
File marker:     0x666
```

> **SOC Action:** Block Microsoft Quick Assist (`quickassist.exe`) at the application-control layer for all non-IT users via WDAC or AppLocker — there is no legitimate business case for end-user Quick Assist sessions in most environments. Force email bombing detection rules in the secure email gateway (>50 inbound messages to one mailbox in <10 minutes triggers quarantine). Hunt EDR for `vssadmin delete shadows /all /quiet` and creation of files with `.threeamtime` extension.

### 3.6 Coinbase Cartel RaaS — advertising and telematics targeted

**Source:** [RansomLook — Coinbase Cartel](https://www.ransomlook.io//group/coinbase%20cartel)

Coinbase Cartel, a known RaaS operation, posted Demand.io (advertising) and Cambridge Mobile Telematics (telematics) as fresh victims. The ransom values posted (US$10.5M and US$200M respectively) appear to be the group's estimate of victim revenue, not the ransom demand. Infrastructure analysis shows degraded uptime (2/12 file-server onions reachable) suggesting active takedown pressure, though the primary leak site remains at 100% uptime. AI correlation analysis at 0.90 confidence groups both victims under a single phishing-led (T1566) campaign using Tox, Atomic Mail, and SimpleX for affiliate coordination.

**Affected sectors:** Advertising, telematics/automotive insurance.

**MITRE ATT&CK:** T1566 (Phishing), T1071.001 (Application Layer Protocol: Web Protocols).

> **SOC Action:** For advertising/adtech and telematics customers, audit external attack surface for exposed admin panels and confirm MFA on all VPN/SSO entry points. Block egress to the known Tox and SimpleX FQDNs (`*.simplex.im`, Tox bootstrap nodes) from corporate endpoints — there is no legitimate use case and presence of those connections is high-fidelity evidence of either compromise or insider risk.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Exploitation of vulnerabilities in widely-distributed software and protocols, particularly affecting Microsoft-published OpenSSL advisories | CVE-2026-10846 (response validation), CVE-2026-11822 (SQLite FTS5 memory corruption) |
| 🟠 **HIGH** | ShadowByt3$ multi-sector ransomware burst targeting education, retail, hospitality | Stride Learning, University of Georgia, Starbucks, Hotelogix, Cropwise/Syngenta, Nintendo — single-actor cluster at 0.95 confidence |
| 🟠 **HIGH** | RaaS-model groups expanding sector coverage | Coinbase Cartel hitting Demand.io and Cambridge Mobile Telematics (0.90 confidence single-actor cluster) |
| 🟠 **HIGH** | Rise of ransomware groups employing double-extortion plus voice-driven social engineering | 3AM ransomware victims across jetmachprod.com, palmero.com, molinoscabodi.com.ar (Quick Assist vishing playbook) |
| 🟠 **HIGH** | Cross-library software supply-chain CVE batch | CVE-2026-11822 SQLite FTS5, CVE-2026-40034 gitoxide command injection, CVE-2026-5222/5223 Cargo credential leak |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **Qilin** (79 reports) — Continues to dominate the pipeline as the highest-volume ransomware actor over 30 days.
- **The Gentlemen** (53 reports) — Sustained high-tempo extortion postings.
- **DragonForce** (42 reports) — Global RaaS hitting retail, government, and construction; previous batch flagged DragonForce activity against shipyards and Gulf-region contractors.
- **Akira** (33 reports) — Persistent ransomware operator with steady victim cadence.
- **TeamPCP** (26 reports) — Hacktivist-aligned operator.
- **Nightspire** (22 reports) — Active double-extortion group.
- **ShinyHunters** (20 reports) — Behind recent American Tower / JCPenney / MSG / Zayo extortion postings.
- **Stormous** (19 reports) — Today's MLIT (Malaysia) breach disclosure adds to ongoing campaign.
- **Velvet Ant** — New entry from today's BleepingComputer disclosure of Operation Highland.
- **Shadowbyt3$** — Single-day burst of 8 victims today; not yet in the rolling top 10.

### Malware Families

- **RansomLook** (109 reports) — Aggregator telemetry; not malware itself.
- **Tox1 / Tox** (34 + 21 reports) — Encrypted comms used by multiple ransomware affiliate programmes.
- **Akira ransomware** (17 reports) — Continued operations.
- **Shai-Hulud / Mini Shai-Hulud** (12 + 12 reports) — Persistent campaign, no new postings today.
- **RALord** (12 reports) — Steady output.
- **GS-Netcat** — New entry today via the Velvet Ant disclosure (modified reverse-shell variant).
- **3AM** — Active overnight; 12 fresh victims posted.

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| Microsoft (MSRC) | 32 | [link](https://msrc.microsoft.com/update-guide) | Coordinated OpenSSL/Vim/SQLite/curl/gitoxide CVE batch — primary critical driver |
| RansomLook | 28 | [link](https://www.ransomlook.io/) | Ransomware leak-site telemetry — ShadowByt3$, 3AM, Coinbase Cartel, Prinz Eugen, Stormous, Triple X |
| Unknown | 10 | — | Mostly Telegram-origin proxy/phishing telemetry; URLs withheld per editorial policy |
| BleepingComputer | 2 | [link](https://www.bleepingcomputer.com/news/security/chinese-hackers-hijack-auth-flow-spy-on-isolated-network-for-a-decade/) | Velvet Ant Operation Highland; Anthropic export-control story |
| Unit42 | 1 | [link](https://unit42.paloaltonetworks.com/) | Routine telemetry contribution |
| Wired Security | 1 | [link](https://www.wired.com/category/security/) | Routine coverage |
| Schneier on Security | 1 | [link](https://www.schneier.com/) | Commentary |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Patch OpenSSL across the estate to address CVE-2026-42768 (Bleichenbacher oracle), CVE-2026-45447 (PKCS7_verify UAF), and the associated high/medium CMS/CMP/QUIC siblings. Prioritise S/MIME relays, code-signing verifiers, and any service that processes unauthenticated PKCS#7 input.
- 🔴 **IMMEDIATE:** Push patched Vim to all developer endpoints and CI runner images to close CVE-2026-52858, CVE-2026-52860, and CVE-2026-47162 (netrw); these trigger on file-open and are realistic supply-chain entry points.
- 🟠 **SHORT-TERM:** Block Microsoft Quick Assist for non-IT users via WDAC/AppLocker policy to defeat the 3AM ransomware vishing playbook; add email-bombing detection to the secure email gateway.
- 🟠 **SHORT-TERM:** For Education, Retail, and Manufacturing customers, query IdP logs for the 30 days prior to today for anomalous logins lacking MFA challenges — ShadowByt3$ leans on phished/valid credentials and burst-discloses many victims in one cycle.
- 🟡 **AWARENESS:** Baseline `pam_unix.so` and PAM configuration on Linux servers and brief the team on the Velvet Ant PAM-replacement technique; the campaign ran undetected for 10 years on a 2016 foothold and is unlikely to be unique to one target.
- 🟢 **STRATEGIC:** Treat the Microsoft-published OpenSSL/Vim/SQLite/curl/gitoxide CVE batch as a forcing function to inventory third-party libraries embedded in commercial software (SBOM enrichment); without an SBOM, downstream patching cannot be planned reliably.

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 75 reports processed across 4 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
