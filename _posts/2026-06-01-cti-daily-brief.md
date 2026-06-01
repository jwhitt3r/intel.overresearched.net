---
layout: post
title:  "CTI Daily Brief: 2026-06-01 - SmartApeSG ClickFix campaign drops NetSupport RAT; Grupo Mauá ransomware targets Brazilian infrastructure"
date:   2026-06-01 20:25:00 +0000
description: "Low-volume reporting day dominated by a SANS ISC analysis of a SmartApeSG ClickFix infection chain delivering NetSupport RAT, plus a fresh RansomLook listing for Brazilian ransomware actor Grupo Mauá targeting construction and infrastructure."
category: daily
tags: [cti, daily-brief, grupo-maua, netsupport-rat, smartapesg]
classification: TLP:CLEAR
reporting_period: "2026-06-01"
generated: "2026-06-01"
draft: true
severity: high
report_count: 3
sources:
  - SANS
  - RansomLook
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-06-01 (24h) | TLP:CLEAR | 2026-06-01 |

## 1. Executive Summary

Three reports were processed across two sources (SANS, RansomLook) in the last 24 hours, with one high-severity item, one medium, and one informational. The dominant operational story is a SANS ISC diary by Brad Duncan documenting an active SmartApeSG ClickFix campaign that delivers an unidentified initial RAT and then drops NetSupport Manager RAT on infected Windows hosts, with fresh IOCs including a persistent C2 at 89.110.110[.]119. RansomLook surfaced a new listing from Brazilian ransomware actor Grupo Mauá, adding a construction/real-estate/energy victim to its known posting pattern. The morning correlation batch (5 reports, 2 trends) flagged Grupo Mauá's sector targeting as high risk and noted infrastructure overlap between the SmartApeSG chain and Telegram-distributed phishing setup under MITRE T1566. No critical-rated items, no CISA KEV additions, and no in-the-wild exploitation of named CVEs were reported in this cycle.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 0 | None reported in period |
| 🟠 **HIGH** | 1 | SmartApeSG ClickFix → NetSupport RAT (SANS ISC) |
| 🟡 **MEDIUM** | 1 | Grupo Mauá ransomware victim listing (RansomLook) |
| 🔵 **INFO** | 1 | SANS ISC Stormcast podcast — green threat level |

## 3. Priority Intelligence Items

### 3.1 SmartApeSG ClickFix delivers unidentified RAT chained to NetSupport Manager RAT

**Source:** [SANS ISC — Unidentified RAT pushes NetSupport RAT](https://isc.sans.edu/diary/rss/33034)

SANS ISC handler Brad Duncan published fresh indicators from a SmartApeSG ClickFix infection observed on 2026-05-27 that delivered an unidentified initial RAT followed by a NetSupport Manager RAT package. The initial RAT has generated non-TLS encoded traffic to the same C2 — 89.110.110[.]119:443 — since approximately April 2026, suggesting a stable operator-controlled node. The ClickFix lure is a fake verification page that coaches users into executing a script; the chain drops a 26 MB zip from silverharvestnetwork[.]com/check, then stages C:\ProgramData\processor.vbs (loader) → token.bat → setup.cab (NetSupport RAT payload), with the staging artefacts deleted post-install for persistence. NetSupport RAT C2 was observed at 185.163.47[.]217:443. Tags include SmartApeSG, ClickFix, NetSupportRAT.

**Affected:** Windows endpoints exposed to ClickFix social-engineering pages; any user population susceptible to "verify yourself" copy-paste-to-run prompts.

**MITRE ATT&CK:** T1204 (User Execution: Malicious File), T1071.001 (Application Layer Protocol: Web Protocols), T1546.003 (Boot/Logon Autostart — Masquerading reference per source).

#### Indicators of Compromise

```
SmartApeSG staging URLs:
hxxps[:]//hiddenplanetlab[.]top/signin/secure-util.js
hxxps[:]//hiddenplanetlab[.]top/signin/private-template?c66kjD5i
hxxps[:]//hiddenplanetlab[.]top/signin/legacy-worker.js?18b3825af007e53d

ClickFix script callbacks:
hxxp[:]//178.156.165[.]82/
hxxp[:]//178.156.173[.]194/
hxxps[:]//silverharvestnetwork[.]com/check

Initial RAT C2 (persistent since April 2026):
tcp[:]//89.110.110[.]119:443

NetSupport RAT C2:
hxxp[:]//185.163.47[.]217:443

File hashes (SHA256):
1514b1268e9dc6d2f37137aa38c756cb4bf8186ac9235d6863b78e7f8bbbe976  (initial RAT zip, 26,555,757 bytes)
469bac8e10f50263e8ff0806e6ba126bb4cc660799129a8653eab3f8ec7201e5  (processor.vbs loader)
9c7eda2c4d3aaa8746495741bef57a07de180f0409409faf0f91658e88ba33f5  (token.bat installer)
7ba5481c873bb3081442561f749f590badd72ef249fddfe993e30b28dc0c2112  (setup.cab — NetSupport package)

On-disk artefacts (transient — deleted post-install):
C:\ProgramData\processor.vbs
C:\ProgramData\token.bat
C:\ProgramData\setup.cab
NetSupport extraction path: C:\ProgramData\UpdateInstaller\
```

> **SOC Action:** Block the listed IPs and domains at egress. Hunt EDR telemetry for wscript.exe or cscript.exe spawning processor.vbs from C:\ProgramData, and for cmd.exe executing token.bat from the same path; flag any expand.exe or extrac32.exe extracting setup.cab to C:\ProgramData\UpdateInstaller\. Add a detection for outbound TCP/443 to 89.110.110[.]119 and 185.163.47[.]217 — both are non-TLS despite the port. User-awareness: refresh ClickFix guidance reminding staff that no legitimate verification page asks them to paste commands into Run, PowerShell, or a terminal.

### 3.2 Brazilian ransomware actor Grupo Mauá adds construction/real-estate victim

**Source:** [RansomLook — Bravox group page](https://www.ransomlook.io//group/bravox)

RansomLook's bravox tracker recorded a new victim posting on 2026-06-01: "Grupo Mauá" — described in the leak-site entry as operating in construction, real estate, energy, and infrastructure. The actor's two known onion sites (bravoxxtrmqee... and bravoxxwcfz5q...) are both currently up with 100% and 93% 30-day uptime respectively, and the group has posted 17 victims all-time with 6 in the last 30 days, indicating an active operational tempo. The morning correlation pass elevated this posting to a high-risk trend due to the sector — Brazilian construction and infrastructure aligns with critical-infrastructure exposure interest seen in other recent batches. No tooling, initial access vector, or ransom note details were provided by the source.

**Affected:** A Brazilian conglomerate operating in construction, real estate, energy, and infrastructure (named "Grupo Mauá" in the leak-site post). Sector-wide exposure: LATAM construction and infrastructure operators.

**MITRE ATT&CK:** Not enumerated in source data.

> **SOC Action:** Organisations operating in Brazilian construction, infrastructure, or energy supply chains should review external-facing RDP, VPN, and Citrix exposure and confirm MFA enforcement on remote access. Threat-hunting teams should monitor RansomLook and analogous trackers for further bravox postings and treat any direct or supply-chain link to "Grupo Mauá" as a candidate intrusion lead pending victim confirmation. No tactical IOCs available — focus on intel-led monitoring rather than blocklist updates.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🟠 **HIGH** | Targeting of multiple sectors by Brazilian threat actor Grupo Mauá | RansomLook bravox posting (Grupo Mauá); referenced alongside SANS ISC Stormcast landscape entry |
| 🟡 **MEDIUM** | Increased phishing-infrastructure overlap between SmartApeSG and Telegram-distributed proxy/secret links (MITRE T1566) | SANS ISC NetSupport RAT diary; Telegram (channel name redacted) phishing proxy post |

Wider-week context from the pipeline (batches 147–148, run 2026-05-31): Genesis ransomware activity across multiple sectors and an emerging vulnerability cluster in cryptographic libraries (Mbed TLS CVE-2026-34875 FFDH buffer overflow; GnuTLS CVE-2026-42012 SAN validation bypass) remained the dominant high-risk trends entering today's cycle.

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **Qilin** (77 reports) — Most-mentioned ransomware brand across the pipeline over the last 30 days.
- **Akira** (74 reports) — High-tempo ransomware actor with continuing weekly victim posts.
- **The Gentlemen** (63 reports) — Sustained leak-site posting activity through late May.
- **DragonForce** (33 reports) — Active extortion operator.
- **ShinyHunters** (31 reports) — Data-theft / extortion brand.
- **Genesis** (20 reports) — Highlighted in 2026-05-31 correlation as a multi-sector phishing-to-encryption operator.

### Malware Families

- **RansomLook** (125 reports) — Tracker tag dominating malware-entity counts; reflects volume of leak-site reporting rather than a discrete malware family.
- **Akira ransomware** (38 reports) — Aligns with the Akira threat-actor tempo above.
- **Tox1 / Tox** (31 / 17 reports) — Recurrent tracker-side classifier on RansomLook entries.
- **Akira / Akira Ransomware** (25 / 16 reports) — Duplicate name variants of the same family.
- **The Gentlemen** (15 reports) — Cross-tagged as actor and toolset in tracker data.
- **Everest ransomware** (11 reports) — Long-running brand still actively posting victims.
- **RALord** (10 reports) — Emerging brand seen since mid-May.

No newly trending vulnerabilities surfaced in the last 24 hours; the existing top-6 list (CVE-2026-0300, CVE-2026-35616, plus 2012–2013 mobile-driver CVEs) is unchanged from late May.

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| SANS | 2 | [link](https://isc.sans.edu/diary/rss/33034) | NetSupport RAT diary plus Monday Stormcast podcast |
| RansomLook | 1 | [link](https://www.ransomlook.io//group/bravox) | Grupo Mauá victim listing via bravox tracker |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Egress-block the SmartApeSG / NetSupport RAT C2 set (89.110.110[.]119, 185.163.47[.]217, silverharvestnetwork[.]com, hiddenplanetlab[.]top, 178.156.165[.]82, 178.156.173[.]194) and add the four SHA256 hashes from Section 3.1 to EDR allow/deny lists. Run a 30-day retrospective hunt for any of these indicators — the initial RAT C2 has been stable since April 2026.

- 🟠 **SHORT-TERM:** Build (or refresh) an EDR detection for VBScript or batch execution out of C:\ProgramData with subsequent CAB extraction to C:\ProgramData\UpdateInstaller\ — this chain is generic enough to catch SmartApeSG variants beyond today's hashes. Run a phishing-awareness micro-campaign on the ClickFix pattern (fake verification pages prompting copy-paste-to-run).

- 🟠 **SHORT-TERM:** If your organisation has Brazilian operations, suppliers, or partners in construction / real estate / energy / infrastructure, treat the Grupo Mauá listing as a watch-item: verify MFA on all remote-access surfaces, review recent VPN/RDP logs for anomalies, and pre-stage incident-response contacts.

- 🟡 **AWARENESS:** Telegram-distributed proxy/secret links remain a phishing-infrastructure vector correlated with broader campaigns under MITRE T1566. Continue to deprioritise t.me proxy URLs at the secure-web-gateway layer and treat them as suspicious by default.

- 🟢 **STRATEGIC:** The morning correlation batch covered only five reports — a quiet news Monday. Use the bandwidth to close out the Mbed TLS (CVE-2026-34875) and GnuTLS (CVE-2026-42012) library-update backlog flagged in the 2026-05-31 batch, before the next high-volume cycle arrives.

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 3 reports processed across 1 correlation batch. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
