---
layout: post
title:  "CTI Daily Brief: 2026-05-20 - In-the-wild exploitation of SonicWall CVE-2024-12802; Ukraine takedown of 28k-account infostealer operator; Qilin RaaS persistence"
date:   2026-05-21 20:05:59 +0000
description: "Ten reports across six sources covering confirmed in-the-wild exploitation of SonicWall CVE-2024-12802 for MFA bypass, a Ukrainian/U.S. joint takedown of an 18-year-old infostealer operator linked to 28,000 stolen accounts, continued Qilin RaaS victim postings, and two HIBP-listed data breaches."
category: daily
tags: [cti, daily-brief, qilin, cobalt-strike, cve-2024-12802, sonicwall]
classification: TLP:CLEAR
reporting_period: "2026-05-20"
generated: "2026-05-21"
draft: true
severity: high
report_count: 10
sources:
  - BleepingComputer
  - HaveIBeenPwned
  - RansomLook
  - Wired Security
  - SANS
  - Sysdig
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-05-20 (24h) | TLP:CLEAR | 2026-05-21 |

## 1. Executive Summary

Ten reports were processed across six sources for the 24 hours ending 2026-05-20, producing three high-severity items and no critical-rated reports. The headline finding is ReliaQuest's confirmation of the first observed in-the-wild exploitation of SonicWall **CVE-2024-12802**, where Gen6 SSL-VPN appliances remained vulnerable to MFA bypass after firmware patching because customers did not perform the required manual LDAP reconfiguration. Ukrainian cyberpolice, working with U.S. law enforcement, identified an 18-year-old Odesa-based infostealer operator tied to 28,000 compromised accounts and roughly $721,000 in fraudulent purchases. The Qilin RaaS group continued to post new victims (Hamer Childs and Porter W Yett) on its leak infrastructure, sustaining its position as the most active threat actor in the pipeline (115 reports over 30 days). Two additional historical-account breaches surfaced via HaveIBeenPwned (Dragonica Lunaris and Windows93/Myspace93). No CISA KEV additions were observed in the reporting window.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 0 | No data available for this period |
| 🟠 **HIGH** | 3 | SonicWall CVE-2024-12802 MFA bypass; Qilin RaaS victim post; Ukrainian infostealer takedown |
| 🟡 **MEDIUM** | 3 | Dragonica Lunaris and Windows93 breach disclosures; second Qilin victim post |
| 🟢 **LOW** | 0 | No data available for this period |
| 🔵 **INFO** | 4 | SANS ISC Stormcast; Sysdig runtime detection skill; two Wired policy/governance pieces |

## 3. Priority Intelligence Items

### 3.1 SonicWall CVE-2024-12802 MFA Bypass Exploited In The Wild on Gen6 SSL-VPN Appliances

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/hackers-bypass-sonicwall-vpn-mfa-due-to-incomplete-patching/)

ReliaQuest assesses with medium confidence that intrusions investigated between February and March 2026 represent the first in-the-wild exploitation of **CVE-2024-12802**, a missing MFA enforcement flaw affecting the UPN login format on SonicWall Gen6 SSL-VPN devices. Operators brute-forced valid VPN credentials, then authenticated past MFA because the firmware update alone does not remediate the issue on Gen6 — a manual LDAP reconfiguration (removing `userPrincipalName` from the "Qualified login name" field, clearing cached LDAP users, and resetting the SSL VPN user domain) is required. In one intrusion the actor reached a domain-joined file server within 30 minutes, used RDP with a shared local administrator credential, and attempted to drop a Cobalt Strike beacon plus a BYOVD driver, both of which were blocked by EDR. The intermittent log-out / log-back-in pattern is consistent with an initial access broker model, and the activity echoes prior Akira ransomware-linked SonicWall abuse. Gen7 and Gen8 appliances are remediated by the firmware update alone.

**Affected products/sectors:** SonicWall Gen6 SSL-VPN appliances; multi-sector and multi-geography per ReliaQuest. Mapped ATT&CK techniques: **T1078.004** (Valid Accounts: Local Account), **T1021** (Remote Services), **T1047** (WMI).

> **SOC Action:** Inventory all SonicWall Gen6 SSL-VPN appliances and confirm the manual LDAP remediation steps in SonicWall's advisory have been completed — firmware version alone is not a reliable indicator. Hunt VPN authentication logs for the `sess="CLI"` signal, which ReliaQuest flags as a key marker of scripted authentication abuse. Alert on successful VPN logins followed within 60 minutes by RDP using local administrator accounts, and on any attempted Cobalt Strike beacon execution or BYOVD driver loads on hosts reachable from the VPN segment.

### 3.2 Ukrainian Cyberpolice and U.S. Law Enforcement Identify Operator Behind 28,000-Account Infostealer Campaign

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/ukraine-identifies-infostealer-operator-tied-to-28-000-stolen-accounts/)

Ukrainian cyberpolice, working with U.S. law enforcement, have identified an 18-year-old from Odesa as the suspected administrator of an infostealer operation that ran from 2024 through 2025 and targeted users of a California-based online store. The operation harvested browser session tokens and credentials from approximately 28,000 victims; 5,800 of those accounts were used for roughly $721,000 in unauthorised purchases, producing about $250,000 in direct losses including chargebacks. Stolen sessions were processed and resold through online marketplaces and Telegram bots, and the police note session-token reuse was used to bypass MFA on some accounts. Authorities conducted two residential searches, seized devices, bank cards, and cryptocurrency-exchange evidence, but have not yet announced an arrest, suggesting case-building is ongoing. Mapped ATT&CK techniques: **T1003** (OS Credential Dumping), **T1078** (Valid Accounts), **T1189** (Drive-by Compromise).

**Affected products/sectors:** Retail/e-commerce customer accounts; cross-border (Ukraine–U.S.) operational impact.

> **SOC Action:** Treat session tokens as credentials in detection logic — alert on token reuse from a new ASN, geolocation, or device fingerprint within the session lifetime, especially when followed by purchase or payment-method changes. Review browser policy to disable persistent session cookies for high-value accounts, and ensure step-up authentication is required for new payment instruments and shipping addresses rather than relying solely on initial MFA.

### 3.3 Qilin RaaS: Two New Victim Postings and Continued Leak-Site Infrastructure Persistence

**Source:** [RansomLook (Hamer Childs)](https://www.ransomlook.io//group/qilin), [RansomLook (Porter W Yett)](https://www.ransomlook.io//group/qilin)

The Qilin (aka Agenda) ransomware-as-a-service group posted two additional victims — Hamer Childs and Porter W Yett — on its leak infrastructure during the reporting window. RansomLook tracking shows Qilin remains highly active: 1,831 posts all-time, 148 in the last 30 days, and 29 in the last 7 days. Operational infrastructure is largely degraded (6 of 640 surfaces categorised as degraded; most onion mirrors and FTP file servers offline), but two `.onion` URLs maintain 90–100% uptime, indicating the affiliates retain a working publication channel. Recent ransom-note naming patterns include `DtMXQFOCos-RECOVER-README.txt` and `README-RECOVER-[rand].txt`. Communications are via Jabber (`qilin@exploit.im`) and a Tox ID. AI-identified pipeline correlation links these two postings via the shared actor and the RansomLook tracking source. Qilin is the top-ranked threat actor in the pipeline-wide trending data with 115 reports in 30 days.

**Affected products/sectors:** Cross-sector ransomware victims, multi-geography; consistent with Qilin's pattern of opportunistic targeting under the RaaS model.

#### Indicators of Compromise

```
Ransom note: DtMXQFOCos-RECOVER-README.txt
Ransom note: README-RECOVER-[rand].txt
Ransom note: README-RECOVER-[rand]_2.txt
Jabber:      qilin@exploit.im
Tox:         7C35408411AEEBD53CDBCEBAB167D7B22F1E66614E89DFCB62EE835416F60E1BCD6995152B68
Leak (up):   hxxp[:]//ijzn3sicrcy7guixkzjkib4ukbiilwc3xhnmby4mcbccnsd7j2rekvqd[.]onion
Leak (up):   hxxp[:]//pandora42btuwlldza4uthk4bssbtsv47y4t5at5mo4ke3h4nqveobyd[.]onion
File srv:    hxxp[:]//kg2pf5nokg5xg2ahzbhzf5kucr5bc4y4ojordiebakopioqkk4vgz6ad[.]onion
IP:          31.41.244[.]100 (historical leak host)
```

> **SOC Action:** Block the listed `.onion` URLs and the legacy `31.41.244[.]100` IP at egress filtering and DNS-over-HTTPS resolvers, and create file-name alerts for the Qilin ransom-note patterns (`*RECOVER-README.txt`, `README-RECOVER-*.txt`) on file servers and user shares. Hunt for outbound Tox/Jabber connections from servers and admin workstations — neither protocol has a legitimate use in most enterprise environments.

### 3.4 Two Historical Account Breaches Disclosed via HaveIBeenPwned (Dragonica Lunaris and Windows93/Myspace93)

**Source:** [HaveIBeenPwned (Dragonica Lunaris)](https://haveibeenpwned.com/Breach/Dragonica), [HaveIBeenPwned (Windows93)](https://haveibeenpwned.com/Breach/Windows93)

Two account-breach disclosures were added in the window. The **Dragonica Lunaris** private game server (December 2025 incident) exposed 126,293 accounts including email addresses, usernames, dates of birth, spoken languages, and **bcrypt** password hashes — strong hashing limits offline crack feasibility but credential-stuffing against email re-use remains the operative risk. The **Windows93 / Myspace93** breach (January 2021, leaked publicly in June 2021) exposed 46,105 accounts containing email addresses, IP addresses, usernames, and passwords in **plain text**, posing direct credential-stuffing risk. Pipeline correlation links the Windows93 breach to a TTP cluster around **T1071.001** (Application Layer Protocol: Web Protocols) alongside the Webworm tradecraft writeup and the 9-year-old PHP vulnerability report — consistent with web-application surface as the underlying compromise vector.

**Affected products/sectors:** Gaming community / consumer web platforms; downstream exposure for enterprises whose users re-use the leaked addresses.

> **SOC Action:** Cross-reference both breach datasets against your workforce email directory and any customer identity pools; force password resets on matches and apply step-up MFA challenges on next login. For the plain-text Windows93 dataset specifically, escalate to credential-stuffing watch: add the corresponding email/password pairs to your IdP's leaked-credential block list if your provider supports it (Entra ID, Okta, Auth0 all do).

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Ransomware groups leveraging malware-signing-as-a-service platforms to enhance their operations (carryover from batch 133, 2026-05-19) | Microsoft disruption of Fox Tempest malware-signing-as-a-service platform tied to ransomware gangs |
| 🟠 **HIGH** | Increased targeting of software development ecosystems by threat actors | Latest PyPi Compromise; The npm Threat Landscape: Attack Surface and Mitigations (Updated May 20) — both linked to actor TeamPCP |
| 🟠 **HIGH** | Increased ransomware activity targeting diverse sectors | Multiple Qilin victim postings (Vial Agro, WNS Lowery, CJ Architects, Hamer Childs, Porter W Yett); PEAR group victims (Fana Jewelry, Indian Creek Valley Water Authority) |
| 🟠 **HIGH** | Increased targeting of technology and cloud sectors by malicious actors | GitHub TeamPCP intrusion claim; ChromaDB max-severity AI-app server hijacking flaw; Fox Tempest malware-signing disruption |
| 🟠 **HIGH** | Rise in phishing-related cybercrimes affecting various sectors | Safepay leak (olipes.com); Microsoft Self-Service Password Reset abused in Azure data-theft attacks; FBI crypto-ATM scam losses |
| 🟡 **MEDIUM** | Persistent use of phishing as a common tactic across various campaigns | Dragonica Lunaris and Windows93 breach disclosures; Porter W Yett Qilin victim posting |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **Qilin** (115 reports) — Top-ranked actor in the pipeline; sustained RaaS victim posting, including both new victims in this 24-hour window
- **Akira** (64 reports) — Continues high-volume activity; historically linked to SonicWall SSL-VPN abuse pattern that mirrors today's CVE-2024-12802 reporting
- **The Gentlemen** (56 reports) — Ongoing campaign presence; no new postings tied to this window
- **TeamPCP** (32 reports) — Anchors the software-supply-chain trend (PyPI, npm, GitHub)
- **ShinyHunters** (31 reports) — Persistent extortion / data-broker activity
- **Lockbit5** (26 reports) — Continued affiliate operations
- **Inc Ransom** (26 reports) — Steady tempo
- **Safepay** (19 reports) — Phishing-aligned campaigns
- **DragonForce** (18 reports) — Multi-sector ransomware operations
- **Everest** (18 reports) — Periodic high-impact victim disclosures

### Malware Families

- **RansomLook** (133 reports) — Tracker tag, reflects the volume of leak-site sourced reporting rather than a malware family
- **Akira ransomware** (36 reports) — Top non-tracker family entry
- **Tox1** (32 reports) — Communication channel/tag associated with multiple groups
- **Akira** (20 reports) — Combined Akira-tagged reporting
- **Other1** (20 reports) — Generic / unclassified family tag
- **Tox** (19 reports) — Tox messaging artefact
- **Qilin** (15 reports) — Qilin-as-family / payload-tagged reports
- **RaaS** (14 reports) — Generic Ransom-as-a-Service tag
- **The Gentlemen** (12 reports) — Family/branding tag
- **Akira Ransomware** (12 reports) — Variant tag

*No vulnerability entities were returned by the trending-entities query for this window. Vulnerability detail in this brief is sourced from the SonicWall priority item (CVE-2024-12802).*

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| BleepingComputer | 2 | [link](https://www.bleepingcomputer.com/news/security/hackers-bypass-sonicwall-vpn-mfa-due-to-incomplete-patching/) | Primary coverage of SonicWall in-the-wild exploitation and Ukraine infostealer takedown |
| HaveIBeenPwned | 2 | [link](https://haveibeenpwned.com/Breach/Dragonica) | Account-breach disclosures (Dragonica Lunaris, Windows93) |
| RansomLook | 2 | [link](https://www.ransomlook.io//group/qilin) | Qilin leak-site tracking (Hamer Childs, Porter W Yett) |
| Wired Security | 2 | [link](https://www.wired.com/story/the-eu-is-going-through-a-trump-fueled-breakup-with-big-tech/) | Policy/governance items (EU–US tech decoupling, ALPR amendment) |
| SANS | 1 | [link](https://isc.sans.edu/diary/rss/33000) | ISC Stormcast podcast, threat level green |
| Sysdig | 1 | [link](https://webflow.sysdig.com/blog/introducing-the-runtime-threat-detection-and-response-skill-for-headless-cloud-security) | Vendor announcement: runtime threat-detection skill for headless cloud |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Verify SonicWall Gen6 SSL-VPN remediation is **complete** — not merely the firmware update — and execute the LDAP reconfiguration steps listed in SonicWall's CVE-2024-12802 advisory. Add `sess="CLI"` detection on VPN logs and prioritise hunts for VPN-to-RDP pivots within 60 minutes of authentication (ref. 3.1).
- 🟠 **SHORT-TERM:** Implement session-token risk scoring (ASN / geo / device-fingerprint change mid-session) to compensate for the MFA-bypass capability the Ukrainian infostealer operation demonstrated at scale; force step-up auth on payment-instrument or shipping-address changes for retail platforms (ref. 3.2).
- 🟠 **SHORT-TERM:** Push the Qilin IOC pack (`.onion` leak URLs, `31.41.244[.]100`, ransom-note filename patterns, Tox/Jabber identifiers) to egress filters, DNS sinkholes, and file-share monitoring rules; alert on any outbound Tox or Jabber from enterprise endpoints (ref. 3.3).
- 🟡 **AWARENESS:** Ingest the Dragonica Lunaris (126k bcrypt) and Windows93 (46k plain-text) datasets into your IdP leaked-credential workflow and notify any matching workforce/customer accounts. Prioritise the plain-text Windows93 list for active credential-stuffing watch (ref. 3.4).
- 🟢 **STRATEGIC:** Bring software-supply-chain monitoring (PyPI / npm / GitHub) into the threat model — the high-risk trend around TeamPCP-led ecosystem compromise has been sustained across the last three correlation batches and is the dominant non-ransomware theme in the pipeline (ref. §4).

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 10 reports processed across 2 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
