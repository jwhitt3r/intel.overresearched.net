---
layout: post
title:  "CTI Daily Brief: 2026-06-07 — Qilin Exploits Check Point VPN Zero-Day; Critical Gogs & UniFi RCE Chains; TeamPCP Supply-Chain Worms Hit npm After CISA KEV Listing"
date:   2026-06-08 20:30:00 +0000
description: "52 reports across 10 sources. Qilin ransomware tied to Check Point VPN zero-day (CVE-2026-50751); unauthenticated UniFi OS root chain (CVE-2026-34908/9/10); Gogs argument-injection RCE; TeamPCP Mini Shai-Hulud framework seeds Miasma/Phantom Gyp worms across npm; WhatsApp disrupts new NSO Pegasus phishing wave."
category: daily
tags: [cti, daily-brief, qilin, the-gentlemen, nso-group, teampcp, cve-2026-50751, cve-2026-34908, mini-shai-hulud]
classification: TLP:CLEAR
reporting_period: "2026-06-07"
generated: "2026-06-08"
draft: false
report_count: 52
severity: critical
sources:
  - BleepingComputer
  - RansomLook
  - RecordedFutures
  - SANS
  - Schneier
  - Wired Security
  - RedCanary
  - Microsoft
  - Wiz
  - Crowdstrike
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-06-07 (24h) | TLP:CLEAR | 2026-06-08 |

## 1. Executive Summary

The pipeline ingested 52 reports across 10 sources, dominated by a heavy ransomware victim cadence (31 RansomLook entries) and four critical vulnerability disclosures. The headline story is **Check Point's confirmation that the Qilin ransomware affiliate has been exploiting CVE-2026-50751**, an unauthenticated authentication-bypass in Remote Access / Mobile Access VPN deployments using deprecated IKEv1 — active in the wild since 7 May, surged in early June. Two further critical RCE chains landed the same day: an **unauthenticated UniFi OS root-shell chain (CVE-2026-34908, -34909, -34910)** validated by Bishop Fox, and a **Gogs argument-injection zero-day** affecting all 2,300+ internet-exposed instances. SANS confirms CISA added TeamPCP supply-chain CVEs (CVE-2026-45321, CVE-2026-48027) to the **KEV catalogue on 27 May with a 10 June federal remediation deadline**, and the leaked Mini Shai-Hulud framework has now seeded Miasma/Phantom Gyp credential-stealing worms across @redhat-cloud-services and 57 additional npm packages. Qilin (5 victims) and "The Gentlemen" (15 victims) dominated extortion-site activity.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 4 | Check Point VPN zero-day (Qilin); UniFi OS unauth RCE chain; Gogs zero-day; Zcash Orchard ZK-proof flaw |
| 🟠 **HIGH** | 33 | Qilin + The Gentlemen + Nightspire victim posts; TeamPCP/Mini Shai-Hulud npm worms; NSO Pegasus phishing; Meta AI Instagram hijacks |
| 🟡 **MEDIUM** | 5 | Oxford University CareerConnect breach; Ransomhouse activity; Entra Agent ID OBO abuse |
| 🔵 **INFO** | 10 | Russia SORM expansion; Meta NameTag removal; Anthropic Project Glasswing; CVE-2026-35429 (Edge spoofing) |

No "low" severity items were posted in this 24-hour window.

## 3. Priority Intelligence Items

### 3.1 Check Point VPN Zero-Day Exploited by Qilin Ransomware (CVE-2026-50751)

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/check-point-links-vpn-zero-day-attacks-to-qilin-ransomware-gang/)

Check Point Research confirmed in-the-wild exploitation of CVE-2026-50751, a critical authentication-bypass affecting Remote Access VPN, Mobile Access SSL VPN, and Spark firewall deployments configured for the deprecated IKEv1 key exchange. Unauthenticated remote attackers can bypass authentication and establish a remote-access VPN session. Activity began 7 May, surged in early June, and has affected "a few dozen" organisations globally — at least one incident is **confirmed post-compromise activity by a Qilin ransomware affiliate**. A second flaw discovered during investigation, **CVE-2026-50752**, enables MitM attacks against site-to-site VPN certificate validation; no in-the-wild exploitation observed yet. Qilin (active since August 2022 as "Agenda") has claimed ~400 victims and was tied to five fresh victim posts in the same 24-hour window (Opera Comique, SatCom CX, Isuzu Motors, Shipping Association of NY/NJ).

**Affected:** Check Point Remote Access VPN, Mobile Access SSL VPN, Spark firewalls (IKEv1 configurations).
**MITRE ATT&CK:** T1078 (Valid Accounts), T1550.002 (Use Alternate Authentication Material).

> **SOC Action:** Apply Check Point hotfixes immediately. Where patching is delayed, disable legacy Remote Access client support, force IKEv2-only authentication, set Machine Certificate Authentication to mandatory, and enable IPS with current signatures. Hunt for anomalous VPN sessions from IKEv1 endpoints over the past 30 days; pivot any matches against Qilin TTPs (lateral movement via valid accounts, RaaS encryptor with .qilin extension).

### 3.2 Unauthenticated UniFi OS Root-Shell Chain (CVE-2026-34908 / -34909 / -34910)

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/critical-unifi-os-bug-lets-hackers-gain-root-without-authentication/)

Bishop Fox validated a three-vulnerability chain in Ubiquiti UniFi OS Server ≤ 5.0.6 that yields unauthenticated remote root. CVE-2026-34908 (improper access control) and CVE-2026-34909 (path traversal) bypass authentication via a mismatch between the auth component's raw-URI evaluation and Nginx's normalised routing; CVE-2026-34910 (command injection) at the package-update endpoint executes arbitrary shell, which then escalates trivially via a service account holding passwordless sudo. Ubiquiti's May advisory did not flag the chained-RCE outcome. UniFi OS Server is the **management plane for physical-access doors, surveillance cameras, and identity systems** — root on the appliance equals administrative control over the whole console.

**Affected:** Ubiquiti UniFi OS Server ≤ 5.0.6.
**MITRE ATT&CK:** T1190 (Exploit Public-Facing Application), T1064 (Scripting), T1071 (Application Layer Protocol).

> **SOC Action:** Upgrade UniFi OS Server beyond 5.0.6 immediately. Run Bishop Fox's free detection script against all UniFi OS Server instances (it classifies vulnerable/patched/unaffected without executing payloads). Note: the script does **not** detect prior compromise — for any system that was internet-exposed pre-patch, assume potential historical exploitation, audit `/var/log/nginx/*.log` for URI-normalisation anomalies, review service-account `sudo` history, and check for backdoor accounts on dependent UniFi access-control and camera devices.

### 3.3 Gogs Critical Zero-Day Argument Injection RCE

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/gogs-patches-critical-zero-day-enabling-remote-code-execution/)

Rapid7's Jonah Burgess disclosed an argument-injection flaw in the `Merge()` function of Gogs (≤ 0.14.2 and 0.15.0+dev) that enables authenticated RCE without admin rights. Because Gogs ships with `DISABLE_REGISTRATION = false` and `MAX_CREATION_LIMIT = -1` by default, an unauthenticated attacker on a default-configured instance can register an account, create a repository, toggle rebase-merging, and operate the full exploit chain without any second-user interaction. The flaw is a sibling of previously patched argument-injection bugs (CVE-2024-39933, CVE-2024-39932, CVE-2026-26194, CVE-2024-39930) that struck a different code path. Shadowserver currently tracks **2,300+ internet-exposed Gogs servers** (1,839 in Asia, 312 in Europe). Patched in Gogs 0.14.3 (PR #8301); CVE pending.

**MITRE ATT&CK:** T1078 (Valid Accounts), T1203 (Exploitation for Client Execution), T1550.003 (Use Alternate Authentication Material).

> **SOC Action:** Upgrade Gogs to 0.14.3 today. If patching is blocked, set `DISABLE_REGISTRATION = true` and `MAX_CREATION_LIMIT = 0` in `app.ini` immediately — these are the only mitigations effective against the unauthenticated path. Audit recent registrations against legitimate developer accounts, check `git config receive.denyDeletes`, and review CI tokens and SSH keys stored in self-hosted Gogs instances for rotation.

### 3.4 TeamPCP Supply-Chain Campaign: CISA KEV Listings & Mini Shai-Hulud Worm Wave

**Source:** [SANS Internet Storm Center](https://isc.sans.edu/diary/rss/33060)

SANS ISC confirms two compounding developments. **(1) CISA formally caught up to the campaign**: on 27 May it added **CVE-2026-45321** (TanStack / Mini Shai-Hulud tracking ID) and **CVE-2026-48027** (malicious code in Nx Console v18.95.0 build) to the KEV catalogue, alongside CVE-2026-8398 (DAEMON Tools Lite), with a **federal remediation due date of 10 June 2026**. CISA published its first standalone advisory the next day documenting the poisoned Nx Console VS Code extension auto-distributed via editor updates and the exfiltration of ~3,800 GitHub-internal repositories, plus a separate "Megalodon" campaign injecting malicious GitHub Actions workflows to harvest CI/CD secrets. **(2) The leaked Mini Shai-Hulud framework is now operational in third-party hands**: from 1 June a Wiz-named "Miasma" credential-stealing worm compromised dozens of @redhat-cloud-services npm packages, followed two days later by a "Phantom Gyp" variant hitting 57 additional packages. Vendors caution copycat use of the public toolkit cannot be ruled out.

**MITRE ATT&CK:** T1195.002 (Compromise Software Supply Chain), T1003 (OS Credential Dumping), T1190 (Exploitation for Client Execution), T1566 (Phishing).

> **SOC Action:** Meet the 10 June KEV deadline — uninstall Nx Console ≥ v18.95.0 from all developer workstations, pin to a known-clean version, and audit VS Code extension auto-update logs since the v18.95.0 release window. Query npm package-lock and yarn.lock files across CI/CD for any `@redhat-cloud-services` dependency installed after 1 June or any of the 57 Phantom Gyp packages. **Rotate every CI/CD-accessible secret** (cloud credentials, registry tokens, GitHub PATs, deploy keys) per CISA's advisory. Inspect public-repo GitHub Actions workflow files for unauthorised `pull_request_target` triggers and exfiltration steps writing to external URLs (Megalodon pattern).

### 3.5 WhatsApp Disrupts New NSO Pegasus Spear-Phishing Wave

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/whatsapp-says-it-disrupted-new-nso-spyware-phishing-attacks/), [The Record](https://therecord.media/whatsapp-says-nso-targeted-users-with-attacks-against-court-order)

Meta states it disrupted NSO Group-linked social-engineering attempts against WhatsApp users — links redirecting victims to external websites that mirror previously documented one-click Pegasus phishing patterns. Meta also identified and removed test accounts and groups created by the operators. Meta argues this activity **violates the 2025 permanent injunction** secured against NSO (which is currently under appeal alongside the $167M judgment). NSO remains on the US Entity List since November 2021.

**Affected:** High-interest individuals (politicians, journalists, activists, academics).
**MITRE ATT&CK:** T1566.002 (Spearphishing Link).

#### Indicators of Compromise

```
Domain: ikhwancast[.]com
Domain: ghazacast[.]com
Domain: fr24cast[.]com
```

> **SOC Action:** Block the three Meta-published domains at egress and DNS. For executive-protection or high-risk user populations, mandate Android Advanced Protection or iOS Lockdown Mode, ensure WhatsApp and OS are on the latest releases, and run a 90-day retro-hunt for DNS resolution or HTTPS connections to the three domains (Pegasus historically uses one-click variants alongside zero-click chains).

### 3.6 Meta AI "High Touch Support" Flaw — 20,000+ Instagram Account Hijacks

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/meta-ai-support-data-breach-affects-20-000-instagram-accounts/)

Meta confirmed in a Maine OAG filing that an authentication-check gap in its AI-assisted Instagram recovery tool ("High Touch Support" / HTS) allowed third parties to trigger password resets for accounts they did not own — **bypassing 2FA**. First exploitation traced to 17 April 2026; Meta discovered the flaw on 31 May. The HTS tool has been disabled, all generated reset links invalidated, and impacted accounts placed in a mandatory security checkpoint. Exposed data may include profile information, DMs, contact details, dates of birth, and linked-account references.

**MITRE ATT&CK:** T1078 (Valid Accounts), T1199 (Trusted Relationship — via support tooling).

> **SOC Action:** For organisations with Instagram presence (marketing, executive comms), audit account-takeover indicators on official Instagram accounts since 17 April: unexpected device sessions, DM activity, profile/bio modifications, and password-reset emails not initiated by the account owner. Treat any prior unattributable password-reset receipt in that window as a credible compromise signal and force a full credential rotation plus 2FA re-enrolment.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Exploitation of critical vulnerabilities across software platforms | Gogs zero-day RCE; UniFi OS unauthenticated root chain; PAN-OS CVE-2026-0257 active exploitation |
| 🟠 **HIGH** | Increased ransomware activity targeting multiple sectors with diverse TTPs | Qilin (Opera Comique, SatCom CX, Isuzu Motors, Shipping Assoc. NY/NJ, Check Point VPN nexus); The Gentlemen (WCM Remedium, The Clinic, 13+ more) |
| 🟠 **HIGH** | Phishing & spear-phishing as primary TTPs in geopolitical cyber operations | NSO/WhatsApp campaign; Armenia election Russia-linked Matryoshka influence op |
| 🟠 **HIGH** | RansomLook-payload campaign across textiles, retail, hospitality, healthcare | Hansoll Textile (Vietnam); Plaza Lama; Villea Hotels / AttanaHotels |
| 🟡 **MEDIUM** | T1078 Valid Accounts as cross-cutting initial-access pattern | Gogs RCE; Check Point VPN; Entra Agent ID OBO abuse; The Gentlemen ops; PAN-OS CVE-2026-0257 |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **Qilin** (73 reports, last seen 2026-06-08) — RaaS active since Aug 2022 as "Agenda"; tied to Check Point VPN zero-day exploitation this period
- **The Gentlemen** (57 reports) — high-volume extortion-site posts across healthcare, manufacturing, apparel, HR services; Trend Micro tracking confirmed
- **Akira** (34 reports) — Windows/Linux/ESXi double-extortion, $200K–$4M demands, VPN/RDP initial access
- **DragonForce** (33 reports) — continued multi-sector activity
- **TeamPCP** (30 reports) — supply-chain operator behind Mini Shai-Hulud; CISA KEV-listed
- **ShinyHunters** (24 reports) — data-theft / extortion brokerage
- **Nightspire** (20 reports, 4 new victims today) — multi-sector ransomware, Tor-based ops
- **NSO Group** — Pegasus operator; new WhatsApp campaign disrupted

### Malware Families

- **RansomLook** (106 reports) — overarching tracking taxonomy for victim-leak posts
- **Mini Shai-Hulud** (13 reports) — TeamPCP supply-chain framework, now open-sourced and weaponised by third parties (Miasma, Phantom Gyp)
- **Akira ransomware** (19 reports) — paired with VPN-credential abuse
- **Crux** — newly identified BlackByte-linked ransomware variant; uses svchost.exe + cmd.exe + bcdedit.exe to disable Windows recovery; .crux extension; Tor leak portal; confirmed active in agriculture, education, nonprofit sectors (US/UK)
- **Pegasus** — commercial spyware deployed via the disrupted NSO links above

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| RansomLook | 31 | [link](https://www.ransomlook.io/) | Victim-post aggregation across Qilin, The Gentlemen, Nightspire, payload, Akira, Black X, Morpheus, RansomHouse, BlackByte-Crux |
| BleepingComputer | 8 | [link](https://www.bleepingcomputer.com/news/security/check-point-links-vpn-zero-day-attacks-to-qilin-ransomware-gang/) | Lead coverage of Check Point/Qilin, UniFi, Gogs, NSO, Meta-AI, Oxford breach |
| RecordedFutures | 3 | [link](https://therecord.media/whatsapp-says-nso-targeted-users-with-attacks-against-court-order) | NSO court-order violation; Armenia disinformation; Russia SORM expansion |
| SANS | 2 | [link](https://isc.sans.edu/diary/rss/33060) | TeamPCP supply-chain update + ISC Stormcast |
| Schneier | 2 | [link](https://securityaffairs.com/193224/hacking/) | Zcash Orchard ZK-proof flaw; Anthropic Project Glasswing commentary |
| Wired Security | 2 | [link](https://www.wired.com/story/meta-removes-face-recognition-code-meta-ai-app-smart-glasses/) | Meta NameTag biometric removal; Europe ditching US tech |
| RedCanary | 1 | [link](https://redcanary.com/blog/threat-detection/entra-id-ai-workflows-assistive-agents/) | Microsoft Entra Agent ID OBO abuse pattern |
| Microsoft | 1 | [link](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-35429) | CVE-2026-35429 Edge for Android spoofing (informational) |
| Wiz | 1 | [link](https://www.wiz.io/blog/introducing-wiz-cloud-cost) | Product announcement (Cloud Cost) |
| Crowdstrike | 1 | [link](https://www.crowdstrike.com/en-us/blog/crowdstrike-zscaler-bring-continuous-identity-security-to-zero-trust-access/) | CrowdStrike–Zscaler identity integration |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Patch **Check Point Remote Access / Mobile Access / Spark VPN** for CVE-2026-50751 and CVE-2026-50752 today. If patching is delayed, disable legacy IKEv1 client support, enforce IKEv2-only authentication, mandate Machine Certificate Authentication, and enable IPS. Hunt the past 30 days of VPN auth logs for IKEv1 anomalies — Qilin is in the wild and pre-positioning.
- 🔴 **IMMEDIATE:** Upgrade **UniFi OS Server beyond 5.0.6** and **Gogs to 0.14.3**. Both are internet-exposed at scale (2,300+ Gogs instances on Shadowserver), both yield privileged code execution, and the UniFi chain reaches root without credentials.
- 🟠 **SHORT-TERM:** Meet the **CISA KEV 10 June federal deadline** for CVE-2026-45321 and CVE-2026-48027 (TeamPCP / Nx Console). Uninstall/pin Nx Console, audit npm dependencies for Miasma/Phantom Gyp infiltration since 1 June, and rotate every CI/CD-accessible secret per CISA's standalone advisory.
- 🟠 **SHORT-TERM:** Block the three NSO-linked domains (`ikhwancast[.]com`, `ghazacast[.]com`, `fr24cast[.]com`) at egress and DNS; enforce iOS Lockdown Mode or Android Advanced Protection on executive-protection mobile fleets.
- 🟡 **AWARENESS:** Qilin and "The Gentlemen" together posted 20+ new victims in this 24-hour window across healthcare, manufacturing, transport, and professional services — review third-party / supplier exposure and validate that VPN/RDP-facing assets are patched and MFA-protected (Qilin's preferred initial-access path).
- 🟢 **STRATEGIC:** With both NSO Pegasus (commercial spyware) and Meta's HTS (AI-assisted support) being abused against high-value targets, formalise an executive-protection programme covering personal-device hardening, secondary-channel account-recovery scrutiny, and quarterly review of all third-party support-system delegations (incl. Entra Agent ID OBO permissions per Red Canary's analysis).

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 52 reports processed across 2 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
