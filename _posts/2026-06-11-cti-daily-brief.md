---
layout: post
title:  "CTI Daily Brief: 2026-06-11 - CISA KEV adds CVE-2026-10520 Ivanti Sentry and CVE-2026-35273 Oracle PeopleSoft under active exploitation; phpBB decade-old auth bypass; 400+ Arch Linux packages backdoored"
date:   2026-06-12 20:10:00 +0000
description: "Two CISA KEV additions under active exploitation (Ivanti Sentry, Oracle PeopleSoft), a critical decade-old phpBB auth bypass, an Arch Linux AUR supply-chain compromise distributing an eBPF rootkit and infostealer, and sustained ShinyHunters / DragonForce / M3rx ransomware extortion against telecoms, retail and manufacturing."
category: daily
tags: [cti, daily-brief, shinyhunters, dragonforce, ivanti, cve-2026-10520, cve-2026-35273, arch-linux, phpbb]
classification: TLP:CLEAR
reporting_period: "2026-06-11"
generated: "2026-06-12"
draft: true
severity: critical
report_count: 71
sources:
  - BleepingComputer
  - CISA
  - Microsoft
  - RecordedFutures
  - SANS
  - Schneier
  - Wiz
  - RansomLook
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-06-11 (24h) | TLP:CLEAR | 2026-06-12 |

## 1. Executive Summary

The pipeline processed 71 reports in the last 24 hours across 12 sources, dominated by ransomware leak-site activity (RansomLook: 36 reports) and patch/exploitation news from BleepingComputer (10 reports). The day's defining theme is active exploitation of enterprise edge software: CISA issued its first Binding Operational Directive 26-04 enforcement, ordering federal agencies to patch Ivanti Sentry CVE-2026-10520 within three days after Shadowserver observed mass exploitation of exposed gateways, and added Oracle PeopleSoft Enterprise PeopleTools CVE-2026-35273 (missing authentication) to the KEV catalogue. A 10-year-old authentication bypass in phpBB (≤ 3.3.16 / 4.0.0-a2) was disclosed, allowing single-request impersonation of any administrator. A large Arch Linux supply-chain compromise pushed an eBPF rootkit and developer-credential infostealer through 400+ AUR packages via the malicious `atomic-lockfile` npm dependency. Ransomware crews ShinyHunters (American Tower, JCPenney, Madison Square Garden Sports, Zayo/Allstream, Ralph Lauren, Nexstar), DragonForce, M3rx, Dire Wolf and Nightspire continued double-extortion postings across telecoms, retail, manufacturing and hospitality.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 3 | phpBB decade-old auth bypass; CISA BOD 26-04 / Ivanti Sentry CVE-2026-10520; Windows Win32k EoP walkthrough |
| 🟠 **HIGH** | 40 | ShinyHunters, DragonForce, M3rx, Dire Wolf, Nightspire, Qilin, Akira, Inc Ransom leak posts; CISA KEV add (Oracle PeopleSoft); Arch Linux AUR compromise; French govt Tchap breach; Conti guilty plea; Snappy CVEs |
| 🟡 **MEDIUM** | 13 | Novo Nordisk clinical-trial breach; Coupang $409M fine; Kyushu Electric lost drive (10.9M records); Maine breach portal abuse; Apache mod_http2 DoS (CVE-2026-49975); FISA 702 lapse |
| 🟢 **LOW** | 3 | Microsoft WUSA installer fix; Telegram proxy posts |
| 🔵 **INFO** | 12 | SANS ISC Stormcast; Wiz OMB M-26-14 logging mandate analysis; Schneier commentary |

## 3. Priority Intelligence Items

### 3.1 CISA orders three-day patch of actively exploited Ivanti Sentry CVE-2026-10520

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/cisa-gives-feds-3-days-to-patch-ivanti-flaw-exploited-in-attacks/)

CISA published the first enforcement of Binding Operational Directive 26-04 (which supersedes BOD 19-02 and BOD 22-01), ordering Federal Civilian Executive Branch agencies to patch Ivanti Sentry CVE-2026-10520 within three days and added the flaw to the Known Exploited Vulnerabilities catalogue. The vulnerability is a maximum-severity OS command-injection weakness in Ivanti's security gateway appliance (formerly MobileIron Sentry). Ivanti's original advisory stated no in-the-wild exploitation, but one day after patches shipped Shadowserver reported "a large amount of Ivanti Sentry CVE-2026-10520 exploitation attempts based on the public PoC" and warned that unpatched instances are "most likely compromised." Shadowserver tracks ~50 exposed admin portals; the true exposure is higher because many instances block its scanner. CISA has flagged 35 Ivanti vulnerabilities historically, 12 of which were weaponised by ransomware crews.

**Affected:** Ivanti Sentry (formerly MobileIron Sentry) admin portals reachable from the internet. ATT&CK: T1071 - Application Layer Protocol; T1190 - Exploit Public-Facing Application.

> **SOC Action:** Immediately inventory all Ivanti Sentry / MobileIron Sentry appliances. Apply Ivanti's CVE-2026-10520 patch and assume compromise on any internet-exposed instance not patched on day-zero. Hunt EDR/proxy logs for outbound connections from Sentry appliances to unfamiliar IPs, anomalous shell processes (`sh`, `bash`, `nc`, `python`) spawned by the Sentry web service, and new SSH keys or local accounts on the appliance. Restrict admin portal exposure to a management VLAN. FCEB agencies: BOD 26-04 deadline is Sunday.

### 3.2 CISA adds Oracle PeopleSoft CVE-2026-35273 to KEV (missing authentication)

**Source:** [CISA](https://www.cisa.gov/news-events/alerts/2026/06/12/cisa-adds-one-known-exploited-vulnerability-catalog)

CISA added CVE-2026-35273 — a Missing Authentication for Critical Function flaw in Oracle PeopleSoft Enterprise PeopleTools — to the KEV catalogue based on evidence of active exploitation. CISA's correlated pipeline data ties this to ongoing reports that Oracle is mitigating a PeopleSoft zero-day exploited in data-theft attacks. Under BOD 26-04, FCEB agencies must prioritise remediation on publicly exposed assets where exploitation grants full asset control.

**Affected:** Oracle PeopleSoft Enterprise PeopleTools deployments, particularly internet-facing campus/HR/finance modules common in public sector and higher education.

> **SOC Action:** Identify all PeopleTools instances and apply Oracle's mitigations / current CPU. For internet-facing PeopleSoft front-ends, audit web access logs for unauthenticated requests to administrative endpoints (look for HTTP 200 responses to /psp/, /psc/, IScript and PeopleCode invocation URLs without a valid PS_TOKEN cookie). Capture and preserve middle-tier (Tuxedo) and PIA logs in case retroactive IR is required.

### 3.3 phpBB: decade-old authentication bypass in versions ≤ 3.3.16 and 4.0.0-a2

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/phpbb-forum-fixes-auth-bypass-bug-lurking-for-a-decade/)

Aikido Security disclosed an authentication bypass introduced into phpBB's codebase approximately 10 years ago. A single HTTP request against a default-configuration installation lets an attacker log in as any user, including administrators, without prior knowledge or special configuration. phpBB shipped a fix on 6 June in version 3.3.17; no safe 4.x release is available yet — the 4.0.0-a2 branch requires upgrading to `master`. The flaw has no CVE identifier at time of writing. RCE is not possible due to a separate Admin Control Panel password check, but admin login grants access to all private messages, content / account modification, staff impersonation, and defacement. Member lists are public by default, making victim selection trivial. Aikido withheld technical details and contacted operators of large phpBB forums directly. Updating may break OAuth login due to a relocated redirect handler. ATT&CK: T1078 - Valid Accounts; T1190 - Exploit Public-Facing Application.

**Affected:** phpBB 3.x ≤ 3.3.16 and 4.0.0-a2; thousands of community forums still on legacy versions.

> **SOC Action:** For any phpBB instance the organisation operates or sponsors, upgrade 3.x → 3.3.17 today, or pull `master` for 4.x deployments. Pull the last 30 days of authentication logs and review for successful logins to administrator accounts from unfamiliar IPs or with no preceding password-prompt flow. Reset all administrator passwords and rotate any OAuth client secrets after upgrade. Where forums host federation with corporate SSO, audit linked accounts for unauthorised privilege use.

### 3.4 Arch Linux AUR: 400+ packages backdoored with eBPF rootkit and developer infostealer

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/over-400-arch-linux-packages-compromised-to-push-rootkit-infostealer/)

The Independent Federated Intelligence Network (IFIN) and Sonatype reported that over 400 packages in the Arch User Repository (AUR) were modified to push a Linux rootkit and infostealer. Attackers spoofed a trusted publisher and hijacked at least 20 orphaned packages, editing PKGBUILD files to add preinstall and post-install scripts that fetch the malicious `atomic-lockfile` npm package. `atomic-lockfile` drops an ELF binary (`deps`) described as a "credential stealer with optional root-only eBPF rootkit capabilities." The rootkit can hide processes, files, and network interfaces from userland. Infostealer targets include GitHub credentials, SSH artefacts, HashiCorp Vault tokens, browser cookie databases, Slack, Discord, Microsoft Teams, Telegram, npm, Docker / Podman, VPN material and shell histories. The payload includes multi-part archiving and HTTP upload exfiltration. AUR maintainers are reverting commits and banning the offending accounts. ATT&CK: T1195.002 - Compromise Software Supply Chain; T1068 - Exploitation for Privilege Escalation; T1071.001 - Application Layer Protocol: Web Protocols; T1556 - Modify Authentication Process.

**Affected:** Developer workstations and build agents running Arch Linux or Arch-based distros (Manjaro, EndeavourOS, Garuda) that installed any of the 400+ affected AUR packages since the takeover window.

#### Indicators of Compromise

```
Malicious npm package: atomic-lockfile
Dropped binary: deps (Linux ELF, eBPF rootkit + infostealer)
Targeted credential stores: GitHub, SSH keys, Vault tokens, browser cookies,
                            Slack, Discord, Teams, Telegram, npm, Docker, VPN
Persistence: PKGBUILD preinstall + post-install scripts invoking npm
```

> **SOC Action:** Block `atomic-lockfile` at the npm proxy and any internal registry mirrors. On Arch / Arch-derivative endpoints, list AUR-installed packages (`pacman -Qm`) and cross-check against the AUR's published list of reverted commits; reinstall flagged packages from the cleaned source. Hunt for ELF processes named `deps` in unusual paths, unexpected `bpf()` syscalls from non-system binaries, and outbound HTTP POSTs containing multi-part uploads from developer endpoints. Rotate credentials for GitHub, npm, Slack, Vault, SSH and cloud CLIs on any potentially affected workstation. Treat compromise of a developer workstation as a precursor to source-code or CI/CD intrusion (T1195).

### 3.5 ShinyHunters extortion wave hits telecoms, retail and live entertainment

**Source:** [RansomLook (Shinyhunters)](https://www.ransomlook.io//group/shinyhunters)

The correlation engine clustered six ShinyHunters leak-site posts within the last 24 hours with 0.90 confidence on shared actor / RansomLook tooling and TTPs (T1566 - Phishing, T1485 - Data Encrypted for Impact). Listed victims include American Tower Corporation (telecom infrastructure), Zayo.com and Allstream.com (telecom / connectivity), JCPenney plus other Catalyst Brands and Authentic Brands Group subsidiaries (retail), Madison Square Garden Sports Corp (live entertainment), Ralph Lauren Corporation (apparel retail) and Nexstar.tv (media). The group continues to operate phishing-led intrusions, encryption and Tor-hosted leak-site / negotiation infrastructure with multiple `.onion` rotations.

**Affected sectors:** US-headquartered telecommunications, retail apparel, live entertainment and media.

> **SOC Action:** For telecom, retail and entertainment SOCs, prioritise phishing-resistant MFA on all internet-facing identity surfaces (M365, Okta, Citrix, VPN, RMM). Hunt M365 sign-in logs for impossible-travel and consent-grant anomalies; review token lifetime policies. Block known ShinyHunters extortion-mail patterns at the secure email gateway and confirm dark-web monitoring coverage for the named subsidiaries. If any of the named organisations is a vendor or partner, request fresh assurance on data-handling and incident notification before scheduled data exchanges.

### 3.6 French government Tchap messenger breach exposes 73,467 employee accounts

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/french-govt-says-tchap-breach-affected-over-73-000-accounts/)

France's digital affairs directorate (DINUM) disclosed that 73,467 public-sector users — approximately 9% of registered accounts — were affected by a breach of the Matrix-based Tchap encrypted messenger. The attacker compromised a single user account via social engineering and scraped all data shared in public (unencrypted) chat rooms: first/last name, email address, employing entity and avatar. The threat actor publicly claimed approximately 650,000 messages, 13.5 GB of documents and media, and a PowerShell script leaking hardcoded LDAP credentials. Private encrypted conversations were not exposed. DINUM identified and blocked the compromised account; CNIL has been notified. Tchap was made the default communications tool for all French civil servants in August 2025 and now reaches 300,000+ monthly users.

**Affected:** French central government, ANSSI-affiliated agencies and public-sector organisations using Tchap. ATT&CK: T1566 - Phishing; T1078 - Valid Accounts.

> **SOC Action:** Government and partner organisations should treat exposed names + entity affiliations as primary spear-phishing targeting data for the next 90+ days. Brief affected staff to expect French-language pretext phishing referencing Tchap, DINUM or their specific ministry. Review any cross-trust integrations or shared-channel arrangements with French public-sector counterparts. For any organisation operating its own Matrix homeserver, audit public room membership policies and rotate any LDAP service-account credentials referenced from automation scripts.

### 3.7 Conti loader developer pleads guilty; DOJ tally exceeds 1,000 victims, $150M ransom

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/ukrainian-national-pleads-guilty-to-role-in-conti-ransomware-operation/)

Ukrainian national Oleksii Oleksiyovych Lytvynenko, extradited from Ireland in 2023, pleaded guilty to conspiracy to commit wire fraud in the Conti ransomware operation. According to DOJ filings he joined Conti in approximately September 2021, possessed stolen data from eight US and four overseas victims, and coded a "loader" used to stage Conti payloads. Court documents cite Conti's lifetime impact as 1,000+ victims and over $150 million in extortion payments. He faces up to 20 years. Conti emerged from Ryuk and was tightly linked to the TrickBot syndicate; following its 2022 shutdown, former operators are believed to have splintered into BlackCat, Black Basta, ZEON, Hive, Quantum, BlackByte, Karakurt and Silent Ransom Group.

**Affected:** Operational law-enforcement signal; strategic relevance to threat actors descended from Conti/TrickBot.

> **SOC Action:** This is a strategic signal rather than a detection trigger. Use the named successor groups (Black Basta, BlackCat, Quantum, Karakurt, Silent Ransom Group) to validate detection coverage against current Conti-lineage TTPs: TrickBot-derived loaders, BazarLoader-style HTTP C2, Cobalt Strike, ESXi targeting, and dual-extortion data theft via Rclone/MEGA. Brief leadership on the continued legal pressure on former Conti operators.

### 3.8 Microsoft June Patch Tuesday: Snappy CVE-2026-46683 (SSRF/local file read) and CVE-2026-46643 (binary path shell injection)

**Source:** [Microsoft MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-46683)

Two high-severity vulnerabilities were published in the Snappy library: CVE-2026-46683 allows server-side request forgery and local file read via the `xsl-style-sheet` option, and CVE-2026-46643 leaves the binary path un-shell-escaped due to an inverted `is_executable` check, opening a path to arbitrary command execution. The correlation engine linked CVE-2026-46643 to the Oracle PeopleSoft zero-day activity through a shared T1071 (Application Layer Protocol) TTP profile. A separate Apache CVE — CVE-2026-49975, a mod_http2 denial-of-service — was disclosed at medium severity.

**Affected:** Applications and document-generation pipelines that embed the Snappy library (commonly used to convert HTML to PDF via wkhtmltopdf wrappers).

> **SOC Action:** Inventory dependencies for any Snappy / wkhtmltopdf usage in reporting, invoicing or PDF-export services. Disable the `xsl-style-sheet` option where unused, and validate / allowlist binary paths passed to Snappy. For Apache instances, plan mod_http2 patching on the next maintenance window and consider rate-limiting HTTP/2 streams as a stop-gap.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Exploitation of vulnerabilities in widely-used software and platforms | CVE-2026-49975 Apache mod_http2 DoS; CVE-2026-46683 Snappy SSRF/LFI; Oracle PeopleSoft zero-day (CVE-2026-35273 KEV) |
| 🟠 **HIGH** | Sustained ransomware activity with double-extortion focus | ShinyHunters (American Tower, JCPenney, MSG Sports, Zayo/Allstream); Nightspire (Pattono, Sierra West) |
| 🟠 **HIGH** | Ransomware-as-a-Service consolidation; multi-victim same-actor postings | DragonForce (Areco, Cekok, Hong Kong Parkview, Al Shafar GRC, A. Liberty Engineering, Al Ishrak, Corniche Hotel Abu Dhabi); Dire Wolf (Clínica Vida, Jewelex, Nueva Pescanova, Did Asia) |
| 🟠 **HIGH** | M3rx leak-post cluster targeting industrial / consulting sectors | werkstoff-service.de, fasadeconsult.no, maringoodman.com, ktwhs.com, suppcenter.global, hbexperts-conseils.ca |
| 🟠 **HIGH** | Geopolitical shift: state-aligned groups pivoting to domestic targeting | OceanLotus: From external espionage to domestic targeting (Vietnam) |
| 🟠 **HIGH** | Supply-chain / package-ecosystem compromise as initial access | Arch Linux AUR (400+ packages, atomic-lockfile npm); BleepingComputer dark-web supply-chain warning |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **Qilin** (85 reports) — RaaS operator; sustained leak-site activity, latest victim DISTINET MURCIA SL
- **The Gentlemen** (53 reports) — RansomLook-tracked extortion crew
- **DragonForce** (45 reports) — RaaS-cartel evolved from hacktivism; multi-victim postings in retail, hospitality, construction
- **Akira** (33 reports) — Double-extortion; VPN/RDP initial access on Windows/Linux; `.akira` extension
- **TeamPCP** (27 reports) — RansomLook leak-site activity
- **Nightspire** (22 reports) — Multi-channel extortion; Telegram, Tox, email demand chains
- **Nova** (22 reports) — Emerging extortion actor
- **ShinyHunters** (21 reports) — Phishing-led intrusions; current wave against telecom and retail
- **Lockbit5** (20 reports) — LockBit successor branding
- **Stormous** (18 reports) — Continued leak-site activity

### Malware Families

- **RansomLook** (111 reports) — Aggregator-tagged generic RaaS payloads across leak-site postings
- **Tox1 / Tox** (34 / 21 reports) — Extortion negotiation channel artefact
- **Akira ransomware** (17 reports) — Windows + Linux variants; `.akira` extension; CryptoAPI
- **Mini Shai-Hulud** (13 reports) — npm worm variant
- **Shai-Hulud** (12 reports) — npm supply-chain worm
- **RALord** (12 reports) — Ransomware leak-site brand

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| RansomLook | 36 | [link](https://www.ransomlook.io/) | Dominant feed of ransomware leak-site postings |
| Unknown / Telegram | 11 | — | Telegram proxy posts and one Windows Win32k EoP walkthrough; not linked per policy |
| BleepingComputer | 10 | [link](https://www.bleepingcomputer.com/news/security/cisa-gives-feds-3-days-to-patch-ivanti-flaw-exploited-in-attacks/) | Primary coverage of CISA/Ivanti, phpBB, Arch Linux, Tchap, Conti |
| RecordedFutures | 3 | [link](https://therecord.media/) | 23andMe settlement, Coupang fine, FISA 702 lapse |
| Microsoft | 3 | [link](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-46683) | Snappy CVEs, Apache mod_http2 DoS |
| Wiz | 2 | [link](https://www.wiz.io/blog/navigating-the-new-federal-logging-mandate-or-omb-memorandum-m-26-14) | OMB M-26-14 federal logging mandate analysis |
| CISA | 1 | [link](https://www.cisa.gov/news-events/alerts/2026/06/12/cisa-adds-one-known-exploited-vulnerability-catalog) | KEV add: CVE-2026-35273 Oracle PeopleSoft |
| SANS | 1 | [link](https://isc.sans.edu/diary/rss/33074) | ISC Stormcast 12 June |
| BellingCat | 1 | [link](https://www.bellingcat.com/) | OSINT analysis |
| Upwind | 1 | [link](https://www.upwind.io/) | Cloud security commentary |
| Schneier | 1 | [link](https://www.schneier.com/) | Policy commentary (Sanders AI sovereign wealth fund) |
| Sysdig | 1 | [link](https://sysdig.com/) | Container security commentary |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Patch Ivanti Sentry CVE-2026-10520 today and assume compromise on any unpatched internet-exposed instance; FCEB agencies are bound by BOD 26-04 with a Sunday deadline. Triage for forensic preservation before patching.
- 🔴 **IMMEDIATE:** Apply Oracle PeopleSoft mitigations for CVE-2026-35273 and audit web-tier logs on any internet-facing PeopleSoft front-end for unauthenticated access to administrative endpoints.
- 🔴 **IMMEDIATE:** Upgrade phpBB to 3.3.17 (or `master` for 4.x) on every operated or sponsored forum and reset administrator credentials post-patch; review the last 30 days of admin logins for impossible-source anomalies.
- 🟠 **SHORT-TERM:** Sweep Arch Linux / Arch-derivative developer endpoints for the `atomic-lockfile` npm package, the `deps` ELF binary and unexpected `bpf()` syscalls; rotate developer cloud, source-control, Slack, Vault and SSH credentials on any potentially affected workstation and treat as a precursor to source-code intrusion.
- 🟠 **SHORT-TERM:** For US telecoms, retail and live-entertainment SOCs, harden phishing-resistant MFA on all identity surfaces and validate dark-web monitoring coverage in response to the ShinyHunters extortion wave against American Tower, JCPenney, MSG Sports, Zayo, Ralph Lauren and Nexstar.
- 🟡 **AWARENESS:** Brief affected French public-sector contacts and integrators on Tchap-themed spear-phishing risk over the next quarter; review any LDAP service-account credentials referenced from PowerShell automation.
- 🟢 **STRATEGIC:** Use the Conti loader-developer guilty plea to validate detection coverage against current Conti-lineage successor groups (Black Basta, BlackCat, Quantum, Karakurt, Silent Ransom Group) — TrickBot/BazarLoader-style loaders, Cobalt Strike, ESXi targeting and Rclone/MEGA exfiltration.

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 71 reports processed across 3 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
