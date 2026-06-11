---
layout: post
title:  "CTI Monthly Report: May 2026 - Qilin-linked Check Point VPN zero-day, record 200-flaw Microsoft Patch Tuesday, ShinyHunters PeopleSoft mass extortion, Miasma/Shai-Hulud supply-chain wave"
date:   2026-06-11 09:30:00 +0000
description: "May 2026 monthly threat intelligence report: 2,621 reports across 50 correlation batches. Headlines include actively exploited Check Point VPN auth bypass (CVE-2026-50751) tied to Qilin affiliates; record-volume Microsoft June Patch Tuesday (200 flaws, 3 publicly disclosed zero-days); exploited Microsoft Exchange XSS zero-day (CVE-2026-42897, on CISA KEV); active PAN-OS GlobalProtect auth bypass (CVE-2026-0257); Chrome V8 zero-day (CVE-2026-11645); Ivanti Sentry max-severity RCE; Veeam Backup RCE; ShinyHunters mass-extorting 100+ Oracle PeopleSoft tenants (University of Nottingham, 454,635 accounts); deliberate leak of Miasma supply-chain worm source on GitHub; Krebs attribution of The Gentlemen RaaS administrator to Alexander Yapaev in Izhevsk, Russia."
category: monthly
tags: [cti, monthly-report, qilin, the-gentlemen, akira, shinyhunters, dragonforce, shai-hulud, miasma, cve-2026-50751, cve-2026-42897, cve-2026-0257, cve-2026-11645, cve-2026-44963, cve-2026-10520]
classification: TLP:CLEAR
reporting_period: "May 2026"
generated: "2026-06-11"
severity: "critical"
draft: true
report_count: 2621
sources:
  - Microsoft
  - RansomLook
  - BleepingComputer
  - AlienVault
  - CISA
  - RecordedFutures
  - SANS
  - Wired Security
  - Schneier
  - CertEU
  - Unit42
  - Krebs on Security
  - HaveIBeenPwned
  - Cisco Talos
  - Crowdstrike
---
| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| May 2026 (rolling 30-day window through 11 Jun 2026) | TLP:CLEAR | 11 Jun 2026 |

## 1. Executive Summary

May 2026 was the highest-volume operational month on record for the CognitiveCTI pipeline: 2,621 reports correlated across 50 batches, with 261 critical and 1,361 high-severity items. Five concurrent pressure fronts defined the month. First, perimeter and identity infrastructure was under sustained exploitation — Check Point Remote Access VPN (CVE-2026-50751, IKEv1 auth bypass, tied to Qilin ransomware affiliates), Palo Alto GlobalProtect / PAN-OS (CVE-2026-0257, KEV-listed May 29), Ivanti Sentry (CVE-2026-10520 max-severity OS command injection), Veeam Backup & Replication (CVE-2026-44963 domain RCE), Microsoft Exchange Server (CVE-2026-42897 XSS zero-day actively exploited and on CISA KEV), Fortinet FortiOS and Cisco SD-WAN. Second, Microsoft's June Patch Tuesday — covering the month's accrued CVE pipeline — was the largest ever at 200 flaws plus three publicly disclosed zero-days (CTFMON LPE, HTTP/2 Bomb DoS, BitLocker bypass) and a separately named YellowKey/GreenPlasma/MiniPlasma cluster. Third, the npm and PyPI ecosystems sustained an unprecedented wave of supply-chain worms: Shai-Hulud (TanStack, then 19 science/bioinformatics PyPI packages), Mini Shai-Hulud, IronWorm (36 packages), and Miasma (Red Hat Cloud Services, 73 Microsoft repos) — with the Miasma source code deliberately leaked on GitHub on June 10, expected to spawn variants. Fourth, ransomware-as-a-service operated at sustained tempo: Qilin (89 victim postings), The Gentlemen (61, with Krebs attributing the administrator to Alexander Andreevich Yapaev in Izhevsk, Russia), Akira (38), DragonForce (34), TeamPCP (29, supply-chain operator), ShinyHunters (23) — the last carrying out a mass-extortion campaign against 100+ Oracle PeopleSoft tenants including the University of Nottingham (454,635 accounts on HaveIBeenPwned). Fifth, China-nexus reconnaissance activity expanded materially: the JDY botnet (Volt Typhoon-adjacent) grew to 1,500+ compromised SOHO/IoT devices targeting US military networks, and TA4922 introduced Atlas RAT in European cyberattacks. A Chrome V8 zero-day (CVE-2026-11645, the fifth Chrome zero-day this year) was exploited in the wild. NSO Group's resumed WhatsApp spearphishing — disrupted by Meta in alleged violation of an existing court order — and the breach of the French government's Tchap messaging service round out the geopolitical signal. The combined picture: every category of perimeter and identity infrastructure (VPN, firewall, backup, mobile gateway, mail server, identity store) was hit by exploited or imminently exploitable critical flaws within a single 30-day window.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|------:|-------------|
| 🔴 **CRITICAL** | 261 | Microsoft June Patch Tuesday RCE backlog (Outlook/Word, Excel, RDP Client, NTFS, WinSock AFD LPE cluster); Check Point VPN bypass actively exploited (CVE-2026-50751); Ivanti Sentry CVE-2026-10520/10523; Veeam VBR CVE-2026-44963; PAN-OS CVE-2026-0257; npm Shai-Hulud / Mini Shai-Hulud / Laravel Lang supply chain; Chrome V8 zero-day CVE-2026-11645; UniFi OS unauthenticated root; Gogs zero-day; Cisco SD-WAN |
| 🟠 **HIGH** | 1,361 | Exchange Server CVE-2026-42897 zero-day on CISA KEV; ShinyHunters Oracle PeopleSoft mass extortion; The Gentlemen / Qilin / Akira / DragonForce victim postings; voicemail-phishing kit (SSO hijacking + RMM delivery); Silent Ransom Group fake-IT-support law-firm vishing; libexpat / OpenSC / Redis privesc CVEs; JDY botnet expansion; CISA Android (CVE-2025-48595) + Linux (CVE-2022-0492) KEV additions |
| 🟡 **MEDIUM** | 593 | Smaller RaaS affiliates (Nova, Lockbit5, Stormous, Inc Ransom, Safepay, Genesis); Telegram-proxy phishing; routine CVE disclosures; HTTP/2 Bomb DoS analysis |
| 🟢 **LOW** | 139 | Minor product advisories; isolated breach notifications |
| 🔵 **INFO** | 267 | ISC StormCast podcasts; DBIR commentary; vendor blog explainers |

## 3. Key Events

### 3.1 Microsoft June 2026 Patch Tuesday — record 200 flaws, three publicly disclosed zero-days

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/microsoft/microsoft-june-2026-patch-tuesday-fixes-3-zero-day-200-flaws/), [Recorded Future](https://therecord.media/microsoft-ships-largest-patch-tuesday-on-record), [SANS ISC](https://isc.sans.edu/diary/Microsoft+June+2026+Patch+Tuesday), [BleepingComputer (Windows 10 ESU KB5094127)](https://www.bleepingcomputer.com/news/microsoft/microsoft-releases-windows-10-kb5094127-extended-security-update/)

Microsoft's June release closed 200 vulnerabilities (excluding 360 Edge/Chromium fixes pushed separately by Google), of which 33 are rated Critical — 28 RCE, 4 elevation of privilege, 1 information disclosure. Three flaws were publicly disclosed before patches landed:

- **CVE-2026-45586** — Windows Collaborative Translation Framework (CTFMON) link-following local privilege escalation to SYSTEM (anonymous reporter).
- **CVE-2026-49160** — HTTP/2 "HTTP/2 Bomb" denial-of-service in HTTP.sys, attributed to Quang Luong and Codex of Calif.io. Mitigated by a new `MaxHeadersCount` registry setting (KB5102602).
- **CVE-2026-50507** — Windows BitLocker security feature bypass.

The separately named "YellowKey," "GreenPlasma" and "MiniPlasma" cluster covers another batch of zero-days addressed in the same release. Critical RCEs in the month's batch include CVE-2026-45456 / CVE-2026-45458 (Outlook/Word), CVE-2026-44820 (Excel), CVE-2026-48563 / CVE-2026-44801 (Remote Desktop Client), CVE-2026-45636 (Windows NTFS), and a cluster of WinSock Ancillary Function Driver use-after-free LPEs (CVE-2026-45598, CVE-2026-45601, CVE-2026-34335, CVE-2026-45596, CVE-2026-42911, CVE-2026-45638). High-severity items include CVE-2026-42912 / CVE-2026-42968 (Telephony), CVE-2026-42984 (Kernel UAF LPE), CVE-2026-44809 (CLFS UAF LPE), CVE-2026-42983 / CVE-2026-44807 (DWM Core Library), CVE-2026-42915 (TCP/IP DoS), CVE-2026-42903 (Kerberos DoS), CVE-2026-42908 (RDP information disclosure), CVE-2026-47640 (SharePoint spoofing), CVE-2026-48569 (Visual Studio Code), CVE-2026-42989 (Winlogon), CVE-2026-42836 (Function Discovery Service), CVE-2026-42837 (Projected File System) and a long Linux kernel CVE tail mirrored through MSRC.

> **SOC Action:** Stage Patch Tuesday rollout starting with Outlook/Word, Excel, and Remote Desktop Client clients — the user-facing RCE surfaces. Apply `MaxHeadersCount` per KB5102602 to internet-facing IIS / HTTP.sys hosts before mass patching to mitigate HTTP/2 Bomb DoS exposure. Hunt for CTFMON link-following abuse via Sysmon Event ID 11 where `ctfmon.exe` writes into user-owned paths. Confirm Windows 10 ESU KB5094127 is staged for any remaining Windows 10 estate. MITRE: T1078.001, T1497.

### 3.2 Check Point VPN authentication bypass (CVE-2026-50751) actively exploited by Qilin

**Source:** [Check Point Research](https://blog.checkpoint.com/security/check-point-releases-important-hotfix-for-vulnerabilities-in-deprecated-ikev1-vpn-protocol), [BleepingComputer](https://www.bleepingcomputer.com/news/security/check-point-links-vpn-zero-day-attacks-to-qilin-ransomware-gang/)

Check Point Research disclosed CVE-2026-50751 (CVSS 9.3), a certificate-validation logic flaw in the deprecated IKEv1 key-exchange path of Check Point Remote Access VPN, Mobile Access and Spark Firewall. An unauthenticated attacker can establish a VPN session without a valid password. Active exploitation against several dozen organisations is confirmed; at least one incident featured post-exploitation activity by a Qilin ransomware affiliate. A companion flaw, CVE-2026-50752 (CVSS 7.4, MITM on site-to-site VPN), was identified through Check Point's BLAST agentic code-review platform during the investigation; no in-the-wild exploitation has been observed for CVE-2026-50752.

Affected versions: R80.20.X through R82.10. Fixed in vendor advisories sk185033 (CVE-2026-50751) and sk185035 (CVE-2026-50752).

#### Indicators of Compromise
```
IPv4: 144.208.127[.]155
IPv4: 162.33.177[.]101
IPv4: 209.182.225[.]136
IPv4: 38.54.107[.]167
IPv4: 38.54.88[.]201
IPv4: 38.60.157[.]139
IPv4: 45.61.136[.]173
```

> **SOC Action:** Apply Check Point hotfixes from sk185033 immediately on any Remote Access or Mobile Access gateway running R80.20.X–R82.10. Where IKEv1 is not operationally required, disable it entirely. Pivot: search VPN authentication logs and NetFlow for the seven attacker IPv4 addresses; correlate any matched sessions with downstream Qilin TTPs (T1190 initial access, T1078 valid accounts, T1133 external remote services, T1486 data encrypted for impact). Flag successful IKEv1 VPN authentication where the corresponding RADIUS / LDAP credential lookup did not occur in the preceding 60 seconds.

### 3.3 Microsoft Exchange Server XSS zero-day (CVE-2026-42897) exploited; CISA KEV-listed since May 15

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/microsoft/microsoft-patches-exchange-server-zero-day-exploited-in-attacks/)

Microsoft patched CVE-2026-42897, a high-severity spoofing flaw in Exchange Server 2016, 2019 and Subscription Edition. A remote unauthenticated attacker can send a crafted email that, when opened in Outlook Web Access, executes arbitrary JavaScript in the browser context. CISA added the flaw to the KEV catalogue on May 15 with a federal patching deadline of May 29. Microsoft enabled an automatic temporary mitigation in mid-May via the Exchange Emergency Mitigation Service (EEMS) and shipped the permanent fix as part of June Patch Tuesday on June 9, recommending the EEMS mitigation stay in place as a defence in depth. Over the past five years CISA has added 20 Exchange Server vulnerabilities to the KEV — ransomware operators have weaponised 14 of them.

> **SOC Action:** Apply June 2026 Exchange Security Updates immediately on Exchange 2016, 2019 and SE. Leave the EEMS XSS mitigation enabled. Hunt OWA access logs for messages whose rendered HTML body contains inline `<script>` or `javascript:` URI patterns delivered to active mailboxes during the period 12 May → 9 June 2026. MITRE: T1190, T1204.

### 3.4 ShinyHunters mass-extortion campaign against Oracle PeopleSoft — 100+ tenants, University of Nottingham (454,635 accounts)

**Source:** [BleepingComputer (PeopleSoft)](https://www.bleepingcomputer.com/news/security/oracle-peoplesoft-servers-hacked-in-shinyhunters-data-theft-attacks/), [BleepingComputer (Nottingham)](https://www.bleepingcomputer.com/news/security/nottingham-university-data-breach-affects-over-450-000-students/), [Recorded Future](https://therecord.media/university-of-nottingham-cyber-incident-shiny-hunters), [HaveIBeenPwned](https://haveibeenpwned.com/Breach/UniversityOfNottingham)

ShinyHunters confirmed to BleepingComputer that it is operating an active extortion campaign against both cloud and on-premises Oracle PeopleSoft instances, claiming theft from 300 instances across 100+ organisations — most in the education sector. The attackers use a "gadget chain" of old and unspecified zero-day flaws, dropping ransom notes via a script that parses `/etc/hosts` to identify PeopleSoft systems and attempts SSH using accounts such as `psoft`, `oracle` and `linuxadm`. The University of Nottingham confirmed compromise; HaveIBeenPwned indexed 454,635 unique email addresses and associated personal data. ShinyHunters claims an unsuccessful attempt to breach an FBI PeopleSoft portal "to publish a statement and set the record straight on some misinformation." Researcher "Michael R" exposed staging infrastructure including a defacement script and MeshCentral agent.

#### Indicators of Compromise
```
IPv4: 142.11.200[.]186 → 142.11.200[.]190
IPv4: 108.174.202[.]99
IPv4: 176.120.22[.]24
Domain (TLS CN): azurenetfiles[.]net
Ransom note path: README-IF-YOU-SEE-THIS-YOUVE-BEEN-HACKED.TXT
Accounts probed via SSH: psoft, oracle, linuxadm
```

> **SOC Action:** Inventory PeopleSoft instances (cloud and on-prem); block egress to the seven IPv4 addresses above and any TLS certificate presenting CN `azurenetfiles[.]net`. Disable password authentication on PeopleSoft administrator SSH where not operationally required; reset `psoft`, `oracle` and `linuxadm` credentials. Hunt PeopleSoft web/app server filesystems for the `README-IF-YOU-SEE-THIS-YOUVE-BEEN-HACKED.TXT` ransom note. MITRE: T1027, T1071, T1102.

### 3.5 PAN-OS GlobalProtect authentication bypass (CVE-2026-0257) — actively exploited, KEV-listed

**Source:** [Unit 42](https://unit42.paloaltonetworks.com/active-exploitation-of-pan-os-cve-2026-0257/), [BleepingComputer](https://www.bleepingcomputer.com/news/security/palo-alto-globalprotect-vpn-auth-bypass-flaw-now-exploited-in-attacks/)

Unit 42 confirmed active exploitation of CVE-2026-0257, an authentication bypass in the portal and gateway components of PAN-OS that allows unauthorized VPN connection establishment. Forged authentication-override cookies targeting local administrator accounts are the documented exploitation path. Added to CISA KEV on May 29. No post-access lateral movement attributed yet; only a small fraction of probed devices successfully established sessions.

#### Indicators of Compromise (pre-PoC, before 29 May 2026)
```
IPv4: 23.128.228[.]6
IPv4: 104.207.144[.]154
IPv4: 146.19.216[.]119
IPv4: 146.19.216[.]120
IPv4: 146.19.216[.]125
IPv4: 179.43.172[.]213
IPv4: 185.195.232[.]139
IPv4: 198.12.106[.]60
IPv4: 202.144.192[.]47
Suspicious GP host IDs: aa:bb:cc:dd:ee:ff, 00:11:22:33:44:55
Suspicious GP device names: WINDOWS-LAPTOP-001, DESKTOP-GP01, GP-CLIENT
Post-PoC marker: endpoint_os_version = "Microsoft Windows 10 Pro 64-bit" with empty source_user_info.domain
```

> **SOC Action:** Upgrade PAN-OS to a fixed release; apply Palo Alto vendor workarounds where upgrade is delayed. Search GlobalProtect logs for successful gateway-connected events from the nine pre-PoC IPv4s and the listed suspicious host IDs / device names. Post-PoC, alert on any successful authentication whose hard-coded `endpoint_os_version` matches `Microsoft Windows 10 Pro 64-bit` with empty `source_user_info.domain`. MITRE: T1071.001, T1558.

### 3.6 Ivanti Sentry max-severity RCE and authentication bypass

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/new-max-severity-ivanti-sentry-flaw-allows-code-execution-as-root/), [CERT-EU 2026-008](https://cert.europa.eu/publications/security-advisories/2026-008/)

Ivanti shipped Sentry R10.5.2, R10.6.2 and R10.7.1 to address CVE-2026-10520 — a maximum-severity OS command injection allowing unauthenticated code execution as root — and CVE-2026-10523, a critical authentication bypass enabling rogue administrator account creation. Ivanti reported no observed exploitation at disclosure. Historical pattern (multiple Ivanti EPMM, Connect Secure and Sentry flaws weaponised by ransomware and state actors within days of disclosure) makes the exploitation window short. Sentry (formerly MobileIron Sentry) sits between corporate back-end systems and remote mobile devices.

> **SOC Action:** Upgrade Sentry to R10.5.2 / R10.6.2 / R10.7.1 within 72 hours. Where upgrade is delayed, restrict Sentry management interfaces to a jump-host source-IP allowlist. Hunt for unexpected administrator account creation: `grep -E "user.*created|admin.*added"` in `/var/log/mics/mics.log`. Inspect process trees for non-standard `sh` or `bash` children spawned by Sentry's Java processes.

### 3.7 Veeam Backup & Replication domain RCE (CVE-2026-44963)

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/new-veeam-vulnerability-exposes-backup-servers-to-rce-attacks/)

CVE-2026-44963 allows any authenticated domain user to achieve RCE on Veeam Backup & Replication 12.3.2.4465 and earlier 12.x builds. Fixed in 12.3.2.4854; 13.x is unaffected due to architectural changes. The flaw only impacts VBR servers joined to a Windows domain — a deployment pattern Veeam has long discouraged but which remains common. CISA has previously flagged four VBR flaws as actively exploited, all weaponised by ransomware operators (Akira, Fog, Frag, Cuba, FIN7).

> **SOC Action:** Upgrade VBR to 12.3.2.4854 (or migrate to 13.x) within seven days. Remove domain join from any backup server as a permanent posture change: backups are tier-0 assets and a non-domain-joined VBR breaks the most common ransomware kill chain. Hunt for any `veeam.backup.*` service account performing unexpected interactive logon or process spawning. MITRE: T1068, T1136.

### 3.8 Chrome V8 zero-day (CVE-2026-11645) — fifth Chrome zero-day this year

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/google-patches-fifth-chrome-zero-day-bug-exploited-in-attacks-this-year/)

Google shipped Chrome Stable 149.0.7827.102 (Windows/Linux) and 149.0.7827.103 (macOS) to patch CVE-2026-11645, an out-of-bounds read and write in the V8 JavaScript engine exploited in the wild via crafted HTML pages for arbitrary code execution inside the browser sandbox. Reported by an anonymous researcher. Joins CVE-2026-2441 (CSS font-feature-values iterator invalidation, February), CVE-2026-3909 (Skia OOB write, March), CVE-2026-3910 (V8, March), CVE-2026-5281 (Dawn/WebGPU UAF, April) as the year's fifth in-the-wild Chrome zero-day.

> **SOC Action:** Force Chrome update push to ≥ 149.0.7827.102 on managed endpoints via Group Policy / Chrome Browser Cloud Management. Pin minimum version in EDR application controls. For high-risk users, enable Enhanced Safe Browsing and consider isolating browser activity. MITRE: T1068, T1106, T1204.

### 3.9 Supply-chain wave — Shai-Hulud, Mini Shai-Hulud (TanStack + 19 PyPI science packages), IronWorm, Miasma (source code leaked)

**Source:** [BleepingComputer (Shai-Hulud PyPI)](https://www.bleepingcomputer.com/news/security/new-shai-hulud-attack-trojanizes-19-science-focused-pypi-packages/), [BleepingComputer (Miasma leak)](https://www.bleepingcomputer.com/news/security/the-miasma-worm-source-code-briefly-leaked-on-github/), [BleepingComputer (IronWorm)](https://www.bleepingcomputer.com/news/security/new-ironworm-malware-hits-36-packages-in-npm-supply-chain-attack/), [SANS ISC (TeamPCP)](https://isc.sans.edu/diary/TeamPCP+Supply+Chain+Campaign), [Recorded Future](https://therecord.media/red-hat-removes-tainted-packages)

Five concurrent open-source supply-chain campaigns ran through the period:

- **Shai-Hulud (TeamPCP, 29 reports):** TanStack npm package family compromise then extension into a fresh Shai-Hulud campaign trojanising 19 science/bioinformatics PyPI packages. Targets developer secrets; data exfiltrated via GitHub repositories and HTTPS endpoints.
- **Mini Shai-Hulud:** TanStack + additional npm packages, Red Hat Cloud Services scope.
- **IronWorm:** worm-style npm malware compromising 36 packages.
- **Miasma:** credential-stealing worm against Red Hat Cloud Services and 73 Microsoft GitHub repositories. Source code deliberately leaked on June 10 across compromised dev accounts under the repo name `Miasma-Open-Source-Release`. Key features per SafeDep analysis: GitHub-only C2 (no traditional C2 infra); harvests credentials from cloud providers, CI/CD, password managers, Kubernetes, secret stores; lateral movement via SSH and AWS SSM; configuration poisoning of AI coding tools (Claude, Gemini, Cursor, Copilot, Kiro, Cline); dead-man switch monitoring exfil-token validity that issues `rm -rf ~/; rm -rf ~/Documents` on revocation; five-stage build pipeline with AES-256-GCM per-file encryption and per-build randomisation to defeat signature detection.
- **Laravel Lang compromise:** RCE backdoor across 700+ versions of the Laravel Lang language pack.

Shai-Hulud's earlier code leak preceded a measurable jump in attack rate and the rise of Miasma; the Miasma leak is expected to spawn further variants.

> **SOC Action:** Quarantine any build pipeline whose `package-lock.json`, `yarn.lock` or `pyproject.toml` references Laravel Lang, TanStack, Red Hat Cloud Services scopes, or any of the 19 named PyPI science packages installed since 12 May 2026. Pin direct dependencies and disable `postinstall` (npm) and `setup.py` execution (PyPI) on CI runners; introduce a multi-day quarantine window for newly published versions. Hunt CI/CD nodes for systemd user services or LaunchAgents matching the Miasma dead-man-switch description. Audit any AI coding tool configurations on developer endpoints (Claude, Gemini, Cursor, Copilot, Kiro, Cline) for tampering. MITRE: T1195.002, T1003, T1078, T1531, T1566.001.

### 3.10 Ransomware-as-a-Service operational tempo — Qilin, The Gentlemen, Akira, DragonForce, ShinyHunters; Krebs attributes The Gentlemen administrator

**Source:** [Krebs on Security](https://krebsonsecurity.com/2026/06/who-runs-the-ransomware-group-the-gentlemen/), [AlienVault OTX](https://otx.alienvault.com/pulse/6a2951722e6ca0cbaaac430b), [RansomLook](https://www.ransomlook.io/), [BleepingComputer](https://www.bleepingcomputer.com/news/security/)

Ransomware leak-site postings ran at high volume. Qilin posted 89 victims (period leader) with confirmed VPN-zero-day initial access (§3.2). The Gentlemen posted 61 victims with logistics, engineering and technology concentrations across Japan, China, Ireland, Turkey, Poland, Austria and the US — Check Point Research counts 332 published victims since group inception in mid-2025, with 240+ in 2026 alone, and observed the group entering targets via internet-facing VPN and firewall devices then encrypting entire networks within hours. Krebs on Security, working from Intel 471, Flashpoint and Constella Intelligence data, attributes the administrator (handle Hastalamuerte / Zeta88, operating a 90/10 affiliate revenue split) to Alexander Andreevich Yapaev, a 36-year-old in Izhevsk, Russia, with documented forum activity from 2019 onward. AlienVault tracks the malware as Storm-2697, written in Go with C-compiled lockers and self-propagation. Akira (38 postings) targeted healthcare and manufacturing. DragonForce (34) continued its hacktivist-to-financially-motivated transition. ShinyHunters (23) executed the Oracle PeopleSoft campaign (§3.4). Newer entrants: Chaos (active double-extortion RaaS, recently hit Optima Tax Relief), M3rx (multi-industry data theft and ransom), Morpheus (high-value targets including 3I Infotech, 325 GB stolen), Fulcrumsec (claimed Avnet EMEA breach with 1.1 TB stolen), Coinbase Cartel (CoinBreach payload), Krybit (broad multi-sector spread), Stormous (auctioning data dumps including ~150 GB from sa2000.com). The Silent Ransom Group (UNC3753) continued fake-IT-support voice-phishing of US law firms.

> **SOC Action:** Build named-actor watchlists for the top-five (Qilin, The Gentlemen, Akira, DragonForce, ShinyHunters) and ingest RansomLook into the SIEM. Brief legal and finance functions on the Silent Ransom Group / UNC3753 vishing pattern — frontline staff should treat unsolicited "IT support" calls as suspicious by default. Specifically for The Gentlemen: assume VPN/firewall entry, look for Go-binary process executions encrypting at high speed across SMB/NFS mounts. MITRE: T1566.004 (spearphishing voice), T1078, T1486.

### 3.11 China-nexus reconnaissance — JDY botnet expansion targeting US military

**Source:** [BleepingComputer / Black Lotus Labs](https://www.bleepingcomputer.com/news/security/china-linked-jdy-botnet-expands-targeting-of-us-military-networks/)

The JDY botnet — previously associated with Volt Typhoon — grew from ~650 bots in January 2024 to 1,500+ compromised SOHO and IoT devices. Black Lotus Labs by Lumen reports the operators rapidly weaponise newly disclosed CVEs into JDY scan signatures (observed scanning for Fortinet FortiClient EMS CVE-2026-35616 shortly after disclosure), with US military and associated networks as the primary target sector. Affected device fleets include Cisco, Araknis, Mimosa Networks, Ubiquiti, DrayTek, Hikvision and Linksys (MIPS / MIPS64 / MIPSEL / MIPSEL64). C2 over hidden Tor services; reverse-shell framework Platypus observed in some cases; fast raw-socket SYN scanning with fixed source port `19000` when root privileges are available.

> **SOC Action:** For organisations in defence supply chain or with USG contracts, audit edge-router and IoT inventories; replace end-of-life SOHO devices from the named vendor list. Add SYN-scan signatures from fixed source port `19000` to perimeter NetFlow analytics. Where Tor egress is not operationally required, block it at the edge. MITRE: T1046, T1189.

### 3.12 NSO spyware operations against WhatsApp; French Tchap government messaging breach

**Source:** [BleepingComputer (NSO)](https://www.bleepingcomputer.com/news/security/whatsapp-says-it-disrupted-new-nso-spyware-phishing-attacks/), [BleepingComputer (Tchap)](https://www.bleepingcomputer.com/news/security/french-govt-messaging-service-breached-in-account-hijacking-attack/)

WhatsApp disrupted a fresh wave of NSO Group spearphishing attempts against its users, which Meta characterises as a violation of an existing court order. Separately, the Tchap messaging service used by the French government suffered an account-hijacking attack: a threat actor used social engineering to take over accounts and exfiltrate files and account information from public chat rooms.

> **SOC Action:** For high-risk users (journalists, dissidents, executives in geopolitically sensitive sectors): enforce iOS Lockdown Mode and equivalent restrictive Android profiles; disable WhatsApp link previews; quarterly mobile-device forensic checks (MVT). For federated / matrix-based government messaging tools, audit account-recovery flows and require hardware-backed MFA for any account with access to non-public rooms. MITRE: T1566.

### 3.13 Additional active-exploitation items

**Source:** [BleepingComputer (Langflow)](https://www.bleepingcomputer.com/news/security/path-traversal-flaw-in-ai-dev-platform-langflow-exploited-in-attacks/), [BleepingComputer (Android/Linux KEV)](https://www.bleepingcomputer.com/news/security/cisa-warns-of-active-attacks-exploiting-android-linux-bugs/), [BleepingComputer (NFCShare)](https://www.bleepingcomputer.com/news/security/nfcshare-android-malware-spreads-via-fake-banking-app-updates-on-github/)

- **Langflow (AI dev platform) — CVE-2026-5027:** Tenable-identified path traversal exploited in the wild to write arbitrary files on exposed servers (unauthenticated). Patched in 1.9.0 / langflow-base 0.8.3.
- **CISA KEV — Android CVE-2025-48595 (integer overflow) and Linux CVE-2022-0492 (privilege escalation):** active-exploitation warning issued June 3.
- **NFCShare Android malware:** new variants distributed as fake banking-app updates on GitHub, targeting multiple European banks; exploits Android `IsoDep` to steal payment-card data via NFC.
- **UniFi OS:** critical unauthenticated-root flaw; Gogs critical zero-day RCE; SolarWinds Serv-U DoS (CISA KEV addition); Fortinet FortiOS unauthenticated RCE; Cisco IOS XE WebUI unauthenticated command execution; Cisco SD-WAN zero-day exploitation (ongoing).
- **Apache HTTP Server CVE-2026-49975:** `mod_http2` denial of service.
- **Pwn2Own Berlin 2026:** $1,298,250 in payouts for 47 zero-days; Microsoft Exchange and Windows 11 compromised on day two.

> **SOC Action:** Treat any internet-exposed VPN, firewall management plane, source-control appliance, mail server or file-transfer product as tier-0 patching priority for the period. Where edge products are not in your SBOM, pull device inventory from EDR and external attack surface management before relying on the CMDB.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 CRITICAL | Exploitation of vulnerabilities in widely-used software and systems | Microsoft June Patch Tuesday (200 flaws, 3 zero-days); YellowKey / GreenPlasma / MiniPlasma; Patch Tuesday May 2026 (30 critical / 130 CVEs) |
| 🔴 CRITICAL | Widespread exploitation of Remote Desktop Protocol vulnerabilities | CVE-2026-42913 RDP Client RCE; CVE-2026-45464 SharePoint spoofing; RDP information disclosure cluster |
| 🔴 CRITICAL | Exploitation of critical vulnerabilities across multiple software platforms | Gogs RCE zero-day; UniFi OS unauthenticated root; PAN-OS CVE-2026-0257 |
| 🔴 CRITICAL | Supply chain attacks exploiting npm, PyPI and software development ecosystems | Shai-Hulud (TanStack, 19 PyPI sci packages); Mini Shai-Hulud; Laravel Lang (700+ versions); IronWorm; Miasma (Red Hat, 73 MS repos, source leaked) |
| 🔴 CRITICAL | Rise in zero-day exploits targeting widely used software | Chrome V8 CVE-2026-11645 (5th this year); Linux kernel LPE (CVE-2023-0185 resurfaced); Cisco SD-WAN zero-days |
| 🔴 CRITICAL | RaaS expansion globally with sophisticated TTPs | Qilin, Nova, Akira, DragonForce campaign tempo; The Gentlemen administrator attributed to Yapaev/Izhevsk; Storm-2697 Go-binary RaaS |
| 🔴 CRITICAL | Targeting of critical infrastructure (government, healthcare) by various actors | Chinese hackers Atlas RAT in European cyberattacks (TA4922); Michigan Surgical Center by The Gentlemen |
| 🔴 CRITICAL | Ransomware groups leveraging malware-signing-as-a-service platforms | Microsoft disruption of Fox Tempest signing-as-a-service tied to ransomware gangs |
| 🔴 CRITICAL | Zero-day exploitation incentivised by hacking competitions | Pwn2Own Berlin 2026 — $1,298,250 for 47 zero-days; Exchange and Windows 11 compromised |
| 🔴 CRITICAL | Exploitation of widely used software for financial gain | THORChain $10M+ theft; Funnel Builder WordPress plugin credit-card theft |
| 🔴 CRITICAL | Exploitation of vulnerabilities in cryptographic libraries | rust-openssl heap overflow CVE-2026-44662; PostgreSQL libpq lo_* superuser overwrite CVE-2026-6477 |
| 🟠 HIGH | Increased ransomware activity by Qilin and ShinyHunters | University of Nottingham (454,635 accounts); Miller & Zois, Iliff by Qilin; Oracle PeopleSoft mass extortion |
| 🟠 HIGH | Phishing campaigns leveraging voicemail and helpdesk impersonation | Voicemail phishing kit with SSO hijacking + RMM delivery; Silent Ransom Group fake-IT-support law-firm vishing |
| 🟠 HIGH | Phishing campaigns leveraging AI and social engineering | Instagram users locked out after Meta AI abuse; "the browser is the front line for AI security" |
| 🟠 HIGH | State-sponsored cyber espionage targeting government and critical infrastructure | Gamaredon × Turla 2025 alliance vs Ukraine; FSB Gamaredon GammaPhish/GammaWorm; Iranian Screening Serpens / Nimbus Manticore |
| 🟠 HIGH | Phishing and spearphishing as primary TTPs in geopolitical operations | NSO spyware against WhatsApp; Russia-linked disinformation in Armenia election |
| 🟠 HIGH | Increased exploitation of privilege escalation vulnerabilities | libexpat CVE-2026-50219; OpenSC CVE-2026-40510; Redis CVE-2026-23479 |
| 🟠 HIGH | Increased focus on supply chain attacks targeting cloud services | IronWorm 36-package npm attack; Miasma vs Red Hat Cloud Services |
| 🟠 HIGH | Targeting of cryptographic libraries impacting critical infrastructure | Mbed TLS CVE-2026-34875 buffer overflow in FFDH key export; gnutls CVE-2026-42012 certificate validation bypass |
| 🟠 HIGH | Brazilian threat actor Grupo Mauá expansion | Grupo Mauá by bravox postings |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **Qilin** (89 reports) — leading RaaS operator; confirmed Check Point VPN CVE-2026-50751 post-exploitation linkage.
- **The Gentlemen** (61 reports) — multi-sector coordinated campaign across Japan, China, Ireland, Turkey, Poland, Austria, US; Krebs links administrator handle Hastalamuerte/Zeta88 to Alexander Andreevich Yapaev (Izhevsk, Russia); 90/10 affiliate split; 332+ published victims since mid-2025 per Check Point.
- **Akira** (38 reports) — concentrated targeting of healthcare and manufacturing.
- **DragonForce** (34 reports) — hacktivist-origin RaaS targeting retail, government, logistics, manufacturing.
- **TeamPCP** (29 reports) — open-source code-poisoning actor behind Shai-Hulud campaigns and the GitHub internal-repo breach claim; tracked as Storm-2697.
- **ShinyHunters** (23 reports) — Oracle PeopleSoft mass extortion (100+ tenants); University of Nottingham (454,635 accounts), Charter Communications.
- **Nova** (22 reports) — RALord deployment across multiple operations.
- **Lockbit5** (20 reports) — refreshed Lockbit lineage branding.
- **Nightspire** (20 reports) — double-extortion across energy, healthcare, transportation, financial services.
- **Stormous** (18 reports) — dark-web data-sale operations including ~150 GB sa2000.com dump.
- **Inc Ransom** (15), **Coinbase Cartel** (13, CoinBreach payload), **Everest** (12), **Safepay** (11), **Genesis** (10).
- **State / espionage:** Gamaredon, Turla, FSB-attributed (Ukraine focus); Iranian Screening Serpens, Nimbus Manticore; TA4922 (Chinese-speaking, Europe, Atlas RAT); Volt Typhoon-adjacent JDY botnet operators.

### Malware Families

- **RansomLook** (109 reports) — leak-site aggregator feed; baseline indicator for RaaS posting activity.
- **Tox1 / Tox / Tox2** (38 / 23 / 9) — clustered Tox-protocol-using malware identifiers.
- **Akira ransomware** (21 reports, plus 14 generic Akira) — primary Akira affiliate payload.
- **Shai-Hulud / Mini Shai-Hulud** (13 / 13) — npm + PyPI worm payloads in the TeamPCP supply-chain campaign.
- **Miasma** — credential-stealing supply-chain worm; deliberate source-code leak June 10; uses GitHub-only C2, AI-tool config poisoning, dead-man-switch home-directory wipe.
- **RALord** (12 reports) — Nova-affiliated ransomware.
- **Nova** (11 reports) — Nova RaaS payload.
- **Qilin** (9 reports), **Lockbit5** (9), **Nightspire** (9) — affiliated payloads.
- **Atlas RAT** — new RAT used by TA4922 in European cyberattacks (Talos / AlienVault analysis).
- **MLTBackdoor** — backdoor with phishing delivery analysed during the period (AlienVault).
- **IronWorm** — npm-targeted worm (36 packages compromised).
- **NFCShare** — Android malware distributed as fake banking-app updates on GitHub; abuses `IsoDep` for NFC payment-card theft.
- **JDY** — China-nexus reconnaissance botnet (1,500+ SOHO/IoT bots).
- **The Gentlemen ransomware** (Storm-2697) — Go-binary locker with self-propagation, 1,570+ organisations compromised.

### Vulnerabilities (named in entity index)

The structured vulnerability entity index returned only six explicit CVE entities during the period (CVE-2026-0300, CVE-2026-35616, CVE-2012-4221, CVE-2013-2596, CVE-2013-2597, CVE-2013-6282). The operationally relevant CVEs cited in this report — CVE-2026-50751 (Check Point), CVE-2026-42897 (Exchange XSS), CVE-2026-0257 (PAN-OS), CVE-2026-11645 (Chrome V8), CVE-2026-44963 (Veeam), CVE-2026-10520 / CVE-2026-10523 (Ivanti Sentry), CVE-2026-45586 / CVE-2026-49160 / CVE-2026-50507 (Patch Tuesday zero-days), CVE-2026-5027 (Langflow), the WinSock AFD UAF cluster, CVE-2026-50219 (libexpat), CVE-2026-40510 (OpenSC), CVE-2026-23479 (Redis), CVE-2026-44662 (rust-openssl), CVE-2026-6477 (PostgreSQL libpq), CVE-2026-44839 (RabbitMQ), CVE-2025-14179 (pdo_firebird SQLi), CVE-2026-34875 (Mbed TLS), CVE-2026-42012 (gnutls), CVE-2025-48595 (Android, CISA KEV) and CVE-2022-0492 (Linux, CISA KEV) — come from report narratives and trend evidence. This is a known coverage gap in entity extraction for vulnerability mentions during the period.

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|--------:|-----|-------|
| Microsoft | 1,216 | [link](https://msrc.microsoft.com/update-guide) | MSRC advisory firehose, dominated by June Patch Tuesday CVE entries |
| RansomLook | 604 | [link](https://www.ransomlook.io/) | Ransomware leak-site aggregator; volume floor for Qilin, The Gentlemen, Akira postings |
| BleepingComputer | 191 | [link](https://www.bleepingcomputer.com) | Primary narrative coverage of Patch Tuesday, Veeam, Ivanti, Check Point, Exchange, Oracle PeopleSoft, Miasma, ransomware |
| AlienVault | 114 | [link](https://otx.alienvault.com/) | OTX pulses including Check Point VPN exploitation, Storm-2697 / The Gentlemen technical analysis, MLTBackdoor, SniperDz |
| Unknown | 106 | — | Source attribution missing or unparsed (Telegram-origin OSINT folds in here per redaction policy) |
| RecordedFuture | 61 | [link](https://therecord.media/) | Patch Tuesday, Red Hat Cloud Services compromise, University of Nottingham coverage |
| CISA | 60 | [link](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | KEV catalogue additions (Exchange CVE-2026-42897, PAN-OS CVE-2026-0257, Android CVE-2025-48595, Linux CVE-2022-0492, SolarWinds Serv-U) and ICS advisories (Brickcom Cameras, Naxclow IoT) |
| SANS | 42 | [link](https://isc.sans.edu/) | ISC StormCast, June Patch Tuesday diary, TeamPCP supply-chain coverage |
| Wired Security | 36 | [link](https://www.wired.com/category/security/) | Geopolitical and policy-level coverage |
| Schneier | 28 | [link](https://www.schneier.com/) | Cryptography and policy commentary |
| Upwind | 21 | [link](https://www.upwind.io/) | Cloud-runtime security advisories |
| Crowdstrike | 16 | [link](https://www.crowdstrike.com/blog/) | Threat actor profiles |
| HaveIBeenPwned | 16 | [link](https://haveibeenpwned.com/) | Breach disclosures (University of Nottingham 454,635 accounts, etc.) |
| Wiz | 15 | [link](https://www.wiz.io/blog) | Cloud vulnerability research |
| Cisco Talos | 15 | [link](https://blog.talosintelligence.com/) | Threat intelligence including Atlas RAT / TA4922 analysis |
| Unit42 | 14 | [link](https://unit42.paloaltonetworks.com/) | PAN-OS CVE-2026-0257 active-exploitation Threat Brief; Iranian APT tracking |
| Krebs on Security | <10 | [link](https://krebsonsecurity.com/) | Attribution work on The Gentlemen administrator |
| CertEU | <10 | [link](https://cert.europa.eu/) | Ivanti Sentry advisory 2026-008 |

Telegram-origin OSINT contributions are aggregated under "Unknown" or vendor sources and are deliberately not linked per the source-redaction policy.

## 7. Consolidated Recommendations

### Patching

- 🔴 **IMMEDIATE:** Apply Check Point sk185033 hotfix on every Remote Access / Mobile Access gateway running R80.20.X–R82.10 within 24 hours; disable IKEv1 where not operationally required (§3.2).
- 🔴 **IMMEDIATE:** Apply June 2026 Microsoft Exchange Security Updates within 48 hours and leave the EEMS XSS mitigation in place (§3.3). Federal patching deadline was May 29.
- 🔴 **IMMEDIATE:** Patch PAN-OS to a CVE-2026-0257-fixed release; apply vendor workarounds where upgrade is delayed (§3.5). KEV deadline already past.
- 🔴 **IMMEDIATE:** Upgrade Ivanti Sentry to R10.5.2 / R10.6.2 / R10.7.1 within 72 hours (CVE-2026-10520, CVE-2026-10523) (§3.6).
- 🔴 **IMMEDIATE:** Upgrade Veeam Backup & Replication to 12.3.2.4854 within seven days; remove domain join from backup servers as a permanent posture change (§3.7).
- 🔴 **IMMEDIATE:** Force Chrome update push to ≥ 149.0.7827.102 on managed endpoints (§3.8).
- 🟠 **SHORT-TERM:** Roll June Microsoft Patch Tuesday across the estate over a one-week window, prioritising Outlook/Word, Excel, RDP Client and any internet-facing HTTP.sys host (apply `MaxHeadersCount` per KB5102602 first) (§3.1). Stage Windows 10 KB5094127 ESU.
- 🟠 **SHORT-TERM:** Patch Fortinet FortiOS, UniFi OS, SolarWinds Serv-U, Cisco SD-WAN, Gogs, Langflow (CVE-2026-5027), Apache HTTP Server (CVE-2026-49975), and any remaining KEV exposures (§3.13).

### Detection

- 🔴 **IMMEDIATE:** Add the seven Check Point attacker IPv4 indicators, the seven ShinyHunters PeopleSoft IPv4s + `azurenetfiles[.]net` TLS CN, and the nine pre-PoC PAN-OS GlobalProtect IPv4s (§3.2 / §3.4 / §3.5) to firewall block-lists, EDR network telemetry and SIEM correlation rules. Page on any successful authentication from those IPs in the last 30 days.
- 🟠 **SHORT-TERM:** Build SIEM rules for successful IKEv1 VPN authentication without a matched upstream RADIUS / LDAP credential lookup (CVE-2026-50751 exploitation signature) (§3.2).
- 🟠 **SHORT-TERM:** Alert on PAN-OS GlobalProtect successful authentications with `endpoint_os_version = "Microsoft Windows 10 Pro 64-bit"` and empty `source_user_info.domain` (post-PoC marker) (§3.5).
- 🟠 **SHORT-TERM:** Detection for OWA messages containing inline `<script>` or `javascript:` URIs delivered between 12 May and 9 June 2026 (CVE-2026-42897) (§3.3).
- 🟠 **SHORT-TERM:** Detection for npm `postinstall` and PyPI `setup.py` execution from CI runners; flag any lockfile change touching Laravel Lang, TanStack, `@redhat-cloud-services/*` scopes or any of the named PyPI science packages installed since 12 May 2026 (§3.9).
- 🟡 **AWARENESS:** Detection for CTFMON link-following abuse (Sysmon Event ID 11 by `ctfmon.exe` in user paths) following Patch Tuesday rollout (§3.1).
- 🟡 **AWARENESS:** SOHO-router SYN scans from fixed source port `19000` (JDY botnet signature) on perimeter NetFlow analytics (§3.11).

### Hunting

- 🔴 **IMMEDIATE:** Retroactively hunt the last 30 days of VPN authentication logs and NetFlow for the Check Point exploitation IPs and the pre-PoC PAN-OS IPs (§3.2 / §3.5).
- 🔴 **IMMEDIATE:** Inventory all Oracle PeopleSoft instances (cloud and on-prem); hunt PeopleSoft web/app server filesystems for the `README-IF-YOU-SEE-THIS-YOUVE-BEEN-HACKED.TXT` ransom note (§3.4).
- 🟠 **SHORT-TERM:** Hunt for unexpected administrator account creation on Ivanti Sentry appliances (`/var/log/mics/mics.log`) (§3.6).
- 🟠 **SHORT-TERM:** Hunt for `veeam.backup.*` service accounts performing interactive logon or process spawning outside backup-window schedules (§3.7).
- 🟠 **SHORT-TERM:** Hunt CI/CD nodes for systemd user services or LaunchAgents matching the Miasma dead-man-switch pattern; audit AI coding tool configurations (Claude, Gemini, Cursor, Copilot, Kiro, Cline) on developer endpoints for tampering (§3.9).
- 🟡 **AWARENESS:** Hunt for Atlas RAT C2 patterns in European subsidiaries; cross-reference Cisco Talos and AlienVault IOCs published during the period (§3.13 / §5).

### Policy

- 🔴 **IMMEDIATE:** Reset and rotate the `psoft`, `oracle` and `linuxadm` credentials across all PeopleSoft hosts; disable SSH password authentication where not operationally required (§3.4).
- 🟠 **SHORT-TERM:** Mandate quarterly mobile-device forensic checks (MVT) for high-risk roles in light of confirmed NSO spyware activity against WhatsApp users (§3.12).
- 🟠 **SHORT-TERM:** Brief legal and finance functions on the Silent Ransom Group / UNC3753 vishing pattern; treat unsolicited helpdesk calls as suspicious by default (§3.10).
- 🟢 **STRATEGIC:** Move backup, mobile-gateway and management-plane appliances behind a jump-host with strict source-IP allowlisting — the month's data shows every perimeter category exploited in a single 30-day window (§3.1–§3.13).
- 🟢 **STRATEGIC:** Adopt a multi-day quarantine window for newly published open-source dependencies; pin direct dependencies and disable build-time arbitrary script execution on CI runners (§3.9).
- 🟢 **STRATEGIC:** For defence supply chain and USG-contracted organisations, refresh edge-router and IoT inventory; remove end-of-life SOHO devices from the JDY vendor list (Cisco, Araknis, Mimosa Networks, Ubiquiti, DrayTek, Hikvision, Linksys) (§3.11).

### Training

- 🟠 **SHORT-TERM:** Run a tabletop simulation on a VPN-zero-day → Qilin ransomware deployment chain using the §3.2 IPs and §5 actor profile as the scenario.
- 🟠 **SHORT-TERM:** Run a separate tabletop on Oracle PeopleSoft extortion (ShinyHunters playbook) for organisations running ERP / HR / SIS workloads (§3.4).
- 🟡 **AWARENESS:** Refresh developer training on lockfile review, `postinstall` / `setup.py` script hygiene, and AI-coding-tool configuration integrity following the Shai-Hulud / Miasma / IronWorm / Laravel Lang wave (§3.9).
- 🟢 **STRATEGIC:** Add a recurring "perimeter device monthly" review to the SOC training calendar — VPN, firewall, backup, mobile gateway, source-control, mail server, identity store — to internalise that every category was exploited in a single 30-day window.

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 2,621 reports processed across 50 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
