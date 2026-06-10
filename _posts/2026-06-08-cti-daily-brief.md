---
layout: post
title:  "CTI Daily Brief: 2026-06-08 - Chrome V8 zero-day exploited in the wild; Shai-Hulud PyPI supply-chain wave; Termite/Qilin ransomware sustained activity"
date:   2026-06-09 20:07:15 +0000
description: "66 reports processed across 1 correlation cycle. Headlines: actively exploited Chrome V8 zero-day (CVE-2026-11645), 19 trojanised PyPI packages in a new Shai-Hulud wave, NFCShare Android banking malware on GitHub, MS Teams IT-impersonation phishing (Cloaked Ursa/UNC6692), and a Tuesday batch of nine critical Linux/library RCE CVEs (Redis, Xorg, libinput, bzip2, golang ssh, rrdtool)."
category: daily
tags: [cti, daily-brief, shai-hulud, qilin, termite, cve-2026-11645]
classification: TLP:CLEAR
reporting_period: "2026-06-08"
generated: "2026-06-09"
draft: true
report_count: 66
severity: critical
sources:
  - Microsoft
  - BleepingComputer
  - Unit42
  - RansomLock
  - RecordedFutures
  - SANS
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-06-08 (24h) | TLP:CLEAR | 2026-06-09 |

## 1. Executive Summary

The pipeline processed 66 reports across one correlation batch (ID 164) in the 24-hour window ending 2026-06-09 07:07 UTC, with severity skewed heavily critical/high (9 critical, 32 high). The dominant theme is a wide-front exploitation wave against open-source libraries and runtimes: Google shipped an emergency Chrome patch for CVE-2026-11645, an out-of-bounds read/write in the V8 JavaScript engine **confirmed exploited in the wild** — the fifth Chrome zero-day of the year. In parallel, Socket disclosed a new Shai-Hulud supply-chain wave that trojanised 19 bioinformatics-focused PyPI packages (37 malicious releases) to harvest developer cloud, source-control, and CI/CD secrets. Microsoft published a tranche of nine critical RCE/LPE CVEs across Redis (use-after-free in unblock/Lua/RESTORE flows), Xorg-x11-server/xwayland, libinput, bzip2, rrdtool, and golang.org/x/crypto/ssh. Unit 42 reported sustained MS Teams IT-helpdesk impersonation by Cloaked Ursa (APT29) and Mandiant-tracked UNC6692, and Termite/Qilin/Ransomhouse continued data-leak activity against healthcare, education, manufacturing, and aviation victims.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 9 | Redis (3× RCE), Xorg-x11-server (2× UAF/SBO), libinput root RCE, bzip2 OOB write, rrdtool SBO, golang ssh panic |
| 🟠 **HIGH** | 32 | Chrome V8 zero-day (in-the-wild); Shai-Hulud PyPI; NFCShare Android; Teams phishing; Termite/Qilin/Ransomhouse leak posts; multiple Xorg/Perl/Go library CVEs |
| 🟡 **MEDIUM** | 19 | FRRouting BGP DoS; golang net/mail and net/textproto issues; html/template URL escaping; libexpat handlers |
| 🟢 **LOW** | 2 | Tier-2 advisory and analyst notes |
| 🔵 **INFO** | 4 | Background advisories and policy/regulatory updates |

## 3. Priority Intelligence Items

### 3.1 Actively-exploited Chrome V8 zero-day — CVE-2026-11645

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/google-patches-fifth-chrome-zero-day-bug-exploited-in-attacks-this-year/)

Google released an emergency Stable Desktop update (Windows 149.0.7827.102 / Mac 149.0.7827.103 / Linux 149.0.7827.102) for CVE-2026-11645, an out-of-bounds read/write in the V8 JavaScript engine reported by an anonymous researcher. Google confirms "an exploit for CVE-2026-11645 exists in the wild." Successful exploitation via a crafted HTML page enables arbitrary code execution inside the renderer sandbox, leaks heap memory, and can be chained to bypass ASLR. This is the fifth in-the-wild Chrome zero-day Google has patched in 2026 (preceded by CVE-2026-2441, CVE-2026-3909, CVE-2026-3910, CVE-2026-5281). MITRE ATT&CK: T1068, T1204.

**Affected:** All pre-149.0.7827.102 Chromium-based browsers (Chrome, Edge, Brave, Opera, Vivaldi typically follow within 24–72h).

> **SOC Action:** Force-push Chrome to 149.0.7827.102+ via group policy / MDM today; audit Chrome version telemetry in EDR (e.g., `chrome.exe` file version) and flag hosts still below the patched build. Block enterprise extensions from new installs for 72h while users update, and monitor proxy logs for HTML responses containing V8-targeted heap-grooming primitives (large typed-array allocations followed by atypical structured-clone calls).

---

### 3.2 Shai-Hulud supply-chain wave — 19 trojanised PyPI bioinformatics packages

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/new-shai-hulud-attack-trojanizes-19-science-focused-pypi-packages/)

Socket disclosed 37 malicious releases across 19 PyPI packages tied to a single maintainer, including widely-used bioinformatics tools (`Dynamo`, `Spateo`, `CoolBox`, `U-FISH`, `Napari-UFISH`). The attack drops a `*-setup.pth` file that triggers on any subsequent `python` invocation — including CI runners, notebook kernels, and `pip` commands — and downloads the Bun JavaScript runtime from GitHub to execute an obfuscated `_index.js` payload. The payload harvests GitHub tokens and Actions secrets, npm/PyPI/RubyGems/JFrog publishing tokens, AWS/GCP/Azure/Kubernetes/Vault credentials, SSH keys, Docker credentials, shell history, `.env`/`.npmrc`/`.pypirc`, and Claude/MCP configuration files. Exfiltration uses auto-created GitHub repositories (Actions write-back pattern) plus a secondary HTTPS channel to `api[.]anthropic[.]com/v1/api` (an invalid endpoint used for camouflage, **not** a real Anthropic compromise). Persistence: systemd services on Linux, LaunchAgents on macOS, GitHub workflow files. Socket's running tally of Shai-Hulud artifacts is now 453. MITRE ATT&CK: T1195.002 (Compromise Software Supply Chain), T1071.001, T1082, T1552.001.

#### Indicators of Compromise
```
Persistence: ~/.config/systemd/user/*shai*.service (Linux)
              ~/Library/LaunchAgents/*shai*.plist (macOS)
File artifact: <package>-setup.pth, _index.js
Process chain: python → bun → _index.js
C2 (decoy):   hxxps[:]//api[.]anthropic[.]com/v1/api
Exfil:        Auto-created GitHub repos (Actions write secrets)
Count:        453 Shai-Hulud artifacts tracked
```

> **SOC Action:** Inventory PyPI installs of `Dynamo`, `Spateo`, `CoolBox`, `U-FISH`, `Napari-UFISH` and the full Socket-published list across dev workstations, CI runners, and notebook environments. Hunt for `.pth` files containing executable code in `site-packages` (`grep -rE "^import|exec\(" *.pth`), and EDR-hunt the `python → bun` process chain. Treat any developer host that ran these packages as compromised: rotate all GitHub/npm/PyPI/RubyGems/JFrog tokens, cloud credentials (AWS/GCP/Azure/Kubernetes/Vault), SSH keys, and Anthropic API keys; restore from known-clean backups.

---

### 3.3 Microsoft Teams "IT helpdesk" social engineering — Cloaked Ursa & UNC6692

**Source:** [Unit 42](https://unit42.paloaltonetworks.com/microsoft-teams-phishing/)

Unit 42 reports that collaboration-tool phishing alerts climbed from 30% to 42% of all phishing alerts in Cortex over consecutive four-month windows. Threat actors initiate Teams chats from external M365 tenants — using typosquatted domains mimicking IT/MSP naming conventions, or operating from compromised partner tenants already on a target's allow-list — and ask employees to approve an MFA prompt under the pretext of "verifying" a login anomaly. Attribution: Cloaked Ursa (aka APT29 / Cozy Bear / Midnight Blizzard) operationalised this technique in 2024, and Mandiant tracked UNC6692 doing the same in December 2025 via outside-tenant chat invites. MITRE ATT&CK: T1566.003 (Spearphishing via Service), T1621 (MFA Request Generation), T1078.004.

> **SOC Action:** Restrict Teams external federation to an allow-list of named tenants and disable open external chat in Teams admin centre; require Conditional Access "phishing-resistant MFA" for any MFA approval initiated from a non-corporate tenant. Hunt Microsoft 365 audit logs for `MessageSent` events where `SenderInfo.Domain` is external and the chat invitation was accepted within 5 minutes (`ChatCreated` followed by `MfaPrompt` from the same user inside 10 minutes). Brief users this week that "IT will never message you via Teams to approve an MFA prompt."

---

### 3.4 NFCShare Android banking malware via fake GitHub-hosted APKs

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/nfcshare-android-malware-spreads-via-fake-banking-app-updates-on-github/)

D3Lab tracked a May-2026 NFCShare campaign targeting Italian and Spanish bank customers (Intesa, Sella, Nexi, Fideuram, Mooney, CaixaBank). Victims arrive via phishing pages impersonating real banks, are funnelled to a GitHub repository hosting 56 trojanised APKs since April 10, and prompted to "verify" their card via NFC. The malware uses Android's `IsoDep` interface with EMV commands to read card number, type, expiry, and the user-supplied 4-digit PIN, then exfiltrates over a WebSocket channel to its C2 — enabling downstream NFC relay fraud (NGate / SuperCard X / RelayNFC ecosystem). Newer samples ship deliberately malformed ZIP entries in the APK to break static-analysis tooling. MITRE ATT&CK: T1566 (Phishing), T1071.001 (Web Protocols), T1437 (Standard Application Layer Protocol — mobile).

#### Indicators of Compromise
```
Distribution: GitHub repository (created 2026-04-10) hosting 56 APKs
APK names:    Intesa Carte.apk, Sella Carte.apk, Banca Sella Carte.apk,
              Nexi Carte.apk, Fideuram Carte.apk, Mooney Carte.apk,
              CaixaBank.apk, CaixaBankNfc.apk, CaixaReactivaTarjeta.apk
Behaviour:    Android IsoDep + EMV READ RECORD commands
Exfil:        WebSocket to attacker C2
Anti-analysis: Malformed APK ZIP path entries
```

> **SOC Action:** For EMEA-banking customers — block sideloading on managed Android via MDM (`UserManager.DISALLOW_INSTALL_UNKNOWN_SOURCES`), and ensure Play Protect is enforced. For SOC monitoring of corporate-owned mobile fleet: alert on installation of APKs sourced from `github.com` or `raw.githubusercontent.com` and on app packages whose Common Name impersonates known banks. For the fraud team, prime BIN ranges for Italian/Spanish issuers for elevated NFC-relay scrutiny.

---

### 3.5 Microsoft Patch Tuesday — 9 critical Linux/library RCE & LPE CVEs

**Source:** [Microsoft Security Response Center](https://msrc.microsoft.com/update-guide/) — see CVE links below

A single MSRC publication wave on 2026-06-09 brought a batch of nine **critical** open-source CVEs that affect virtually every Linux distribution and many Windows containers/WSL workloads:

- **Redis RCE × 3:** [CVE-2026-23479](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-23479) (use-after-free in unblock client flow), [CVE-2026-23631](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-23631) (Lua UAF), [CVE-2026-25243](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-25243) (RESTORE invalid memory access). All allow remote code execution against redis-server.
- **Xorg-x11-server / Xwayland:** [CVE-2026-50258](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-50258) (xkb key-types SBO) and [CVE-2026-50261](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-50261) (UAF in `syncchangecounter()`). Five additional **high**-severity Xorg flaws (CVE-2026-50256/50257/50259/50260/50262) round out the batch.
- **libinput:** [CVE-2026-50292](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-50292) — unescaped phys output in `libinput-device-group` injects udev properties, yielding **arbitrary root code execution** against pre-1.30.4 / 1.31.x<1.31.3.
- **bzip2:** [CVE-2026-42250](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-42250) — off-by-one OOB write during decompression, RCE-capable.
- **rrdtool:** [CVE-2026-43958](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-43958) — stack buffer overflow on malformed input → local code execution / DoS.
- **golang.org/x/crypto/ssh:** [CVE-2026-39835](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-39835) — server panic during `CheckHostKey`/`Authenticate`, weaponisable for DoS of every Go SSH server (Teleport, gitea, drone, custom bastions).

The pipeline correlation engine grouped these under shared TTP T1068 (Exploitation for Privilege Escalation) with confidence 0.70. MITRE ATT&CK: T1068, T1190, T1203.

> **SOC Action:** Prioritise patching in this order — (1) any internet-exposed redis-server (rotate Redis ACLs and confirm `bind` is not 0.0.0.0 before patching); (2) Go-binary SSH servers (rebuild against the patched `golang.org/x/crypto` and roll); (3) bzip2 (rebuild base images — libbz2 is in nearly every Linux image); (4) Xorg/Xwayland on workstation fleet; (5) libinput on workstation fleet (root LPE). Treat all Redis CVEs as remotely exploitable and run a scan for unauthenticated Redis on the perimeter (`shodan-style` 6379/TCP sweep) **before** patching to find shadow IT.

---

### 3.6 Termite, Qilin & Ransomhouse — sustained data-leak activity

**Source:** RansomLook aggregator — [Termite](https://www.ransomlook.io/group/termite), [Qilin](https://www.ransomlook.io/group/qilin), [Ransomhouse](https://www.ransomlook.io/group/ransomhouse)

Six new leak-site posts in the 24h window: Termite published `wieseusa.com` and `rolandmachinery.com`; Qilin published `The Banyans Health and Wellness` and `Kinetic Education`; Ransomhouse published `Aegle Aviation`. Sectoral spread covers healthcare/wellness, education, machinery/manufacturing, and aviation. Qilin sits at **75 reports** pipeline-wide over the trailing 30 days (#1 trending threat actor), with Termite returning after a gap. Pipeline correlation entry #1117 binds the Termite + Qilin posts via shared malware tag `RansomLook` (confidence 0.90). MITRE ATT&CK: T1486 (Data Encrypted for Impact), T1567.002 (Exfiltration to Cloud Storage).

> **SOC Action:** For organisations operationally similar to the named victims (US heavy-machinery distribution, AU wellness/healthcare, education-sector SaaS, regional aviation MRO): treat this as a sector-priority indicator. Validate offline immutable backups within 30 days, review remote-access exposure (Citrix/VPN, Veeam B&R, RDWeb), and pull internal data-egress baselines for the past 14 days (Rclone, MEGA, AnonFiles, Cloudflare R2 tunnels).

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|--------------------|
| 🟠 **HIGH** | Increased exploitation of privilege-escalation vulnerabilities across OS libraries and runtimes | libexpat CVE-2026-50219; OpenSC CVE-2026-40510; Redis CVE-2026-23479; Xorg CVE-2026-50257/50259/50260/50261; DBI CVE-2026-10879; Chrome CVE-2026-11645 (T1068, conf 0.70) |
| 🟠 **HIGH** | Sustained ransomware operations by Termite, Qilin, and Ransomhouse against healthcare, education, manufacturing, aviation | Wiese USA, Roland Machinery (Termite); Banyans Health, Kinetic Education (Qilin); Aegle Aviation (Ransomhouse) — shared RansomLook tag, conf 0.90 |
| 🟡 **MEDIUM** | Phishing pivoting from email to collaboration tools and supply-chain channels | MS Teams IT impersonation (Cloaked Ursa, UNC6692); NFCShare phishing→GitHub; Shai-Hulud PyPI; SoFi HK third-party breach; Telegram exploit channels (T1566, conf 0.50) |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors
- **Qilin** (75 reports) — Ransomware-as-a-Service; healthcare, education, retail; #1 active by volume
- **The Gentlemen** (57 reports) — Active double-extortion crew, regular leak-site updates
- **Akira** (34 reports) — Continues to dominate mid-market intrusions
- **DragonForce** (33 reports) — Aggressive leak-site posting cadence
- **TeamPCP** (30 reports) — Sustained activity over the trailing month
- **ShinyHunters** (24 reports) — Data-theft/extortion focus
- **Nova** (21 reports) — Active leak-site presence
- **Nightspire** (20 reports) — Mid-tier RaaS
- **Inc Ransom** / **Genesis** (17 reports each)
- **Cloaked Ursa (APT29)** / **UNC6692** — Featured in today's Teams phishing report (Unit 42)
- **Termite** / **Ransomhouse** — Active in today's leak-site cycle

### Malware Families
- **RansomLook** (103 reports) — Generic aggregator tag dominating the malware index
- **Tox1** (30) / **Tox** (22) — Communication tooling indicator across ransomware affiliates
- **Other1** (25) — Aggregator catch-all
- **Akira ransomware** (19) — Affiliate ecosystem
- **Mini Shai-Hulud** (13) / **Shai-Hulud** (11) — Supply-chain malware family active in today's PyPI campaign
- **The Gentlemen** (13) — Family name overlap with the actor
- **RALord** (12) / **Akira** (12)
- **NFCShare** — Featured in today's banking-malware report

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| Microsoft | 50 | [link](https://msrc.microsoft.com/update-guide/) | Bulk MSRC CVE publication wave — 9 critical, ~30 high |
| RansomLock | 6 | [link](https://www.ransomlook.io/) | Termite, Qilin, Ransomhouse leak-site posts |
| BleepingComputer | 5 | [link](https://www.bleepingcomputer.com/news/security/google-patches-fifth-chrome-zero-day-bug-exploited-in-attacks-this-year/) | Chrome zero-day; Shai-Hulud; NFCShare |
| Unit42 | 1 | [link](https://unit42.paloaltonetworks.com/microsoft-teams-phishing/) | MS Teams IT-impersonation campaign (Cloaked Ursa/UNC6692) |
| SANS | 1 | [link](https://isc.sans.edu/diary.html) | Daily handler diary |
| RecordedFutures | 1 | [link](https://therecord.media/) | Background reporting |
| Unknown | 2 | — | Telegram (channel name redacted) — dark-web exploit forum chatter |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Push Chrome 149.0.7827.102+ to all managed endpoints within 24h (CVE-2026-11645 is exploited in the wild). Validate via fleet telemetry that <1% of hosts remain on a pre-patch build by end of day.
- 🔴 **IMMEDIATE:** Inventory and quarantine the 19 trojanised PyPI bioinformatics packages (Dynamo, Spateo, CoolBox, U-FISH, Napari-UFISH and the full Socket list) across developer workstations, CI runners, and notebook environments. Rotate every secret class listed in §3.2 for any host that touched the packages.
- 🟠 **SHORT-TERM:** Patch the nine Microsoft-published critical CVEs (Redis ×3, Xorg ×2, libinput, bzip2, rrdtool, golang ssh) in the order recommended in §3.5. Prioritise internet-exposed Redis and Go-binary SSH servers.
- 🟠 **SHORT-TERM:** Lock down Microsoft Teams external federation to an allow-list and require phishing-resistant MFA for external-tenant interactions. Brief end-users this week that "IT will never DM you in Teams to approve MFA."
- 🟡 **AWARENESS:** Brief mobile-banking and EMEA customer-support teams on the NFCShare GitHub-APK distribution pattern; coordinate with the fraud team on elevated NFC-relay monitoring for Italian/Spanish issuer BINs.
- 🟢 **STRATEGIC:** Tabletop a Qilin-style data-theft scenario this quarter — Qilin is the pipeline's #1 active actor and is hitting healthcare/education/manufacturing weekly. Validate immutable backup integrity and partner-tenant trust boundaries (the path Cloaked Ursa exploits in §3.3).

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 66 reports processed across 1 correlation batch. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
