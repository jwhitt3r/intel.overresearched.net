---
layout: post
title:  "CTI Weekly Brief: 2026-06-01 to 2026-06-07 - npm Supply-Chain Worm, Cisco/Acer Zero-Days, Silent Ransom Callback Phishing"
date:   2026-06-08 09:00:00 +0000
description: "Weekly threat intelligence summary covering 469 reports across 15 sources: TeamPCP's Miasma worm hits @redhat-cloud-services npm packages, Acer Wave 7 max-severity zero-days, Cisco Unified CM PoC, actively-exploited Android and WordPress flaws, and Silent Ransom Group callback phishing against US law firms."
category: weekly
tags: [cti, weekly-brief, teampcp, miasma, qilin, cve-2026-3300, cve-2026-20230]
classification: TLP:CLEAR
reporting_period_start: "2026-06-01"
reporting_period_end: "2026-06-07"
generated: "2026-06-08"
draft: false
severity: critical
report_count: 469
sources:
  - Microsoft
  - RansomLook
  - BleepingComputer
  - AlienVault
  - RecordedFutures
  - CISA
  - SANS
  - Schneier
  - Upwind
  - Unit42
  - HaveIBeenPwned
  - Cisco Talos
  - Wired Security
  - Crowdstrike
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-06-01 to 2026-06-07 (7d) | TLP:CLEAR | 2026-06-08 |

## 1. Executive Summary

The pipeline processed 469 reports from 15 sources across the reporting period, with 37 rated critical and 256 rated high. The dominant narrative was the continued maturation of npm supply-chain attacks: on 1 June, the TeamPCP cluster pushed the **Miasma** worm into 32 packages under the `@redhat-cloud-services` scope, harvesting GitHub OIDC tokens, cloud credentials, and CI/CD secrets via an npm `preinstall` hook. Unit 42 published a parallel landscape update characterising the post-Shai-Hulud era as a "high-consequence threat landscape" with credential-free initial access techniques now in routine use.

Three additional critical issues warrant immediate attention: Cisco Unified Communications Manager **CVE-2026-20230** (SSRF to root, public PoC available); Acer Wave 7 mesh router max-severity zero-days **CVE-2026-49200/49201** (unauth credential disclosure and hardcoded AES backdoor, no patch until end of June); and a VS Code zero-day disclosed with PoC that allows one-click GitHub OAuth token theft via webview message-passing. Google's June Android bulletin shipped a fix for **CVE-2025-48595**, confirmed under limited targeted exploitation. WordPress saw two actively-exploited critical plugin flaws (**CVE-2026-3300** in Everest Forms Pro, **CVE-2026-8206** in Kirki), and Meta confirmed >20,000 Instagram accounts were hijacked through an AI-assisted support tool that failed to verify email ownership during password reset.

Ransomware activity remained intense: **Qilin** topped the trending threat actors at 68 reports, followed by The Gentlemen (42), Akira (33), and DragonForce (33). A new BlackByte affiliate variant — **Crux** — was confirmed active across US/UK targets, and the FBI/Mandiant-tracked **Silent Ransom Group (UNC3753 / Luna Moth)** continued aggressive callback-phishing operations against US law firms.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 37 | npm/Miasma worm; Cisco Unified CM CVE-2026-20230; Acer Wave 7 zero-days; VS Code GitHub-token zero-day; Android CVE-2025-48595; WordPress Everest Forms/Kirki RCE; Redis use-after-free chain |
| 🟠 **HIGH** | 256 | Ransomware leak-site postings (Qilin, Akira, DragonForce, Genesis, Nova, Coinbase Cartel); Silent Ransom Group law-firm campaign; C0XMO botnet; Instagram/Meta breach; Baker Distributing breach |
| 🟡 **MEDIUM** | 107 | Microsoft Patch Tuesday secondary CVEs; phishing TTP analyses; geopolitical tech-decoupling reporting |
| 🟢 **LOW** | 11 | Minor advisories and informational follow-ups |
| 🔵 **INFO** | 58 | Defender/EDR tuning; vendor blogposts; conference content |

## 3. Priority Intelligence Items

### 3.1 Miasma — Worming npm Supply-Chain Attack on Red Hat Cloud Services

**Source:** [Upwind](https://www.upwind.io/feed/miasma-npm-supply-chain-worm-redhat-credential-harvest), [Unit 42](https://unit42.paloaltonetworks.com/monitoring-npm-supply-chain-attacks/)

On 1 June 2026, unauthorised commits to the RedHatInsights GitHub organisation were used to publish 96 malicious versions across 32 packages in the `@redhat-cloud-services` npm scope (waves at ~10:53 UTC and 13:44–13:46 UTC). The campaign is tracked as **Miasma**, attributed by Upwind and Unit 42 to the **TeamPCP** cluster, and built on the public Mini Shai-Hulud code base that was open-sourced on 12 May 2026. Each package ships a `preinstall` hook (`node index.js`) that executes a 4.2 MB obfuscated payload through four de-obfuscation layers. The implant validates GitHub tokens, enumerates org secrets, scans `/proc/<pid>/mem` on GitHub Actions runners to recover masked workflow secrets, pulls cloud creds from AWS IMDS/ECS, Azure IMDS OAuth2, GCP metadata, HashiCorp Vault at `127.0.0.1:8200`, and Kubernetes service-account tokens; SSH keys, Docker credentials, `.env` files, GPG keys, and browser data are also taken. Propagation uses the harvested npm token's `bypass_2fa` parameter to publish backdoored versions of other packages the victim maintains, and creates a public repo titled "Miasma: The Spreading Blight" — the cleanest family fingerprint. The affected scope sees 80,000–117,000 weekly downloads. Red Hat's RHSB-2026-006 confirms no Hybrid Cloud Console release shipped during the compromise window; ARO, OpenShift Dedicated, ROSA, ACS Cloud Service, and AAP on Cloud are unaffected. **Affected:** npm consumers of `@redhat-cloud-services/*` direct or transitive on 1 June 2026. **ATT&CK:** T1195.002 (Supply Chain Compromise: Software), T1059.002, T1068, T1071.001, T1083, T1204.002.

#### Indicators of Compromise
```
Affected packages (representative):
  @redhat-cloud-services/chrome 2.3.1, 2.3.2, 2.3.4
  @redhat-cloud-services/frontend-components 7.7.2, 7.7.3, 7.7.5
  @redhat-cloud-services/types 3.6.1, 3.6.2, 3.6.4
  @redhat-cloud-services/rule-components 4.7.2, 4.7.3
  @redhat-cloud-services/rbac-client 9.0.3, 9.0.4, 9.0.6
Fingerprint: GitHub repo with description "Miasma: The Spreading Blight"
Payload: ~4.2 MB obfuscated index.js invoked via package.json "preinstall"
```

> **SOC Action:** Search package-lock.json / yarn.lock / pnpm-lock.yaml for any pinned `@redhat-cloud-services/*` versions installed on 1 June 2026 and quarantine those build artefacts. Rotate every GitHub PAT, GitHub Actions OIDC trust relationship, npm token, AWS/Azure/GCP key, Vault root token, Kubernetes SA token, and SSH key reachable by any affected runner. Hunt GitHub audit logs for repos created with description "Miasma: The Spreading Blight" and for `bypass_2fa=true` parameter on npm publish API calls. Add an EDR rule for `node index.js` invoked from `node_modules/**/preinstall`.

### 3.2 Cisco Unified CM Critical SSRF — CVE-2026-20230 (PoC Public)

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/cisco-warns-of-critical-unified-cm-flaw-with-poc-exploit-code/)

Cisco patched a critical (SIR: Critical) server-side request forgery flaw in Unified Communications Manager that allows an unauthenticated remote attacker to write arbitrary files to the underlying OS and escalate to root. Public proof-of-concept code exists; Cisco PSIRT has not yet observed active exploitation. The flaw only impacts systems with the **WebDialer** service enabled (disabled by default). Fixed releases: Unified CM 14SU6 or 15SU5 (September 2026 / COP). **ATT&CK:** T1190 (Exploit Public-Facing Application).

> **SOC Action:** Inventory Unified CM instances and check the WebDialer service status under Cisco Unified Serviceability → Tools → Service Activation → CTI Services. Where WebDialer is enabled and the device is not patched, disable the service immediately as the interim mitigation. Restrict management-plane access to the Unified CM HTTP interface to admin VLANs only, and monitor web logs for anomalous POST/PUT traffic against `/cucm-uds/` and CGI handlers.

### 3.3 Acer Wave 7 Mesh Router — Max-Severity Zero-Days (CVE-2026-49200 / CVE-2026-49201)

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/acer-warns-of-max-severity-zero-days-affecting-wave-7-routers/)

Two CVSS-10 zero-days disclosed by researcher Gergo Pap affect Wave 7 mesh routers on firmware `T7c_GBL_1.01.000055` or earlier. **CVE-2026-49200** exposes `acer_cgi.log` through the web interface without authentication, leaking cleartext web and Telnet credentials. **CVE-2026-49201** is a hardcoded AES key in `upload.cgi` that lets an unauthenticated remote attacker decrypt, modify, and re-encrypt system backups for persistent backdoor injection. No patch is available; Acer plans to ship firmware by end of June 2026. **ATT&CK:** T1078, T1496, T1550.

> **SOC Action:** Identify Acer Wave 7 devices on the network (admin UI at `http://192.168.76.1` or `http://acerconnect.com`). Disable remote management; if remote access is required, restrict to a known-good admin source IP allow-list. Alert on any unauthenticated GET request returning `acer_cgi.log` and on writes to `upload.cgi`. Rotate router admin credentials and Telnet creds even if the device is not remotely reachable, as the hardcoded key permits offline backup tampering.

### 3.4 VS Code GitHub-Token Theft Zero-Day (One-Click)

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/vs-code-zero-day-lets-hackers-steal-github-tokens-in-one-click/)

Researcher Ammar Askar publicly disclosed (with PoC) an unpatched, unassigned-CVE Visual Studio Code flaw that abuses the sandboxed webview message-passing system. Clicking a single malicious link causes JavaScript inside a webview to simulate keypresses in the host editor, install a malicious extension, and exfiltrate the GitHub OAuth token POSTed from `github.com` to `github.dev`. The token is not repo-scoped, so it grants full access to every private repository the victim can read. Mitigation pending vendor patch: clear cookies and site data for `github.dev`, then re-authenticate so the `GitHub Repositories` sign-in prompt re-appears. **ATT&CK:** T1078.004, T1566, T1539 (Steal Web Session Cookie).

> **SOC Action:** Push a guidance note to engineering: clear `github.dev` cookies/site data and re-authenticate. Audit GitHub organisation audit logs for unusual `repo` enumeration patterns from new OAuth token sessions over the past 7 days. Consider temporarily restricting `github.dev` via browser policy on enterprise-managed endpoints until a VS Code patch is released. Where SSO/SAML enforcement is available, require it on all org repos and rotate any PATs that share scope with OAuth grants.

### 3.5 Android June 2026 Bulletin — CVE-2025-48595 Under Active Exploitation

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/google-fixes-one-actively-exploited-android-zero-day-124-flaws/)

Google's June 2026 Android Security Bulletin fixed 124 flaws, including 18 critical issues and **CVE-2025-48595**, a high-severity Android Framework code-execution / privilege-escalation flaw under limited, targeted exploitation on Android 14+. No user interaction required. Google has not yet released technical details; historically, similar Framework flaws have been used by commercial spyware vendors and nation-state operators. Pixel devices receive the fix immediately; OEM rollouts will lag.

> **SOC Action:** Push Android 2026-06-05 patch level via MDM (Intune / Jamf / Workspace ONE) to all corporate Android devices, with priority on devices belonging to executives, legal, comms, and any users with travel exposure to surveillance-active jurisdictions. Block non-compliant devices from corporate mail and conditional-access apps. Hunt for unusual escalations or background process creations in mobile EDR telemetry over the past 30 days on high-value-target devices.

### 3.6 WordPress: Two Actively-Exploited Critical Plugin Flaws

**Source:** [BleepingComputer (Everest Forms)](https://www.bleepingcomputer.com/news/security/critical-everest-forms-pro-flaw-exploited-to-take-over-wordpress-sites/), [BleepingComputer (Kirki)](https://www.bleepingcomputer.com/news/security/critical-kirki-flaw-exploited-to-hijack-wordpress-admin-accounts/)

**CVE-2026-3300** in Everest Forms Pro (≤ 1.9.12): the Complex Calculation feature passes form input into `eval()` without escaping quotes, allowing unauthenticated PHP code injection. Wordfence has blocked over 29,300 exploit attempts; attackers are creating rogue admin accounts using `wp_insert_user()` (commonly username `diksimarina`). Patch in 1.9.13+. **CVE-2026-8206** in Kirki (6.0.0–6.0.6, on 500k+ sites): `handle_forgot_password()` accepts an attacker-supplied email during password reset, sending the reset link to the attacker rather than the registered account email — enabling account takeover including administrator accounts. Patched in 6.0.7; Wordfence blocked 222+ attempts in 24h. **ATT&CK:** T1059.001 (PHP), T1078 (Valid Accounts).

#### Indicators of Compromise
```
Everest Forms exploit source IPs: 202.56.2[.]126, 209.146.60[.]26
Rogue admin username string: "diksimarina"
Kirki target endpoint: REST API /wp-json/.../handle_forgot_password
```

> **SOC Action:** Inventory all WordPress estates for Everest Forms Pro and Kirki; force-update to 1.9.13+ and 6.0.7+ respectively, or disable the plugins. Block source IPs `202.56.2[.]126` and `209.146.60[.]26` at the WAF. Query the `wp_users` table for any administrator accounts created since 13 April 2026 and review usernames for `diksimarina`. Review WordPress access logs for password-reset POSTs that target admin usernames from external email addresses.

### 3.7 Meta AI-Support Tool Breach — 20,000+ Instagram Accounts Hijacked

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/meta-ai-support-data-breach-affects-20-000-instagram-accounts/)

Meta confirmed in a Maine OAG breach filing that a vulnerability in its AI-assisted **High Touch Support (HTS)** account-recovery system allowed attackers to perform Instagram password resets without 2FA, because HTS failed to verify whether the supplied email was actually associated with the targeted account. First exploitation observed 17 April 2026; Meta disabled HTS and invalidated all reset links generated by the tool on 31 May 2026. Potential exposure includes contact info, DOB, posts, DMs, profile data, and linked accounts. Pattern echoes the Kirki WordPress flaw — both are recovery-flow logic errors that fail to bind the reset token to the legitimate identity. **ATT&CK:** T1556 (Modify Authentication Process), T1566.

> **SOC Action:** For executive and brand-protection accounts, audit linked Instagram/Meta business accounts for unauthorised admin changes since 17 April 2026 and reset credentials. Treat this as a template threat: review your own organisation's account-recovery flows (especially anything with an LLM-mediated agent) for the same defect — verifying that the email/SMS reset target is bound to the account record before issuing tokens.

### 3.8 Silent Ransom Group / UNC3753 / Luna Moth — Law-Firm Callback Phishing

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/silent-ransom-group-targets-law-firms-with-fake-it-support-calls/)

Mandiant detailed dozens of attacks between January and May 2026 by **UNC3753** (a.k.a. Silent Ransom Group, Luna Moth, Chatty Spider) against US legal, financial, and professional services firms. The chain begins with benign invoice-themed phishing emails from consumer email accounts (no links/attachments), followed by phone calls in which attackers impersonate IT helpdesks and convince employees to join remote-support sessions via Microsoft Teams, Zoom, Quick Assist, or Terminal Services. During the session, victims install RMM tools (AnyDesk, Zoho Assist, Bomgar, SuperOps). The group uses `privnote[.]com` to share installation links/commands (reducing forensic artefacts) and registers phishing domains following the pattern `<organization>-itdesk[.]com`, `<organization>-it[.]com`, `<organization>-helpdesk[.]com`. Data is exfiltrated with WinSCP or Rclone; ransom demands typically arrive within 30 minutes of attacker departure. Follows last week's FBI FLASH on the same actor. **ATT&CK:** T1566, T1021, T1071.001, T1219 (Remote Access Software), T1567.002 (Exfil to Cloud Storage).

> **SOC Action:** Block install/execution of unsanctioned RMM tools (AnyDesk, Zoho Assist, Bomgar, SuperOps, Quick Assist) via AppLocker / WDAC / Defender ASR rule "Block process creations originating from PSExec and WMI commands" and via EDR. Alert on outbound connections to `privnote[.]com`. Add domain-monitoring queries for newly-registered look-alikes matching `*-itdesk[.]com`, `*-it[.]com`, `*-helpdesk[.]com` against your brand. Run helpdesk-impersonation tabletop exercise with the legal and finance teams; require call-back to a known internal number before any remote-support session.

### 3.9 C0XMO Botnet — Gafgyt Variant on DD-WRT (CVE-2021-27137)

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/c0xmo-botnet-spreads-via-dd-wrt-router-flaw-kills-rival-malware/)

Fortinet identified **C0XMO**, a new modular Gafgyt-derived botnet targeting DD-WRT firmware via CVE-2021-27137 (unauthenticated buffer overflow). It supports ARM, MIPS, PowerPC, SuperH, x86/x64 and includes 19 DDoS methods (UDP/TCP/SYN/ICMP floods, ping of death, NTP/Memcached amplification, Discord voice UDP floods, Valve-specific floods). Propagation uses a Python script (`requests`, `paramiko`, `beautifulsoup4`) scanning ports 22, 23, 80, 443, 7547, 8080, 8443, 8888, brute-forcing weak SSH/Telnet creds. Persistence via copies in `/tmp/.sys`, `/var/tmp/.sys`, `/dev/shm/.sys` and 15-minute cron jobs; modifies shell startup files. Actively kills rival botnet clients and red-team tools. Initial reported targeting: a Japanese tech firm from a German source IP. **ATT&CK:** T1190, T1071, T1090, T1496.

> **SOC Action:** Patch any DD-WRT or DVR/video appliances reachable from the internet to firmware that addresses CVE-2021-27137. Egress-block outbound Telnet (23) from internal networks. Monitor for SSH brute-force from internet-facing IoT/edge devices and alert on creation of files matching `/tmp/.sys`, `/var/tmp/.sys`, `/dev/shm/.sys` on Linux endpoints.

### 3.10 BlackByte's Crux Variant — Confirmed Active

**Source:** [RansomLook (blackbyte-crux)](https://www.ransomlook.io//group/blackbyte-crux)

**Crux** is a ransomware variant active since July 2025 claiming affiliation with the established BlackByte operation; double-extortion model with a Tor leak portal. Execution chain abuses `svchost.exe`, `cmd.exe`, and `bcdedit.exe` to disable Windows Recovery before rapid encryption with the `.crux` extension. Ransom note pattern: `crux_readme_[random].txt`. At least three confirmed incidents across agriculture, education, professional services, media, and nonprofits in the US and UK. Latest leak-site posting on 7 June 2026 (Quanticate Ltd, UK professional services). **ATT&CK:** T1486 (Data Encrypted for Impact), T1490 (Inhibit System Recovery), T1003 (OS Credential Dumping).

#### Indicators of Compromise
```
Ransom note pattern: crux_readme_[random].txt
File extension: .crux
Contact email: BlackBCruxSupport@onionmail[.]org
Leak portal: hxxp[:]//dounczge5jhw4iztnnpzp54kd4ot3tikhjsimurtcewqssgye6vvrhqd[.]onion/
File server: hxxp[:]//faow6n2hkweyyalp67zvonafn2dzphw36cav653wamj724mwsmtfa5yd[.]onion/
Recovery-disable chain: bcdedit /set {default} bootstatuspolicy ignoreallfailures, bcdedit /set {default} recoveryenabled No
```

> **SOC Action:** Build an EDR detection on `bcdedit.exe` invocations with `ignoreallfailures` or `recoveryenabled No` arguments — high-fidelity, low-FP for ransomware kill-chain pre-encryption. Alert on creation of `crux_readme_*.txt` and any file rename with extension `.crux`. Block resolver-level queries for the two `.onion` hosts above (where Tor egress is policy-prohibited).

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Advanced exploitation by botnets to spread and eliminate competition, indicating a maturing IoT-botnet landscape | C0XMO via DD-WRT CVE-2021-27137 |
| 🔴 **CRITICAL** | Exploitation of widely-used WordPress plugin ecosystem to take full control of public sites | Everest Forms Pro CVE-2026-3300 active exploitation |
| 🔴 **CRITICAL** | Active exploitation of widely-used infrastructure components (CISA KEV) | SolarWinds Serv-U; PAN-OS CVE-2026-0257 |
| 🔴 **CRITICAL** | Cloud-service vulnerability exploitation by threat actors | Azure HorizonDB EoP CVE-2026-48567; fake helpdesk credential theft |
| 🔴 **CRITICAL** | Exploitation of widely-deployed packages and language runtimes | libsolv CVE-2026-9149; Go SSH CVE-2026-39835; jq stack/heap flaws; Redis use-after-free chain (CVE-2026-23479, -23631, -25243) |
| 🔴 **CRITICAL** | Ransomware groups targeting diverse sectors with sophisticated TTPs | Akira (National Standard Parts Associates; Northern Ohio Regional MLS); The Gentlemen; DragonForce |
| 🔴 **CRITICAL** | Targeting of critical infrastructure (government and healthcare) by various actors | Chinese-attributed Atlas RAT against European targets; "The Gentlemen" Michigan Surgical Centre |
| 🔴 **CRITICAL** | Supply-chain attacks exploiting npm and software development ecosystems | Miasma worm in @redhat-cloud-services; Mini Shai-Hulud waves; ongoing Shai-Hulud descendants |
| 🟠 **HIGH** | Increased ransomware activity targeting healthcare and manufacturing globally | Blackwater (utourworld.com), Inc Ransom (kelmreuter.com), Genesis (*B*) |
| 🟠 **HIGH** | Coinbase Cartel targeting technology and manufacturing with CoinBreach ransomware | Demand.io; Cambridge Mobile Telematic |
| 🟠 **HIGH** | Increased targeting of professional services across multiple vectors | BlackByte/Crux (Quanticate); Silent Ransom Group (US law firms) |
| 🟠 **HIGH** | Phishing remains a prevalent vector, often combined with other TTPs | 2026 DBIR "browser as the new endpoint"; Evil MSI campaign; Operation TaxShadow |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **Qilin** (68 reports) — dominant ransomware leak-site activity for the week; broad sector targeting
- **The Gentlemen** (42 reports) — continued leak-site velocity; Tox-family payload variants
- **Akira** (33 reports) — Akira ransomware affiliates active against manufacturing, MLS, and SMB sectors
- **DragonForce** (33 reports) — sustained double-extortion campaigns
- **TeamPCP** (29 reports) — npm supply-chain cluster behind Miasma and Mini Shai-Hulud waves
- **ShinyHunters** (25 reports) — credited with the Baker Distributing breach (102,935 accounts)
- **Genesis** (22 reports) — healthcare and legal-services focus
- **Nova** (21 reports) — healthcare (e.g., Aspire Hospital, Universitas Nasional)
- **Inc Ransom** (18 reports) — manufacturing and B2B services
- **Stormous** (17 reports) — broad sector phishing-led intrusions
- **Coinbase Cartel** (16 reports) — CoinBreach ransomware against technology and manufacturing
- **Nightspire** (16 reports) — sustained leak-site posting cadence
- **Everest** (12 reports) — Everest ransomware continuing leak operations
- **Lockbit5** (12 reports) — early observation of LockBit 5 branded variant
- **Safepay** (11 reports) — emerging operation across multiple sectors

### Malware Families

- **RansomLook** (105 reports) — aggregated leak-site activity tracker (meta-category, not a malware family per se)
- **Tox1 / Tox / Tox2** (49 combined) — Tox-family payload variants linked to The Gentlemen and Stormous
- **Akira ransomware / Akira** (30 combined) — encryptor active across affiliates
- **RALord** (12 reports) — emergent ransomware family
- **Mini Shai-Hulud** (11 reports) — npm-supply-chain worm framework used by TeamPCP and copycats
- **Nova** (11 reports) — ransomware family
- **Shai-Hulud** (10 reports) — original npm-supply-chain worm code base
- **Nightspire** (9 reports) — ransomware payload
- **Everest ransomware** (9 reports)
- **Inc Ransom** (6 reports)
- **Crux** (BlackByte variant) — confirmed in three+ incidents; rapid `bcdedit`-driven recovery disable
- **C0XMO** (Gafgyt variant) — modular IoT botnet, DD-WRT CVE-2021-27137
- **Miasma** — TeamPCP's June 2026 npm worm payload

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| Microsoft | 191 | [link](https://msrc.microsoft.com/update-guide) | MSRC vulnerability advisories; libexpat, Redis, jq, Go SSH, GnuTLS, Azure HorizonDB, M365 Copilot |
| RansomLook | 102 | [link](https://www.ransomlook.io/) | Ransomware leak-site aggregation (Qilin, Akira, Genesis, Nova, BlackByte-Crux, etc.) |
| BleepingComputer | 47 | [link](https://www.bleepingcomputer.com/news/security/cisco-warns-of-critical-unified-cm-flaw-with-poc-exploit-code/) | Primary coverage of Cisco Unified CM, Acer, VS Code, Android, WordPress, Silent Ransom Group |
| Unknown | 28 | — | Includes Telegram-origin OSINT (channel name redacted) |
| AlienVault | 23 | [link](https://otx.alienvault.com/) | Open Threat Exchange pulses |
| RecordedFutures | 15 | [link](https://www.recordedfuture.com/research) | Strategic threat reporting |
| CISA | 9 | [link](https://www.cisa.gov/news-events/alerts) | KEV additions (Serv-U), advisories |
| SANS | 9 | [link](https://isc.sans.edu/) | ISC diaries — Evil MSI, browser-living threats |
| Schneier | 6 | [link](https://www.schneier.com/) | Commentary and analysis |
| Upwind | 6 | [link](https://www.upwind.io/feed/miasma-npm-supply-chain-worm-redhat-credential-harvest) | Primary technical report on Miasma |
| Wired Security | 6 | [link](https://www.wired.com/category/security/) | Policy and threat-trend reporting |
| Crowdstrike | 3 | [link](https://www.crowdstrike.com/blog/) | Adversary intelligence |
| Unit42 | 3 | [link](https://unit42.paloaltonetworks.com/monitoring-npm-supply-chain-attacks/) | npm threat landscape update |
| HaveIBeenPwned | 3 | [link](https://haveibeenpwned.com/Breach/BakerDistributing) | Baker Distributing (102,935 accounts) |
| Cisco Talos | 3 | [link](https://blog.talosintelligence.com/) | Threat research |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Quarantine all build artefacts that pinned `@redhat-cloud-services/*` packages installed on 1 June 2026; rotate every GitHub PAT, npm token, GitHub Actions OIDC trust, cloud key, Vault root token, Kubernetes SA token, and SSH key reachable by affected runners (Miasma — §3.1).
- 🔴 **IMMEDIATE:** Identify Cisco Unified CM systems with WebDialer enabled; disable WebDialer as an interim mitigation and schedule the 14SU6 / 15SU5 upgrade (CVE-2026-20230 — §3.2).
- 🔴 **IMMEDIATE:** Push the Android 2026-06-05 patch level via MDM for any device used by high-value targets, particularly executives, legal staff, and travelling personnel (CVE-2025-48595 — §3.5).
- 🔴 **IMMEDIATE:** Inventory WordPress estates for Everest Forms Pro and Kirki plugins; force-update or disable and audit `wp_users` for admin accounts created after 13 April 2026 (especially username `diksimarina`) (§3.6).
- 🟠 **SHORT-TERM:** Disable remote management on Acer Wave 7 routers and rotate credentials in anticipation of late-June firmware (CVE-2026-49200/49201 — §3.3).
- 🟠 **SHORT-TERM:** Block install/execution of unsanctioned RMM tooling (AnyDesk, Zoho Assist, Bomgar, SuperOps, Quick Assist); run a callback-phishing tabletop with helpdesk, legal, and finance teams (Silent Ransom Group — §3.8).
- 🟠 **SHORT-TERM:** Issue engineering guidance to clear `github.dev` cookies and re-authenticate; review GitHub org audit logs for unusual repo-enumeration via OAuth tokens (VS Code zero-day — §3.4).
- 🟡 **AWARENESS:** Audit your own recovery flows (especially LLM-mediated agents) for the Meta/HTS and Kirki defect class — failing to bind reset tokens to the legitimate identity (§3.6, §3.7).
- 🟢 **STRATEGIC:** Treat npm/PyPI/RubyGems package consumption as untrusted code execution by default — enforce CI-side dependency pinning with checksum verification, isolate build runners, and prevent CI/CD secrets from being readable to arbitrary `preinstall` scripts. The Shai-Hulud / Mini Shai-Hulud / Miasma lineage is now an established threat pattern (§3.1).
- 🟢 **STRATEGIC:** Tune EDR for ransomware kill-chain primitives that recur across families — `bcdedit /set ... recoveryenabled No`, vssadmin shadow-copy deletion, and `wbadmin delete catalog`. These provide high-fidelity, family-independent detections (BlackByte/Crux — §3.10).

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 469 reports processed across 14 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
