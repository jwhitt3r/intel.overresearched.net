---
layout: post
title:  "CTI Weekly Brief: 15-21 June 2026 - Microsoft 365 Copilot vulnerability spree, FortiBleed credential dump, and four CISA emergency-patch orders"
date:   2026-06-22 08:15:42 +0000
description: "524 reports processed across 14 correlation batches: a wave of critical Microsoft 365 Copilot flaws, the FortiBleed leak of 73k Fortinet VPN credentials, four CISA actively-exploited emergencies (Splunk, Joomla JCE, Cisco SD-WAN, FortiSandbox), the @mastra npm supply-chain compromise attributed to North Korea's Sapphire Sleet, and a looming Secure Boot certificate expiration on 24 June."
category: weekly
tags: [cti, weekly-brief, shinyhunters, qilin, sapphire-sleet, cve-2026-42824, cve-2026-20253, fortibleed]
classification: TLP:CLEAR
reporting_period_start: "2026-06-15"
reporting_period_end: "2026-06-21"
generated: "2026-06-22"
draft: false
severity: critical
report_count: 524
sources:
  - Microsoft
  - BleepingComputer
  - CISA
  - Wired Security
  - HaveIBeenPwned
  - Upwind
  - Wiz
  - RansomLook
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-06-15 to 2026-06-21 (7d) | TLP:CLEAR | 2026-06-22 |

## 1. Executive Summary

The CognitiveCTI pipeline processed **524 reports** across **14 correlation batches** during the week of 15-21 June 2026, with 25 rated critical and 371 rated high. The week was dominated by AI-platform exposure and identity-provider attacks: Microsoft disclosed five critical flaws in Microsoft 365 Copilot and Azure AD on Patch Tuesday, Varonis published the **SearchLeak** chain (CVE-2026-42824) that weaponises Copilot Enterprise into a one-click data-theft tool, and Microsoft attributed the prior week's **@mastra npm supply-chain compromise** (>140 packages, easy-day-js dropper) to North Korean state actor **Sapphire Sleet / BlueNoroff**.

CISA issued four short-fuse emergency directives under BOD 26-04 for actively-exploited flaws in **Splunk Enterprise (CVE-2026-20253)**, **Joomla JCE plugin (CVE-2026-48907)**, **Cisco Catalyst SD-WAN Manager (CVE-2026-20262)** and **Fortinet FortiSandbox (CVE-2026-39813/39808/25089)** — all confirmed in-the-wild. Researcher Bob Diachenko published the **FortiBleed** dataset exposing valid Fortinet/FortiGate VPN credentials for 73,932 firewall URLs across 21,632 domains worldwide, attributed to a Russian-speaking multi-operator group. Ransomware operations remained at high volume, with **Qilin** (67 reports), **The Gentlemen** (72), **Deadlock** (55) and **Lockbit5** (39) leading victim postings, and the **Nova/RALord** rebrand continuing to expand. Operators should also note the 24 June expiration of three Microsoft-signed Secure Boot certificates — a strategic risk to UEFI bootkit defences that demands action this week.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 25 | M365 Copilot SearchLeak + Patch Tuesday flaws; FortiBleed; Cisco SD-WAN, Splunk, Joomla, FortiSandbox actively-exploited; F5 NGINX out-of-band; Mastra npm supply chain; RoguePlanet Defender 0-day; JCPenney/ShinyHunters |
| 🟠 **HIGH** | 371 | Ransomware victim postings (Qilin, The Gentlemen, Lockbit5, Nova, Worldleaks, Inc Ransom); Sapphire Sleet attribution; AryStinger D-Link botnet; Secure Boot expiry; MSG/ShinyHunters leak; Prinz Eugen ransomware |
| 🟡 **MEDIUM** | 63 | Microsoft Patch Tuesday secondary CVEs; OXLOADER / FlutterShell macOS backdoor; ClickFix AI-generated lures |
| 🟢 **LOW** | 13 | Low-confidence Telegram OSINT, miscellaneous research notes |
| 🔵 **INFO** | 52 | RansomLook telemetry pages, threat-actor profile updates |

## 3. Priority Intelligence Items

### 3.1 Microsoft 365 Copilot SearchLeak — one-click enterprise data theft (CVE-2026-42824)

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/new-attack-turned-microsoft-365-copilot-into-1-click-data-theft-tool/)

Varonis disclosed **SearchLeak**, a maximum-severity vulnerability chain in Microsoft 365 Copilot Enterprise that allows attackers to exfiltrate mailbox, OneDrive and SharePoint content via a single crafted URL. The chain combines a **parameter-to-prompt (P2P) injection** in Copilot Search's `q` URL parameter, an **HTML rendering race condition** that executes attacker-controlled `<img>` tags before sanitisation, and a **CSP bypass** via Bing's "Search by Image" SSRF feature — Bing fetches the image URL containing the exfiltrated data, and the attacker reads it from their server logs. From the victim's perspective, Copilot simply "thinks" for a moment. Microsoft patched the issue server-side at the start of June; no customer action is required for SearchLeak itself, but the attack class (prompt injection + LLM output rendering + allowlisted SSRF) generalises to every agentic AI surface in the enterprise stack. Relevant ATT&CK techniques: T1189 (Drive-by Compromise), T1566 (Phishing).

> **SOC Action:** Audit and inventory all Copilot Enterprise Search activations across M365 tenants. Enable Purview audit logging for `CopilotInteraction` and `SearchQueryInitiated` events. Hunt for outbound image requests from Copilot rendering hosts to non-Microsoft domains in the prior 30 days, and brief users that crafted Copilot links should be treated with the same suspicion as phishing URLs.

### 3.2 Microsoft Patch Tuesday — four additional critical Copilot / Azure AD / Dynamics flaws

**Source:** [Microsoft MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45480), [MSRC CVE-2026-47645](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-47645), [MSRC CVE-2026-42895](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-42895), [MSRC CVE-2026-54130](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-54130)

Beyond SearchLeak, the 18 June Patch Tuesday cycle (internally referred to as "Nightmare Eclipse") shipped fixes for four further critical-severity flaws: **CVE-2026-45480** (Azure Active Directory elevation of privilege via improper authentication), **CVE-2026-47645** (M365 Copilot Business Chat EoP via open redirect), **CVE-2026-42895** (Microsoft Copilot command-injection tampering), and **CVE-2026-54130** (M365 Copilot information disclosure via missing authentication on a critical function). Two further critical flaws — **CVE-2026-47647** (Dynamics 365 EoP) and **CVE-2026-47633** (Microsoft Cost Management info disclosure) — round out the cycle. All are network-exploitable; none required user authentication in the worst cases.

> **SOC Action:** Confirm Microsoft cloud-tenant patches landed (most are service-side, but verify Edge / Entra connector versions in inventory). Pull Entra sign-in logs for anomalous privilege escalations against synced and cloud-only identities for the 18–22 June window. Add Dynamics 365 and Cost Management admin role assignments to your privileged-access weekly review.

### 3.3 CISA emergency directives — four BOD 26-04 patch orders in seven days

**Sources:** [BleepingComputer — Splunk](https://www.bleepingcomputer.com/news/security/cisa-splunk-enterprise-flaw-actively-exploited-patch-by-sunday/), [BleepingComputer — Joomla JCE](https://www.bleepingcomputer.com/news/security/cisa-orders-feds-to-patch-max-severity-joomla-plugin-flaw-by-friday/), [BleepingComputer — Cisco SD-WAN](https://www.bleepingcomputer.com/news/security/cisco-fixes-sd-wan-vmanage-flaw-exploited-in-zero-day-attacks/), [BleepingComputer — FortiSandbox](https://www.bleepingcomputer.com/news/security/critical-fortinet-fortisandbox-flaws-now-exploited-in-attacks/)

CISA issued four actively-exploited emergency patch orders against FCEB agencies this week under the new BOD 26-04 framework:

- **CVE-2026-20253 — Splunk Enterprise** (versions 10.2.0–10.2.3, 10.0.0–10.0.6): unauthenticated arbitrary file create/truncate via PostgreSQL sidecar; WatchTowr published a PoC on 12 June; Splunk confirmed in-the-wild exploitation on 18 June; Shadowserver tracks **1,400+ exposed instances** (952 NA, 223 EU). Patch deadline: Sunday 22 June.
- **CVE-2026-48907 — Joomla JCE Pro plugin** (Widget Factory Content Editor): max-severity unauthenticated PHP upload/execution via new editor profile creation; automated exploitation; deadline Friday 19 June. The JCE security team explicitly warned that patching closes the entry point but does not remediate already-compromised sites.
- **CVE-2026-20262 — Cisco Catalyst SD-WAN Manager (formerly vManage)**: file upload validation flaw allows low-privilege remote attacker to write arbitrary files and escalate to root via crafted HTTP requests to API endpoints. All deployment types affected (on-prem, Cloud-Pro, Cisco-Managed, FedRAMP). Cisco IOCs: check `vmanage-server`, `vmanage-appserver` and `serviceproxy-access` logs for `index.jsp` and `.war` upload attempts.
- **CVE-2026-39813 / -39808 / -25089 — Fortinet FortiSandbox**: unauthenticated command injection enabling privilege escalation and RCE with no user interaction. Patches were released 14 April; exploitation began in the 24 hours before Defused's 16 June advisory.

> **SOC Action:** Treat this as a coordinated, week-long patch cycle. For Splunk, immediately upgrade to fixed releases or disable the PostgreSQL sidecar service (this will break Edge Processor, OpAmp and SPL2 pipelines — accept the outage). For Joomla, scan all internet-facing sites for the JCE plugin, patch to 2.9.99.6+, then run a full server-side IR review including profile audit, credential rotation and malware sweep — patching alone does not evict attackers. For Cisco SD-WAN, hunt the named log files for upload attempts of the IOC filenames before applying the matrix patches. For FortiSandbox, prioritise externally-reachable management interfaces and check `fortiguard` heartbeat anomalies.

### 3.4 FortiBleed — 73,932 Fortinet VPN credentials exposed worldwide

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/fortibleed-leak-exposes-fortinet-vpn-credentials-for-73-000-devices/)

Security researcher Bob Diachenko discovered an open server holding what appears to be valid FortiGate SSL VPN credentials (usernames, emails, plaintext passwords) for **73,932 unique firewall URLs across 21,632 domains in 194 countries**. The dataset is attributed to a Russian-speaking multi-operator threat group that allegedly conducted approximately **1.16 billion credential attempts against 320,777 FortiGate targets** and a further 2.1 billion against 163,650 MS SQL Server systems, using a 45-GPU Hashtopolis cluster to crack intercepted SSL VPN authentication hashes. Hudson Rock independently confirmed the dataset and named **Chevron, Samsung, Foxconn, Comcast, AT&T, Mercedes-Benz, Toyota, Siemens, Lenovo, PwC, Accenture, Oracle**, and multiple government and critical-infrastructure operators as appearing in the records. The most-affected countries by device count: India, US, Taiwan, Mexico, Turkey, Thailand, Colombia, Malaysia, Chile and the UAE. The operators left an open directory containing tooling, cron-job logs and bash histories — Diachenko reports a Turkish NATO defence contractor was fully compromised, with classified documents allegedly stolen. ATT&CK: T1003 (OS Credential Dumping), T1078 (Valid Accounts), T1550 (Use Alternate Auth Material), T1566 (Phishing).

> **SOC Action:** Assume FortiGate SSL VPN credentials are compromised. Force a **password rotation for every SSL VPN account**, enforce MFA on every SSL VPN portal (no exceptions), revoke and re-issue VPN client certificates, and hunt for AD lateral movement from VPN-assigned IP ranges over the last 90 days using authentication events 4624/4625, Kerberos TGS requests, and SMB session creates. If you operate a FortiGate, treat your perimeter as breached until you can prove otherwise.

### 3.5 @mastra npm supply-chain compromise attributed to North Korea (Sapphire Sleet / BlueNoroff)

**Sources:** [Upwind](https://www.upwind.io/feed/mastra-supply-chain-compromise-easy-day-js-dropper-pulls-a-cross-platform-rat-into-mastra-installs), [BleepingComputer — Microsoft attribution](https://www.bleepingcomputer.com/news/security/microsoft-links-mastra-ai-supply-chain-attack-to-north-korean-hackers/)

On 17 June, attackers compromised the npm maintainer account `ehindero` and published malicious updates to **140+ packages in the @mastra/* scope** (the Mastra AI framework, >1M weekly downloads). Every compromised package gained a dependency on `easy-day-js@1.11.22`, a typosquat of `dayjs` whose `postinstall` script (`setup.cjs`) disables TLS verification, fetches a cross-platform RAT from `23.254.164[.]92:8000`, and persists on Windows (Registry Run key `NvmProtocal`), macOS (`~/Library/LaunchAgents/com.nvm.protocal.plist`), and Linux (user systemd unit `nvmconf.service`). The second-stage payload enumerates 166 cryptocurrency wallet extensions (MetaMask, Phantom, Coinbase Wallet, Binance Wallet, TronLink, etc.) and exfiltrates browser histories, host metadata, and tokens. Microsoft attributes the campaign with high confidence to **Sapphire Sleet / BlueNoroff** based on a PowerShell backdoor, C2 infrastructure overlap, and Defender-exclusion tradecraft seen in the same actor's April 2026 Axios HTTP client compromise. Relevant ATT&CK techniques: T1071 (Application Layer Protocol), T1547 (Boot/Logon Autostart Execution), T1547.001 (Registry Run Keys), T1566 (Phishing).

#### Indicators of Compromise

```
Network C2:        23.254.164[.]92:8000  (stage-2 dropper)
                   23.254.164[.]123
User-Agent:        mozilla/4.0 (compatible; msie 8.0; windows nt 5.1; trident/4.0)
npm package:       easy-day-js@1.11.21, easy-day-js@1.11.22
File markers:      $TMPDIR/.pkg_history, $TMPDIR/.pkg_logs
macOS persist:     ~/Library/NodePackages/, ~/Library/LaunchAgents/com.nvm.protocal.plist
Linux persist:     systemctl --user status nvmconf.service
Windows persist:   HKCU\Software\Microsoft\Windows\CurrentVersion\Run\NvmProtocal
Lockfile grep:     grep -r "easy-day-js" package-lock.json yarn.lock pnpm-lock.yaml
```

> **SOC Action:** Treat any developer workstation or CI runner that ran `npm i` against a `@mastra/*` package since 2026-06-17 01:15 UTC as potentially compromised. Block `23.254.164.0/24` at egress, run the lockfile and persistence checks above on dev fleets, and rotate any developer credentials, npm tokens, GitHub PATs, cloud access keys and crypto-wallet seeds that may have been accessible. Add `easy-day-js` to any internal package-blocklist (Verdaccio / JFrog / GitHub Packages).

### 3.6 F5 out-of-band patches for critical NGINX RCE/DoS vulnerabilities

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/f5-issues-out-of-band-patches-for-critical-nginx-vulnerabilities/)

F5 released out-of-band patches for two critical NGINX vulnerabilities: **CVE-2026-42530** (RCE in `ngx_http_v3_module` on NGINX 1.31 when HTTP/3 features are enabled) and **CVE-2026-42055** (DoS / code execution in `ngx_http_proxy_v2_module`). Both are exploitable by unauthenticated remote attackers against NGINX instances with specific configurations. Workarounds include disabling HTTP/3 and adjusting the relevant configuration directives. A separate Russian-language Telegram post on 18 June circulated additional CVE-2026-42530 exploit context to lower-tier actors.

> **SOC Action:** Inventory NGINX deployments and prioritise externally-reachable HTTP/3-enabled instances. Apply the F5 OOB patch within the standard emergency window; for instances that cannot be patched immediately, disable HTTP/3 via `listen ... quic` removal and confirm via `nginx -T`. Audit reverse-proxy upstreams for unexpected child processes.

### 3.7 RoguePlanet — unpatched Microsoft Defender SYSTEM-privilege zero-day (CVE-2026-50656)

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/microsoft/microsoft-working-on-defender-patch-for-rogueplanet-zero-day/)

Researcher "Nightmare Eclipse" published a working proof-of-concept for **RoguePlanet** — a race-condition vulnerability in the Microsoft Defender Malware Protection Engine that spawns a SYSTEM-privileged command prompt on fully-patched Windows 10 and 11. The exploit works regardless of real-time-protection state. Microsoft assigned **CVE-2026-50656** on 17 June and confirmed it is working on a patch but has not yet shipped one. This is the latest in an ongoing series of Defender zero-day disclosures from the same researcher (BlueHammer, RedSun, GreenPlasma, MiniPlasma, YellowKey, UnDefend); GreenPlasma, MiniPlasma and YellowKey were fixed in the June Patch Tuesday cycle. ATT&CK: T1059.001 (Command and Scripting Interpreter), T1068 (Privilege Escalation).

> **SOC Action:** Until a patch ships, hunt for child processes of `MsMpEng.exe` spawning `cmd.exe` or PowerShell with `SYSTEM` integrity — this is highly anomalous and a high-fidelity RoguePlanet indicator. Tighten EDR allowlists around Defender process trees and prepare to expedite the next Defender platform update once Microsoft releases it. Do not disable Defender as a workaround.

### 3.8 JCPenney breach via Oracle PeopleSoft zero-day (ShinyHunters extortion)

**Source:** [HaveIBeenPwned](https://haveibeenpwned.com/Breach/JCPenney)

ShinyHunters' "pay-or-leak" campaign against Oracle PeopleSoft customers continues. JCPenney was added to HIBP on 20 June after **368,418 employee and corporate records** were exposed — emails, names, dates of birth, Social Security numbers, phone numbers, home addresses, government-issued IDs and job titles, primarily from internal HR systems. Initial access was reportedly via the same critical Oracle PeopleSoft zero-day the group has been weaponising since early June. Madison Square Garden data — including references to Knicks players and coaches — was also leaked the same week ([Wired](https://www.wired.com/story/security-news-this-week-hackers-claim-to-leak-stolen-madison-square-garden-data/)).

> **SOC Action:** Any organisation running on-prem Oracle PeopleSoft should treat its HR module as a high-priority compromise target. Apply the Oracle out-of-cycle mitigation guidance immediately, audit PeopleSoft application logs for unauthenticated `PSADMIN` or `PSSAMPLE` activity, and force password rotation for employee accounts. If you appear in the JCPenney dataset, brief affected employees on enhanced phishing and SIM-swap risk for the next 90 days.

### 3.9 Secure Boot certificate expiration — 24 June 2026

**Source:** [Wired](https://www.wired.com/story/a-critical-deadline-is-approaching-for-windows-and-linux-security/)

Three Microsoft-signed Secure Boot certificates that anchor the UEFI chain of trust on Windows and Linux systems expire on **24 June 2026**. If not refreshed, affected systems will lose the cryptographic basis for verifying firmware integrity during boot, weakening protection against UEFI bootkits such as LoJax (Fancy Bear / APT28), MosaicRegressor, ESpecter, FinSpy and MoonBounce. The replacement certificates have been distributed via Windows Update and major Linux distribution channels, but enrolment requires reboots and firmware participation that some fleets have not yet completed.

> **SOC Action:** Inventory Secure Boot-enabled systems and verify the new Microsoft KEK / DB entries have been enrolled (PowerShell: `Get-SecureBootUEFI db`; Linux: `mokutil --list-enrolled`). Push the relevant Windows Update servicing-stack and firmware vendor updates ahead of 24 June. For air-gapped or update-paused fleets, schedule a maintenance window this week — once the certificates expire, recovery requires physical or out-of-band intervention.

### 3.10 AryStinger botnet — 4,000+ D-Link routers conscripted as distributed proxies

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/arystinger-botnet-infected-thousands-of-d-link-routers-worldwide/)

Qianxin XLab identified **AryStinger**, a previously undocumented botnet that has compromised more than 4,000 outdated D-Link DIR-850L and DIR-818LW routers via CVE-2013-3307, CVE-2016-5681 and CVE-2025-11837. Infected devices become distributed "executors" that scan, proxy, tunnel and execute commands on the attacker's behalf — and can be used to tamper with DNS settings to hijack browsing. A more advanced Go-based variant targets NAS systems with Shell / Go / Java / Python execution capability. Infection geography: South Korea 48.5%, China 31.8%, Sweden 6.4%, Malaysia 3.5%, Singapore 2.5%. No attribution made by XLab.

> **SOC Action:** If your network includes EoL D-Link DIR-850L or DIR-818LW devices, replace them. Block outbound connections from SOHO router IP space to known AryStinger C2 (XLab report contains current infrastructure list). For NAS estates, ensure management interfaces are not internet-exposed and patch to the latest vendor firmware.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Exploitation of vulnerabilities in critical infrastructure and technology sectors | F5 NGINX OOB patches; Entra Agent ID cross-tenant compromise |
| 🔴 **CRITICAL** | Sophisticated obfuscation in malware delivery, including AI-generated lures | ClickFix Campaign Generated Via AI Delivers SmartRAT; 140+ npm Packages Compromised |
| 🔴 **CRITICAL** | Supply-chain exploitation of widely-used software and platforms | Mastra easy-day-js dropper; GitHub-dismissed supply-chain-worm flaws |
| 🔴 **CRITICAL** | Rising double-extortion ransomware against government and healthcare | themintgaming.com By brain cipher; mupras.com By krybit |
| 🔴 **CRITICAL** | Exploitation of vulnerabilities in technology / SaaS products | CVE-2026-6253 proxy credentials redirect-to leak; M365 Copilot SearchLeak |
| 🟠 **HIGH** | Qilin RaaS expansion across multiple sectors | Taiwan Sintong Machinery, Sivatel Bangkok, Belz Institutions, Pacific Lamp & Supply (all "By qilin") |
| 🟠 **HIGH** | Lockbit5 mass-victim posting across education, healthcare, construction | 21+ correlated Lockbit5 victims with shared T1566 phishing TTP |
| 🟠 **HIGH** | Ransomware proliferation via cheap RaaS / builders ($20 BLACKNET-00) | Telegram (channel name redacted) sale posts; xX313XxTeam advertising |
| 🟠 **HIGH** | Rebranding cycle: Nova ← RALord, Worldleaks ← Hunters International | Dosab/Hosab/Nhà Thành Phố "By nova"; L'Archevque & Rivest, Super Finishing "By worldleaks" |
| 🟠 **HIGH** | Advanced obfuscation in cross-platform loaders | Operation FlutterBridge (FlutterShell macOS backdoor); OXLOADER infostealer dropper |
| 🟠 **HIGH** | Buffer-overflow / use-after-free CVE wave in technology + government | CVE-2026-7383 (ASN.1 heap overflow); CVE-2026-12464 (Browser use-after-free); CVE-2026-46331 (Linux net/sched) |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **The Gentlemen** (72 reports) — most-mentioned actor of the week; correlated to the `Tox1` malware family and victim postings spanning Australia (sugar producer), MENA holdings, Vietnam and Taiwan
- **Qilin** (67 reports) — RaaS operator with the broadest sector spread (manufacturing, finance, professional services, education) and active Jabber/Tox C2 infrastructure
- **Deadlock** (55 reports) — surged in mid-month; predominantly post-only victim shaming, no confirmed encryption observed
- **Lockbit5** (39 reports) — coordinated mass-victim drop on 18 June: 21+ organisations across education, construction and healthcare with shared T1566 phishing TTP
- **DragonForce** (36 reports) — continues to leverage Microsoft Teams relays, often paired with Babuk / ARCrypter variants
- **Nightspire** (27) — active infrastructure with multiple Telegram / Tox / Session channels and "Phantom" / "Reaper" affiliates
- **Akira** (27) — sustained victim-posting cadence; correlated to Akira ransomware payload
- **ShinyHunters / Shinyhunters** (23 + 20 combined) — Oracle PeopleSoft zero-day extortion campaign (JCPenney, MSG, prior Instructure / Kodak); responsible for the highest-publicity breach of the week
- **Nova** (14) — rebrand of RALord, RaaS model with captcha-protected leak portal
- **Inc Ransom** (13) — active across healthcare, legal services, media (Newspaper Media Group)
- **TeamPCP** (12) / **WorldLeaks** (11) / **Genesis** (11) — sustained mid-tier RaaS activity
- **Sapphire Sleet / BlueNoroff** — newly attributed to @mastra npm compromise; long-running DPRK financial / crypto-theft cluster

### Malware Families

- **Lockbit5** (14 reports) — encryptor in active deployment alongside the leak-site postings above
- **Akira ransomware** (13) — continued enterprise targeting
- **Nightspire** (11) — paired with affiliate "Phantom" / "Reaper" toolkits
- **Nova / RALord** (10 + 8) — rebranded RaaS encryptor
- **Deadlock** (10) — limited technical reporting, primarily victim-portal mentions
- **The Gentlemen** (9) / **Tox1** (53) — correlated cluster; Tox1 used as the obfuscated dropper
- **Inc Ransom** (8) — INC-README3.txt variant ransom notes
- **Qilin** (8) — README-RECOVER-[rand].txt notes
- **3AM ransomware** (8) — concentrated 12 June postings
- **AryStinger** — new D-Link router botnet (this week's only newly-named family)
- **Prinz Eugen** — new ransomware family identified by Threatdown; ChaCha20-Poly1305 encryption, prioritises recently-modified files first, deletes originals post-encryption
- **cross-platform RAT** — Sapphire Sleet implant via easy-day-js, targets 166 crypto-wallet extensions
- **FlutterShell** — macOS backdoor delivered via Operation FlutterBridge
- **OXLOADER** — new infostealer loader using advanced obfuscation to evade detection

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| RansomLook | 248 | [link](https://www.ransomlook.io/) | Aggregated leak-site postings (Qilin, The Gentlemen, Lockbit5, Nova, Worldleaks, Inc Ransom, etc.) |
| Microsoft | 81 | [link](https://msrc.microsoft.com/update-guide) | June Patch Tuesday CVEs, including 6+ critical Copilot/Azure/Dynamics flaws |
| BleepingComputer | 51 | [link](https://www.bleepingcomputer.com/news/security/) | Primary coverage of FortiBleed, CISA emergency directives, M365 SearchLeak, RoguePlanet, Cisco SD-WAN 0-day |
| AlienVault | 35 | [link](https://otx.alienvault.com/) | OTX pulse feed — IOC enrichment and campaign tracking |
| Unknown | 26 | — | Telegram (channel names redacted) — TLP:AMBER+STRICT OSINT including CVE-2026-40369 sandbox escape, NGINX RCE chatter, $20 ransomware builder ads |
| RecordedFuture | 14 | [link](https://www.recordedfuture.com/research) | Strategic threat-intel briefings |
| CISA | 14 | [link](https://www.cisa.gov/news-events/cybersecurity-advisories) | ICS advisories (Schneider Electric EasyLogic, AVer PTC cameras) plus BOD 26-04 directives |
| Wired Security | 8 | [link](https://www.wired.com/category/security/) | Secure Boot expiration coverage; MSG/ShinyHunters leak |
| SANS | 8 | [link](https://isc.sans.edu/) | Daily diary; technical write-ups |
| Schneier | 6 | [link](https://www.schneier.com/) | Policy / strategic commentary |
| HaveIBeenPwned | 4 | [link](https://haveibeenpwned.com/) | JCPenney breach addition (368k accounts) |
| Crowdstrike | 4 | [link](https://www.crowdstrike.com/blog/) | Adversary tradecraft updates |
| Wiz | 4 | [link](https://www.wiz.io/blog/red-agent-pov-ssrf) | Red Agent SSRF-to-LFR research on GCP Cloud Run |
| ESET Threat Research | 3 | [link](https://www.welivesecurity.com/) | EU-focused detection notes |
| Upwind | 3 | [link](https://www.upwind.io/feed) | Mastra supply-chain attack technical analysis |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Complete the **four CISA BOD 26-04** patch cycles this week — Splunk Enterprise (CVE-2026-20253), Joomla JCE (CVE-2026-48907), Cisco Catalyst SD-WAN Manager (CVE-2026-20262), Fortinet FortiSandbox (CVE-2026-39813/39808/25089). All four are confirmed in-the-wild, PoC-public and short-fuse.
- 🔴 **IMMEDIATE:** Treat all FortiGate SSL VPN credentials as compromised per FortiBleed: force password rotation, enforce MFA on every SSL VPN portal, re-issue client certificates, and hunt 4624/4625/SMB lateral movement from VPN-assigned ranges across the last 90 days.
- 🔴 **IMMEDIATE:** Quarantine and re-baseline any developer workstation or CI runner that pulled `@mastra/*` after 2026-06-17 01:15 UTC. Block `23.254.164.0/24` at egress, rotate npm tokens, GitHub PATs and any cloud credentials exposed on those hosts, and add `easy-day-js` to internal package blocklists.
- 🟠 **SHORT-TERM:** Push out the Secure Boot certificate refresh (Windows Update servicing-stack + firmware vendor updates) before **24 June 2026**. After expiration, recovery requires physical or out-of-band intervention.
- 🟠 **SHORT-TERM:** Apply the F5 NGINX OOB patches; for unpatched HTTP/3 instances, disable QUIC listeners as a temporary workaround and verify with `nginx -T`.
- 🟠 **SHORT-TERM:** Hunt for the RoguePlanet pre-cursor — `MsMpEng.exe` parenting `cmd.exe` / `powershell.exe` with SYSTEM integrity — until CVE-2026-50656 ships. Do not disable Defender.
- 🟡 **AWARENESS:** Audit Copilot Enterprise Search activations and enable Purview audit logging for Copilot interactions to detect future SearchLeak-style prompt-injection-to-exfil chains; brief end users that Copilot links should be treated like phishing URLs.
- 🟡 **AWARENESS:** Refresh ransomware threat models to include the new Nova ← RALord and Worldleaks ← Hunters International rebrands, the cheap-builder ecosystem (BLACKNET-00 / blacknetransom $20 sales), and the Qilin / The Gentlemen / Lockbit5 sector spread.
- 🟢 **STRATEGIC:** For organisations running on-prem Oracle PeopleSoft, accelerate cloud migration planning and apply Oracle's PeopleSoft zero-day mitigations immediately — ShinyHunters has telegraphed a multi-month "pay-or-leak" campaign and additional victims are highly likely.
- 🟢 **STRATEGIC:** Build an AI/agentic-system threat-model deliverable for the next architecture review: SearchLeak and the four Copilot CVEs demonstrate that classical web bugs (SSRF, race conditions, open redirect, missing auth) are being chained with prompt injection into novel data-theft paths that bypass conventional CSP and DLP controls.

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 524 reports processed across 14 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
