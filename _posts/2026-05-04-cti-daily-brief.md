---
layout: post
title:  "CTI Daily Brief: 2026-05-04 - Weaver E-cology CVE-2026-22679 actively exploited; ShinyHunters dumps Vimeo data; Safepay ransomware surge"
date:   2026-05-05 20:04:27 +0000
description: "25 reports processed. Three critical vulnerabilities (Weaver E-cology CVE-2026-22679 in-the-wild RCE, GNU Binutils CVE-2025-11083, libssh2 CVE-2026-7598). Safepay drives a five-victim ransomware cluster across IT services and construction; ShinyHunters publishes 119k Vimeo emails via Anodot third-party breach."
category: daily
tags: [cti, daily-brief, safepay, shinyhunters, qilin, cve-2026-22679, weaver-e-cology]
classification: TLP:CLEAR
reporting_period: "2026-05-04"
generated: "2026-05-05"
draft: true
severity: critical
report_count: 25
sources:
  - Microsoft
  - BleepingComputer
  - HaveIBeenPwned
  - SANS
  - Elastic Security Labs
  - RansomLook
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-05-04 (24h) | TLP:CLEAR | 2026-05-05 |

## 1. Executive Summary

Twenty-five reports were processed across six named sources in the last 24 hours, with three critical vulnerability disclosures and an 18-report high-severity tail dominated by ransomware leak-site postings. The headline operational item is BleepingComputer's confirmation that **CVE-2026-22679** in Weaver E-cology office automation has been exploited in the wild since mid-March, five days after the vendor patch and two weeks before public disclosure — Vega researchers observed unauthenticated RCE attempts with PowerShell payloads and an MSI installer dropped via an exposed debug API. Microsoft published two further critical CVEs affecting widely-redistributed open-source libraries: a GNU Binutils heap overflow (CVE-2025-11083) and a libssh2 integer overflow (CVE-2026-7598). On the actor side, the **Safepay** ransomware operation accounts for five of today's victim postings across Japan, Portugal, Italy, Germany, and Canada with strong correlation around IT services and phishing-driven access, while **ShinyHunters** added Vimeo to its extortion portal and published 119,167 email addresses sourced from a breach of analytics vendor Anodot. No CISA KEV additions were observed in this period.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 3 | Weaver E-cology CVE-2026-22679 in-the-wild RCE; GNU Binutils CVE-2025-11083 heap overflow; libssh2 CVE-2026-7598 integer overflow |
| 🟠 **HIGH** | 18 | Safepay ransomware cluster (5); Qilin RaaS (2); Inc Ransom (2); Chaos RaaS (2); Vimeo/ShinyHunters breach (119k accounts); Telegram WHM exploit drop |
| 🟡 **MEDIUM** | 2 | Microsoft CVE-2026-37457 disclosure; Securotrop ransom listings |
| 🔵 **INFO** | 2 | SANS ISC Stormcast 5 May; Elastic Workflows 9.4 GA |

## 3. Priority Intelligence Items

### 3.1 Weaver E-cology CVE-2026-22679 exploited since mid-March

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/weaver-e-cology-critical-bug-exploited-in-attacks-since-march/)

Vega Threat Intelligence has documented a roughly week-long campaign exploiting an unauthenticated RCE flaw (CVE-2026-22679) in Weaver E-cology 10.0 builds prior to build 20260312. The vulnerability is an exposed debug API endpoint that passes user-supplied parameters to backend RPC functionality without authentication or input validation, allowing attackers to execute arbitrary system commands via the `java.exe` (Tomcat-bundled JVM) process. Observed activity included Goby-linked ping callbacks for RCE confirmation, multiple obfuscated PowerShell payload-download attempts (blocked by EDR), an MSI installer named `fanwei0324.msi` that failed to execute, and reconnaissance via `whoami`, `ipconfig`, and `tasklist`. Attackers did not establish persistence in the cases observed, but exploitation began only five days after the vendor's silent patch and two weeks before public disclosure — indicating either patch-diffing or insider knowledge. Weaver E-cology is overwhelmingly used by Chinese organisations for workflow, document, HR, and collaboration processes. The vendor fix removes the debug endpoint entirely; no workarounds are available.

> **SOC Action:** Inventory Weaver E-cology 10.0 deployments and verify build is ≥ 20260312. Hunt for child processes of `java.exe` originating from Weaver's Tomcat (especially `powershell.exe`, `msiexec.exe`, `cmd.exe` running `whoami`/`ipconfig`/`tasklist`). Block egress from E-cology hosts to non-corporate destinations and alert on any MSI download to a Tomcat-parented process. MITRE: T1190, T1059.001, T1071.001, T1204.

### 3.2 Microsoft critical CVEs in GNU Binutils and libssh2

**Source:** [MSRC — CVE-2025-11083](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-11083), [MSRC — CVE-2026-7598](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-7598)

Microsoft published two critical advisories affecting open-source components that ship inside Microsoft products and are widely redistributed across Linux distributions and developer toolchains. **CVE-2025-11083** is a heap-based overflow in the `elf_swap_shdr` function in `elfcode.h` of the GNU Binutils Linker, allowing an attacker who can supply a crafted ELF object to trigger arbitrary code execution during linking — relevant to CI/CD pipelines, container build hosts, and any system that links untrusted ELF inputs. **CVE-2026-7598** is an integer overflow in `libssh2`'s `userauth.c` `userauth_password` path, where improper bounds-checking when parsing the authentication response length permits remote pre-auth code execution via a crafted password packet. Both advisories are tagged 100% confidence and TLP:CLEAR, but no public exploitation has been reported and neither has been added to CISA KEV at the time of writing. The blast radius for libssh2 in particular is large, as it is statically or dynamically linked into curl, libgit2, and many SSH-using applications.

> **SOC Action:** Track Microsoft component-update releases for both CVEs and apply as soon as they ship in the May Patch Tuesday cycle. Inventory third-party software depending on `libssh2.dll`/`.so` (use `lsof`/`tasklist /m` or SBOM tooling) and prioritise SSH-facing services. For Binutils, restrict who can run `ld` against untrusted input on build hosts and treat ELF inputs from external pipelines as untrusted. MITRE: T1190, T1059.

### 3.3 ShinyHunters publishes Vimeo data via Anodot third-party breach

**Source:** [HaveIBeenPwned — Vimeo](https://haveibeenpwned.com/Breach/Vimeo)

ShinyHunters listed Vimeo on its extortion portal in April 2026 and has now published several hundred gigabytes of data, including 119,167 unique email addresses (some accompanied by names) plus video titles, technical data, and metadata. Vimeo attributes the exposure to a compromise of **Anodot**, a third-party analytics vendor, and states that no Vimeo video content, login credentials, or payment card data are included. The breach was added to HIBP on 5 May 2026. ShinyHunters' continued operational tempo is consistent with prior trend data placing the group on 23 reports across the pipeline since April, including the recently observed Marcus & Millichap (1.84M accounts) and Instructure breaches that share the same TTP signature: exploitation of public-facing applications at SaaS analytics or learning vendors used by the eventual victim brand.

> **SOC Action:** If your organisation uses Vimeo for marketing or training video hosting, audit which staff used corporate emails for Vimeo accounts and force a password reset on any account where the same password is reused elsewhere. Add Anodot's domains and the 119k email list (when made available via HIBP API) to credential-stuffing watchlists. Review third-party analytics vendor inventories for any SaaS that handles user PII and confirm SSO + tenant-scoping is in place. MITRE: T1190, T1078, T1567.

### 3.4 Safepay ransomware: five-victim cluster across IT services and construction

**Source:** [RansomLook — Safepay](https://www.ransomlook.io//group/safepay)

Five Safepay leak-site postings appeared in the last 24 hours: hokuyo2006.co.jp (Japan), bootstransport.ca (Canada — logistics/transport), dahlgrenscement.se (Sweden — construction materials), maiadouro.pt (Portugal), fital-treppenlifte.de (Germany), and zonaovest.to.it (Italy). The CognitiveCTI correlation engine grouped these at 0.95 confidence on actor and 0.70 on T1566 phishing as the shared initial-access TTP, with sector clustering around IT services. Safepay's leak infrastructure shows mixed availability — most clearnet domains are down with one onion service operational — suggesting either targeted disruption or rolling C2 maintenance. Two ransom-note variants (`readme_safepay_ascii.txt`, `readme_safepay.txt`) are referenced. The geographic spread (six countries in 24 hours) indicates affiliate-driven targeting rather than a single regional campaign.

#### Indicators of Compromise

```
Ransom note filenames: readme_safepay_ascii.txt, readme_safepay.txt
Leak site (defanged): hxxps[:]//ransomlook[.]io/group/safepay
Initial-access TTP: T1566 - Phishing
```

> **SOC Action:** For European mid-market construction, transport, and IT-services tenants, hunt for the Safepay ransom-note filenames in EDR file-creation telemetry and on backup-server file shares. Quarantine any host writing `readme_safepay*.txt` files. Tighten phishing controls on inbound mail to operations and finance roles, and confirm offline immutable backups exist. MITRE: T1566, T1486, T1490.

### 3.5 Qilin, Inc Ransom, Chaos, Everest, Krybit, Space Bears, PEAR — secondary leak-site postings

**Source:** [RansomLook](https://www.ransomlook.io/) (multiple group pages)

The remaining high-severity volume is RansomLook leak-site activity from secondary actors. **Qilin** posted Cushman & Wakefield (commercial real estate) and Seagate Capital Construction; the actor has 90 reports across the pipeline since 9 April and remains the highest-volume RaaS in the dataset. **Inc Ransom** posted sanver.com.mx and childplace.org. **Chaos RaaS** posted vacaero.com and cswindustrials.com — the same Chaos cluster previously associated with the 69 GB Optima Tax Relief exfiltration; the correlation engine flags T1566/T1078/T1485 as the shared TTP set. **Space Bears** posted Erla Technologies SAS, **Everest** posted Studio Marchi, **Krybit** posted foodsmart.com.do, and **PEAR** posted Morning Star Tours. None of these postings include independent technical analysis — they are extortion announcements from the leak sites and should be treated as victim notification rather than confirmed campaign telemetry.

> **SOC Action:** Cross-reference today's victim names against your third-party / vendor inventory; if any match, contact the vendor's security team and pre-emptively rotate any shared credentials, API keys, or VPN tunnels. Treat Qilin and Chaos as the highest-priority ransomware threats given pipeline-wide volume. MITRE: T1566, T1078, T1485, T1490.

### 3.6 Telegram-distributed mass WHM exploit drop

**Source:** Telegram (channel name redacted)

A Telegram post advertised mass distribution of WHM (cPanel Web Host Manager) exploits via a private "VIP" subscription channel. Specific CVEs were not enumerated in the post and no payload was published. Categorising as high-severity due to the wide deployment of WHM/cPanel across hosting providers and small-business shared-hosting environments, but the operational confidence is low — these advertisements frequently bundle public-domain exploits to monetise inexperienced attackers. The post tag `TLP:AMBER+STRICT` reflects the Telegram-OSINT origin and should be honoured: do not redistribute the channel URL.

> **SOC Action:** If your organisation operates internet-facing WHM/cPanel control panels, ensure the panel is fully patched, force-MFA on all reseller and root accounts, and restrict cPanel/WHM admin interfaces to allow-listed source IPs. Hunt for WHM authentication anomalies and unexplained API token creation. MITRE: T1190, T1078, T1133.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Supply-chain attacks leveraging npm and PyPI packages to distribute malware (carry-over from 4 May batch) | Mini Shai-Hulud npm worm; Intercom npm package compromise |
| 🟠 **HIGH** | Increased use of phishing in ransomware campaigns | Telegram WHM exploit drop; Erla Technologies (Space Bears); foodsmart.com.do (Krybit) |
| 🟠 **HIGH** | Targeting of IT services and construction sectors by ransomware actors | hokuyo2006.co.jp (Safepay); maiadouro.pt (Safepay); Studio Marchi (Everest) |
| 🟠 **HIGH** | Continued ransomware activity targeting diverse sectors with sophisticated TTPs | Cushman & Wakefield (Qilin); Seagate Capital Construction (Qilin); Luna Group (Lamashtu) |
| 🟠 **HIGH** | Phishing campaigns increasingly sophisticated, targeting multiple sectors | vacaero.com (Chaos); CISA "Copy Fail" Linux exploitation |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **Qilin** (90 reports) — Highest-volume RaaS in the pipeline; today added Cushman & Wakefield and Seagate Capital Construction
- **The Gentlemen** (63 reports) — No new postings today; remains active across legal and aerospace
- **Coinbase Cartel** (31 reports) — No new postings today
- **DragonForce** (28 reports) — Last seen 4 May
- **ShinyHunters** (23 reports) — Today's Vimeo extortion drop confirms continuing operational tempo
- **Inc Ransom** (18 reports) — Today posted sanver.com.mx and childplace.org
- **Lamashtu** (18 reports) — Last seen 4 May with Luna Group, ROYAL M HOTEL postings
- **Safepay** (5 mentions today) — Five-victim cluster across IT services / construction in six countries

### Malware Families

- **RansomLook / RansomLock** (62 / 44 reports) — Source-tracker entity, not a malware family per se; reflects high RaaS leak-site coverage volume in the dataset
- **RaaS generic** (24 reports) — Cross-actor tagging
- **Tox / Tox1** (21 / 13 reports) — Communications protocol used by Qilin, Chaos for victim contact
- **Qilin ransomware** (13 reports) — Payload variant tracking matches actor volume
- **Chaos Ransomware** (2 today) — Multi-platform (Windows, ESXi, Linux, NAS) configurable encryption
- **Gentlemen ransomware** (9 reports) — No new payload activity today

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| RansomLook | 17 | [link](https://www.ransomlook.io/) | Aggregated leak-site postings — Safepay (5), Qilin (2), Inc Ransom (2), Chaos (2), and singletons from Everest, Space Bears, Krybit, PEAR, Securotrop |
| Microsoft | 3 | [link](https://msrc.microsoft.com/update-guide/) | CVE-2025-11083 (GNU Binutils), CVE-2026-7598 (libssh2), CVE-2026-37457 (medium) |
| HaveIBeenPwned | 1 | [link](https://haveibeenpwned.com/Breach/Vimeo) | Vimeo / ShinyHunters / Anodot — 119,167 accounts |
| BleepingComputer | 1 | [link](https://www.bleepingcomputer.com/news/security/weaver-e-cology-critical-bug-exploited-in-attacks-since-march/) | Vega's analysis of in-the-wild CVE-2026-22679 exploitation |
| Elastic Security Labs | 1 | [link](https://www.elastic.co/security-labs/elastic-workflows-ga-9-4) | Elastic Workflows 9.4 GA — vendor product info, not threat data |
| SANS | 1 | [link](https://isc.sans.edu/diary/rss/32952) | ISC Stormcast 5 May — green threat level |
| Telegram (redacted) | 1 | — | Mass WHM exploit drop advertisement; channel URL withheld per editorial policy |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Inventory Weaver E-cology 10.0 estate and confirm build ≥ 20260312. Until patched, isolate any internet-facing E-cology instance and hunt for `java.exe` → `powershell.exe`/`msiexec.exe` parent-child chains plus `whoami`/`ipconfig`/`tasklist` execution from Tomcat-parented processes. CVE-2026-22679 is confirmed in-the-wild.

- 🟠 **SHORT-TERM:** Track Microsoft's May patch cycle for CVE-2025-11083 (GNU Binutils) and CVE-2026-7598 (libssh2) and apply on disclosure. Run an SBOM query for `libssh2` linkages — the integer overflow is a pre-auth RCE on a library that ships inside curl, libgit2, and many SSH-using clients.

- 🟠 **SHORT-TERM:** Audit corporate Vimeo accounts and force password resets on any with credential reuse; review SaaS analytics vendors (Anodot-class) for tenant-scoping and SSO. Add the new HIBP Vimeo dataset to credential-stuffing detection feeds.

- 🟡 **AWARENESS:** Cross-reference today's RansomLook victim list (Cushman & Wakefield, Seagate Capital, Erla Technologies SAS, Studio Marchi, Morning Star Tours, foodsmart.com.do, sanver.com.mx, childplace.org, vacaero.com, cswindustrials.com, Thompson Builders, plus six Safepay victims) against your vendor and customer inventory; alert security contacts and rotate shared credentials where matches exist.

- 🟢 **STRATEGIC:** Raise the priority of phishing-resistant MFA rollout for IT-services and construction-sector tenants — Safepay, Qilin, Chaos, Everest and Space Bears all use phishing (T1566) as primary initial access, and the correlation engine flagged this TTP across 13 of today's 25 reports.

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 25 reports processed across 2 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
