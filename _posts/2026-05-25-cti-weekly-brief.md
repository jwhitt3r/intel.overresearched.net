---
layout: post
title:  "CTI Weekly Brief: 25–31 May 2026 — TeamPCP supply-chain campaign breaches GitHub, WordPress and Gogs zero-days under exploitation, Mbed TLS / GnuTLS critical batch"
date:   2026-06-01 08:12:45 +0000
description: "Weekly summary of 695 ingested reports (36 critical, 287 high). TeamPCP supply-chain operation reached GitHub's internal codebase and trojanised Microsoft's durabletask SDK; CVE-2026-8732 in WP Maps Pro is being actively exploited; an unpatched Gogs argument-injection zero-day enables RCE; a large Mbed TLS / GnuTLS / OpenSSL critical batch lands across MSRC; ransomware churn (Qilin, Akira, Gunra, Genesis) and a SmartApeSG ClickFix NetSupport RAT campaign continue."
category: weekly
tags: [cti, weekly-brief, teampcp, gunra, qilin, akira, mbed-tls, cve-2026-8732]
classification: TLP:CLEAR
reporting_period_start: "2026-05-25"
reporting_period_end: "2026-05-31"
generated: "2026-06-01"
draft: false
report_count: 695
severity: critical
sources:
  - Microsoft
  - RansomLock
  - CISA
  - BleepingComputer
  - SANS
  - AlienVault
  - Wired Security
  - Schneier
  - Wiz
  - Cisco Talos
  - ESET Threat Research
  - Crowdstrike
  - RecordedFutures
  - HaveIBeenPwned
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 25 May 2026 to 31 May 2026 (7d) | TLP:CLEAR | 1 June 2026 |

## 1. Executive Summary

The pipeline ingested 695 reports across the reporting window, of which 36 were rated critical and 287 high. The week's dominant story is the **TeamPCP supply-chain campaign**, which stacked three escalations in seven days: a trojanised Nx Console VS Code extension that pivoted into GitHub's internal CI/CD and exfiltrated approximately 3,800 internal repositories, a trojanised Microsoft-published `durabletask` PyPI SDK carrying a Linux disk-wiper second stage, and a third Mini Shai-Hulud wave through the `@antv` npm ecosystem hitting packages with 4M+ weekly downloads. Independent reporting ties the publish chain back to OIDC credentials harvested in the earlier TanStack wave, making this the first publicly confirmed multi-stage operation in the campaign.

In parallel, two unauthenticated web-stack issues moved into active exploitation: **CVE-2026-8732** in the WP Maps Pro WordPress plugin (Wordfence blocked 3,600+ exploitation attempts in 24 hours), and an **unpatched Gogs argument-injection zero-day** that enables RCE on default-configured instances (Shadowserver tracks 2,400+ exposed servers). Microsoft's MSRC published a large critical batch covering Mbed TLS (multiple CVEs including a NULL-pointer write, FFDH buffer overflow, predictable PRNG seed), GnuTLS certificate validation bypasses (CVE-2026-42012, CVE-2026-42013), Libsolv heap overflows, OpenSC, libyang use-after-free, and Go SSH auth bypasses. CISA released ICS advisories with four critical-rated devices in scope including healthcare-deployed Eppendorf BioFlo 320 bioreactors (CVE-2026-7251, hard-coded VNC password, CVSS 9.8) and XCharge C6 EV chargers (CVE-2026-9037/38/39). Ransomware tempo remained elevated with Qilin (82 reports across pipeline window), Akira (74), The Gentlemen (63), DragonForce, ShinyHunters, Gunra, and a fresh Genesis campaign run.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 36 | TeamPCP supply-chain operation; WP Maps Pro active exploitation; Gogs zero-day; Mbed TLS / GnuTLS / Libsolv / OpenSC / libyang MSRC batch; CISA ICS critical advisories (KMW CCTV, Eppendorf BioFlo 320, PUSR USR-W610, XCharge C6, ABB B&R Automation Runtime) |
| 🟠 **HIGH** | 287 | Mbed TLS algorithm-downgrade and FFDH key flaws; Node.js V8 hash-collision DoS (CVE-2026-21717) and Node 20 HTTP request smuggling (CVE-2025-23167); RabbitMQ XSS; gitoxide command injection; ransomware leak-site activity (Gunra STAREMPIRE, cmd organization, Genesis sweep, Grupo Mauá / bravox) |
| 🟡 **MEDIUM** | 245 | MSRC vulnerability churn; CISA ICS advisories; vendor patch advisories; AlienVault pulse intelligence |
| 🟢 **LOW** | 70 | SmartApeSG/NetSupport RAT ClickFix tradecraft; minor compatibility issues; tier-2 ransomware leak posts |
| 🔵 **INFO** | 57 | Stormcast podcasts; defensive guidance; product release notes |

## 3. Priority Intelligence Items

### 3.1 TeamPCP supply-chain campaign reaches GitHub-internal codebase and Microsoft's PyPI SDK

**Source:** [SANS ISC](https://isc.sans.edu/diary/rss/33014)

Three escalations stacked inside a single week. The TanStack OIDC credentials harvested in the earlier wave (tracked as CVE-2026-45321 in BleepingComputer reporting) were re-used to publish a trojanised build of the Nx Console VS Code extension (v18.95.0, publisher `nrwl.angular-console`, verified-publisher badge, ~2.2M installs). The malicious build was live on the Visual Studio Marketplace for roughly 18 minutes; on a GitHub employee endpoint it auto-updated inside that window, exfiltrated developer secrets, and was used to move laterally through GitHub's internal CI/CD. GitHub CISO Alexis Wales publicly named the extension as the root of an intrusion that pulled ~3,800 internal repositories — OpenAI, Grafana Labs and Mistral AI were named as downstream victims. In parallel, the same operator pushed a trojanised build of Microsoft's official `durabletask` Azure Durable Functions SDK on PyPI (versions 1.4.1 through 1.4.3, ~417k monthly downloads) inside a ~35-minute window, with independent reporting characterising the second-stage as a Linux disk-wiper. A third `Mini Shai-Hulud` wave through the `@antv` npm ecosystem pushed 639 malicious package versions across 323 packages, including `echarts-for-react` (~1.1M weekly downloads) and `size-sensor` (~4.2M weekly downloads). MITRE ATT&CK: T1078 (Valid Accounts), T1195.002 (Supply Chain Compromise – Software Supply Chain).

> **SOC Action:** Rotate any developer/CI-CD OIDC credentials exposed during the publish windows above. Inventory `Nx Console` installations on developer endpoints and verify build is not v18.95.0; pin `durabletask` to a known-good version pre-1.4.1 or post-1.4.3 across PyPI lockfiles. Query EDR for `code.exe`/`code-insiders.exe` child processes invoking `curl`, `wget`, `bash`, or PowerShell `Invoke-WebRequest` within 60 minutes of an Nx/VS Code extension auto-update. Stop treating publisher-verified or attestation badges as install-time safety signals — gate marketplace installs through an internal mirror with delay-and-review.

### 3.2 WP Maps Pro plugin actively exploited — unauthenticated admin account creation (CVE-2026-8732)

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/wp-maps-pro-bug-exploited-to-create-admin-accounts-on-wordpress-sites/)

WP Maps Pro versions ≤ 6.1.0 (over 15,800 sales on Envato Market) contain an AJAX endpoint that accepts unauthenticated requests guarded only by a publicly exposed nonce in frontend JavaScript. A specially crafted request with `check_temp=false` invokes `wp_insert_user()` with the hardcoded `administrator` role and a generated magic-login URL, returning passwordless admin access to the attacker. Wordfence/Defiant observed in-the-wild exploitation and blocked 3,600+ attempts in 24 hours. WP Maps Pro 6.1.1 fixes the issue. MITRE ATT&CK: T1078.003 (Valid Accounts), T1098 (Account Manipulation).

> **SOC Action:** Patch all WP Maps Pro installs to 6.1.1 immediately. For each WordPress estate, dump `wp_users` and `wp_usermeta` and search for newly created users with role `administrator` and an email of `support@flippercode.com` or a randomly generated username; revoke and audit. Add a WAF/edge rule blocking POST requests to the `wp-admin/admin-ajax.php` action used by WP Maps Pro with `check_temp=false`.

### 3.3 Unpatched Gogs zero-day RCE via rebase argument injection

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/new-gogs-zero-day-flaw-lets-hackers-get-remote-code-execution/)

Rapid7's Jonah Burgess disclosed an unpatched argument-injection flaw in Gogs 0.14.2 and 0.15.0+dev. Because the default configuration ships with `DISABLE_REGISTRATION=false` and `MAX_CREATION_LIMIT=-1`, any user can self-register, create a repository, enable "rebase before merging," and inject the `--exec` flag into `git rebase` via a malicious branch name, achieving RCE as the Gogs service account. The maintainers acknowledged the report in March but have not provided a patch; Shadowserver tracks 2,400+ exposed servers (1,894 in Asia, 319 in Europe). This is similar to but distinct from CVE-2025-8110, which was added to CISA KEV in January after in-the-wild exploitation. MITRE ATT&CK: T1190 (Exploit Public-Facing Application), T1059 (Command and Scripting Interpreter).

> **SOC Action:** Take any Internet-exposed Gogs instance off the public Internet or set `DISABLE_REGISTRATION=true` and disable rebase-merging in repository settings as a stop-gap. Hunt for unexpected child processes of the Gogs binary, especially `git` invocations with `--exec=` in the argv string. Audit Gogs server users created in the last 30 days for non-employee accounts.

### 3.4 Mbed TLS / GnuTLS / Libsolv / Go cryptography critical batch (Microsoft MSRC)

**Source:** [Microsoft Security Response Center](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-34874)

A large batch of critical-rated vulnerabilities landed on MSRC across cryptographic and parsing libraries that are pervasive in Linux distributions, container images, and embedded firmware. Highlights: **CVE-2026-34874** (Mbed TLS NULL-pointer dereference in distinguished-name parsing — write to address 0), **CVE-2026-42012** and **CVE-2026-42013** (GnuTLS certificate validation bypass via URI/SRV SANs and oversized SANs), **CVE-2026-48864** and **CVE-2026-9150** (Libsolv heap and stack-based buffer overflows in `.solv` decompression and Debian metadata parsing), **CVE-2026-40528** (OpenSC < 0.27.0 buffer overrun in `do_key_value()`), **CVE-2026-41401** (libyang heap use-after-free in XML metadata parsing), and a cluster of Go SSH issues — **CVE-2026-39828** (certificate restriction bypass), **CVE-2026-42508** (auth bypass via unenforced `@revoked` status in `knownhosts`), and **CVE-2026-46597** (byte-arithmetic underflow / panic). The 2026-05-31 correlation batch grouped these under the trend "Increased targeting of critical infrastructure sectors with vulnerabilities in widely used cryptographic libraries." MITRE ATT&CK: T1190, T1071.001, T1193.

> **SOC Action:** Run `dpkg -l | grep -E 'libmbedtls|libgnutls|libsolv|opensc|libyang'` and equivalent `rpm -qa` queries across the Linux estate; prioritise hosts that terminate TLS or process untrusted certificate chains. Update Go dependencies pulling `golang.org/x/crypto` and `golang.org/x/net/html` to versions issued after 28 May 2026. Subscribe affected base-image SBOMs to a scheduled re-scan.

### 3.5 Active ICS critical advisories — healthcare, IoT, EV charging, factory automation

**Source:** [CISA ICSA-26-148-06 (KMW)](https://www.cisa.gov/news-events/ics-advisories/icsa-26-148-06), [CISA ICSMA-26-146-01 (Eppendorf)](https://www.cisa.gov/news-events/ics-medical-advisories/icsma-26-146-01), [CISA ICSA-26-148-02 (PUSR)](https://www.cisa.gov/news-events/ics-advisories/icsa-26-148-02), [CISA ICSA-26-148-08 (XCharge)](https://www.cisa.gov/news-events/ics-advisories/icsa-26-148-08), [CISA ICSA-26-146-04 (ABB B&R)](https://www.cisa.gov/news-events/ics-advisories/icsa-26-146-04)

Five CISA advisories crossed the critical threshold this week. **KMW KM-IP521 / KM-IP421 CCTV cameras** (CVE-2026-5386, CVSS 9.1) accept an unauthenticated administrator password reset over the network; firmware update available. **Eppendorf BioFlo 320 bioreactors** (CVE-2026-7251, CVSS 9.8) ship with a hard-coded VNC server password that allows full remote takeover of the bioreactor's user interface — affects healthcare and life-sciences environments worldwide. **Jinan USR IOT PUSR USR-W610** RS232/485-to-Wi-Fi converters (CVE-2026-7786, CVSS 9.8) contain plaintext administrative credentials embedded in firmware; the vendor did not respond to CISA coordination. **XCharge C6 EV chargers** (CVE-2026-9037/9038/9039, CVSS up to 9.8) lack firmware signature validation, contain a stack-based buffer overflow in signal processing, and accept default admin credentials over the vehicle-charger signalling channel; vendor reports update deployed to all affected chargers. **ABB B&R Automation Runtime** (System Diagnostics Manager DoS, Automation Runtime < 6.3 / < Q4.93) allows unauthenticated network attackers to delete diagnostic data. MITRE ATT&CK: T1078, T1071, T1190.

> **SOC Action:** Run an asset query across OT and clinical engineering inventories for the affected vendors and firmware strings. For all five, enforce network segmentation behind firewalls with explicit allow-lists; never expose VNC, web-management, or signalling channels to the Internet. Prioritise the Eppendorf and PUSR fixes — both have CVSS 9.8 and trivial exploitation paths.

### 3.6 Node.js trio: V8 hash-collision DoS, HTTP request smuggling, Permission Model bypass

**Source:** [MSRC CVE-2026-21717](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-21717), [MSRC CVE-2025-23167](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-23167)

Three high-severity Node.js issues landed in the same MSRC batch. **CVE-2026-21717** is a V8 string-hashing flaw — integer-like strings hash to their numeric value, making collisions trivially predictable; any endpoint that calls `JSON.parse()` on attacker-controlled input is an amplifier, and affected versions span 20.x, 22.x, 24.x and 25.x. **CVE-2025-23167** is a Node 20 HTTP/1 parser flaw allowing improper header termination (`\r\n\rX` instead of `\r\n\r\n`), enabling request smuggling past proxy-based access controls; resolved by the `llhttp` v9 upgrade. **CVE-2026-21711** lets code running under `--permission` without `--allow-net` create Unix Domain Socket server endpoints, bypassing the Permission Model's network boundary (Node 25.x). MITRE ATT&CK: T1499.003 (Application Exhaustion Flood), T1190.

> **SOC Action:** Upgrade Node.js across the fleet — Node 20 to the latest llhttp v9 build, Node 22/24/25 to versions including the V8 fix. For applications you cannot upgrade immediately, add rate-limiting and request-body-size caps in front of JSON-parsing endpoints. Audit any container image base for `node:20`/`node:22`/`node:24`/`node:25` and bump to a patched tag.

### 3.7 SmartApeSG ClickFix campaign deploying NetSupport RAT via unidentified loader

**Source:** [SANS ISC](https://isc.sans.edu/diary/rss/33034)

SANS handler Brad Duncan published an infection chain captured 27 May 2026 in which a SmartApeSG ClickFix lure delivered an as-yet-unnamed RAT that has been C2-beaconing to `89.110.110[.]119:443` (encoded, not TLS) consistently since April. The initial RAT pulled down a follow-on NetSupport Manager RAT package via `processor.vbs` → `token.bat` → `setup.cab`, achieving persistence under `C:\ProgramData\UpdateInstaller\`. SmartApeSG indicators rotate daily. MITRE ATT&CK: T1204.002 (User Execution: Malicious File), T1071.001, T1546.

#### Indicators of Compromise

```
SmartApeSG lure URLs (2026-05-27):
  hxxps[:]//hiddenplanetlab[.]top/signin/secure-util.js
  hxxps[:]//hiddenplanetlab[.]top/signin/private-template?c66kjD5i
  hxxps[:]//hiddenplanetlab[.]top/signin/legacy-worker.js?18b3825af007e53d

ClickFix script traffic:
  hxxp[:]//178.156.165[.]82/
  hxxp[:]//178.156.173[.]194/
  hxxps[:]//silverharvestnetwork[.]com/check

Initial RAT C2:
  tcp://89.110.110[.]119:443

NetSupport RAT C2:
  hxxp[:]//185.163.47[.]217:443

Files:
  Initial RAT zip — SHA256 1514b1268e9dc6d2f37137aa38c756cb4bf8186ac9235d6863b78e7f8bbbe976
  processor.vbs — SHA256 469bac8e10f50263e8ff0806e6ba126bb4cc660799129a8653eab3f8ec7201e5
  token.bat — SHA256 9c7eda2c4d3aaa8746495741bef57a07de180f0409409faf0f91658e88ba33f5
  setup.cab — SHA256 7ba5481c873bb3081442561f749f590badd72ef249fddfe993e30b28dc0c2112
```

> **SOC Action:** Block the listed C2 IPs and domains at egress. Query EDR for `wscript.exe` or `cscript.exe` spawning `cmd.exe` running `.bat` files out of `C:\ProgramData\`, and for `expand.exe` extracting CAB files into `C:\ProgramData\UpdateInstaller\`. Hunt user-mode network connections to 89.110.110[.]119 and 185.163.47[.]217 over the last 30 days. Reinforce ClickFix user-awareness messaging — fake "verify you are human" prompts are the dominant initial-access vector this quarter.

### 3.8 Ransomware tempo — Gunra (STAREMPIRE), cmd organization, Genesis sweep, Grupo Mauá

**Source:** [RansomLook](https://www.ransomlook.io/) (multiple posts)

Leak-site activity remained heavy. Gunra (first identified April 2025) listed STAREMPIRE on its Tor leak site and continued double-extortion operations across manufacturing, healthcare and IT verticals. The cmd organization listed Lake Washington School District alongside other entities. The Genesis affiliate ran a multi-victim sweep including Cavalier Flooring Systems Inc., Green Resource, Wentworth and A Roettgers — the 2026-05-31 correlation batch grouped these under "Genesis ransomware group targeting multiple sectors with phishing and data encryption tactics." A Brazilian threat actor cluster tracked as **Grupo Mauá** appeared via the bravox affiliate. Across the pipeline window, the leading actors by report count remain Qilin (82), Akira (74), The Gentlemen (63), DragonForce (33), ShinyHunters (31), and TeamPCP (27). MITRE ATT&CK: T1486 (Data Encrypted for Impact), T1485 (Data Destruction), T1566 (Phishing).

> **SOC Action:** Increase EDR sensitivity for `vssadmin delete shadows`, `wbadmin delete`, and bulk SMB file rename anomalies across file servers. Validate that immutable / object-lock copies of last week's backups exist and are restore-tested. For schools and SMB construction/engineering customers in particular, run a phishing-tabletop and review MFA enforcement on the M365 / VPN edge.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 CRITICAL | Rise in zero-day exploits targeting widely used software | Google Chrome zero-day exploited in the wild; new Linux kernel privilege-escalation vulnerability (CVE-2023-0185 referenced in batch 146) |
| 🔴 CRITICAL | Supply-chain attacks becoming more sophisticated, affecting major platforms and software ecosystems | TeamPCP campaign (Nx Console, durabletask, @antv); Laravel Lang compromised with RCE backdoor across 700+ versions |
| 🔴 CRITICAL | Ransomware-as-a-Service groups expanding operations globally | Adensa Teknoloji by nova; Sponseller Group by qilin; Global Retool Group by qilin |
| 🟠 HIGH | Targeting of multiple sectors by Brazilian threat actor Grupo Mauá | Grupo Mauá 🇧🇷 by bravox; ISC Stormcast 1 June 2026 references the activity |
| 🟠 HIGH | Increased targeting of critical infrastructure with vulnerabilities in widely used cryptographic libraries | CVE-2026-34875 (Mbed TLS FFDH buffer overflow); CVE-2026-42012 (GnuTLS certificate-validation bypass) |
| 🟠 HIGH | Rising incidents of ransomware targeting diverse sectors with sophisticated TTPs | STAREMPIRE by gunra; Lake Washington School District by cmd organization |
| 🟠 HIGH | Genesis ransomware group targeting multiple sectors with phishing and data encryption tactics | Cavalier Flooring Systems; Green Resource; Wentworth; A Roettgers (all by genesis) |
| 🟠 HIGH | Focus on arbitrary-code-execution vulnerabilities in critical infrastructure components | Critical OpenSSL RCE; Microsoft Exchange on-premises arbitrary code execution |
| 🟠 HIGH | Increased exploitation of unauthenticated access vulnerabilities across various platforms | Palo Alto GlobalProtect VPN auth bypass exploited in attacks; Fortinet FortiOS unauthenticated RCE |
| 🟠 HIGH | APT groups intensifying espionage campaigns targeting technology and defense sectors | Tracking Iranian APT Screening Serpens' 2026 espionage campaigns; Fast and Furious — Nimbus Manticore operations |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **Qilin** (82 reports) — Dominant RaaS affiliate, broad sector targeting, Tor leak site active
- **Akira** (74 reports) — Continued high-tempo ransomware activity, healthcare and manufacturing exposure
- **The Gentlemen** (63 reports) — Sustained leak-site posting cadence
- **DragonForce** (33 reports) — Hacktivist-origin operator now running financially motivated ops
- **ShinyHunters** (31 reports) — Data-extortion operations, brand-name victim listings
- **TeamPCP** (27 reports) — Supply-chain operator behind the Nx Console / durabletask / @antv compromises
- **Genesis** (20 reports) — Multi-sector phishing-led ransomware sweep
- **Everest** (20 reports) — Active leak-site cadence
- **Inc Ransom** (19 reports) — Mid-tier affiliate activity
- **Nova / RALord** (18 / 10 reports) — Emerging RaaS operator
- **Safepay** (18 reports) — Persistent leak-site posting
- **Stormous** (16 reports) — Sustained operations
- **Lamashtu** (14 reports) — Newer affiliate, climbing
- **Nightspire** (14 reports) — Active April–May
- **ShinyHunters (variant casing)** (13 reports) — Same operator cluster as above

### Malware Families

- **RansomLook** (126 reports) — Aggregator tag, not a family — reflects volume of leak-site posts
- **Akira ransomware** (38) — Plus 25 entries under bare "Akira" and 16 under "Akira Ransomware" — same family
- **Tox1 / Tox** (31 / 17) — The Gentlemen-linked builder
- **Mini Shai-Hulud** (10) — TeamPCP supply-chain worm framework, source reportedly published to GitHub
- **NetSupport RAT** — SmartApeSG ClickFix campaign deployment (this week)
- **Everest ransomware** (11)
- **Qilin** (11 entries, family-level)
- **RALord** (10) — Nova-linked
- **Nova** (10)
- **Nightspire** (9)
- **Chaos Ransomware** (8)

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| Microsoft | 474 | [link](https://msrc.microsoft.com/update-guide/) | MSRC CVE batch — bulk of weekly volume; cryptographic libraries, kernel, Go ecosystem |
| RansomLook | 76 | [link](https://www.ransomlook.io/) | Ransomware leak-site aggregator; Qilin, Akira, Gunra, Genesis posts |
| Unknown | 23 | — | Telegram (channel name redacted); exploit / PoC posts (TLP:AMBER+STRICT) |
| CISA | 20 | [link](https://www.cisa.gov/news-events/cybersecurity-advisories) | ICS / ICSMA advisories; five critical-rated this week |
| BleepingComputer | 19 | [link](https://www.bleepingcomputer.com/news/security/wp-maps-pro-bug-exploited-to-create-admin-accounts-on-wordpress-sites/) | Lead coverage of WP Maps Pro exploitation and Gogs zero-day |
| AlienVault | 15 | [link](https://otx.alienvault.com/) | OTX pulses; IOC enrichment |
| SANS | 11 | [link](https://isc.sans.edu/diary/rss/33014) | TeamPCP supply-chain analysis; NetSupport RAT infection diary |
| Wired Security | 7 | [link](https://www.wired.com/category/security/) | Mainstream cyber reporting |
| HaveIBeenPwned | 5 | [link](https://haveibeenpwned.com/) | Breach disclosures |
| RecordedFutures | 5 | [link](https://www.recordedfuture.com/research) | Threat intelligence research |
| Wiz | 5 | [link](https://www.wiz.io/blog) | Cloud and Gogs research |
| Schneier | 4 | [link](https://www.schneier.com/) | Editorial commentary |
| Cisco Talos | 4 | [link](https://blog.talosintelligence.com/) | Vendor threat research |
| ESET Threat Research | 4 | [link](https://www.welivesecurity.com/) | Malware analysis |
| Crowdstrike | 4 | [link](https://www.crowdstrike.com/blog/) | Adversary tradecraft reporting |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Update all WP Maps Pro installations to 6.1.1 and hunt `wp_users` for newly created administrators with email `support@flippercode.com` — exploitation is active (CVE-2026-8732).
- 🔴 **IMMEDIATE:** Take Internet-exposed Gogs instances offline or disable open registration and rebase-merging until a patch ships; hunt for `git rebase --exec=` argument-injection in Gogs server logs.
- 🔴 **IMMEDIATE:** Rotate developer / CI-CD OIDC credentials; pin and re-validate `Nx Console`, `durabletask`, `echarts-for-react`, `size-sensor`, and any `@antv` npm packages — assume any of these installed in the publish windows is compromised.
- 🔴 **IMMEDIATE:** Patch Eppendorf BioFlo 320 bioreactors (CVE-2026-7251) and PUSR USR-W610 converters (CVE-2026-7786); both have CVSS 9.8 with trivial exploitation. Confirm KMW CCTV and XCharge C6 fixes deployed.
- 🟠 **SHORT-TERM:** Apply the Mbed TLS / GnuTLS / Libsolv / OpenSC / libyang / Go-crypto patches across Linux estate and rebuild container base images; prioritise TLS-terminating hosts and certificate-processing services.
- 🟠 **SHORT-TERM:** Upgrade Node.js 20 to a release with `llhttp` v9; upgrade Node 22/24/25 to versions including the V8 hash-collision fix. Add request-size and rate limits in front of JSON-parsing endpoints.
- 🟡 **AWARENESS:** SmartApeSG ClickFix lures are the dominant initial-access vector this week. Refresh user-awareness messaging on fake "verify you are human" prompts and ensure the listed C2 indicators are blocked at egress.
- 🟢 **STRATEGIC:** Stop treating marketplace publisher-verified badges and attestation signals as install-time safety guarantees. Gate VS Code / npm / PyPI installs through an internal mirror with a delay-and-review window; deploy SBOM-driven continuous re-scan of base images.

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 695 reports processed across 6 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
