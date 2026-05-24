---
layout: post
title:  "CTI Daily Brief: 2026-05-23 - The Gentlemen ransomware sweeps 8 organisations; Laravel Lang supply-chain attack drops credential stealer; ShinyHunters extort 7-Eleven (185k records)"
date:   2026-05-24 20:07:06 +0000
description: "The Gentlemen ransomware group claimed 8 fresh victims across Japan, Ireland, Turkey, Poland, Austria, the US, France and Argentina in a single 24-hour burst. A separate supply-chain compromise rewrote GitHub tags on the Laravel Lang Composer packages to push the DebugElevator credential stealer to developers, while ShinyHunters published 185,256 records from a 7-Eleven extortion campaign."
category: daily
tags: [cti, daily-brief, the-gentlemen, shinyhunters, bravox, laravel-lang, debugelevator, tox1, supply-chain]
classification: TLP:CLEAR
reporting_period: "2026-05-23"
generated: "2026-05-24"
draft: true
severity: high
report_count: 13
sources:
  - RansomLook
  - BleepingComputer
  - HaveIBeenPwned
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-05-23 (24h) | TLP:CLEAR | 2026-05-24 |

## 1. Executive Summary

Thirteen reports were ingested in the last 24-hour cycle across three sources, dominated by ransomware leak-site activity (RansomLook contributed 11 of 13 reports). The Gentlemen ransomware group is the headline actor of the period, posting eight new victims to its onion leak site in a coordinated burst spanning logistics, engineering, glass packaging, telecom and office-systems verticals across Japan, Ireland, Turkey, Poland, Austria, the United States, France and Argentina. A separate supply-chain compromise of the Laravel Lang Composer packages — flagged as a critical-risk trend by the correlation engine — rewrote GitHub tags across at least four repositories to deliver the cross-platform `DebugElevator` credential stealer, which targets cloud, CI/CD, browser and cryptocurrency secrets. ShinyHunters published 185,256 records from an April 2026 "pay-or-leak" extortion of 7-Eleven, and a smaller Bravox affiliate added the Salvation Army Canada to its leak feed. No CISA KEV additions or confirmed in-the-wild zero-day exploitation were captured this cycle.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 0 | None at report level — but correlation engine flagged supply-chain credential theft as a critical-risk trend |
| 🟠 **HIGH** | 12 | The Gentlemen leak-site posts (8); 7-Eleven breach (ShinyHunters); Laravel Lang supply-chain attack; Bravox Salvation Army Canada post; Sanatorio Delta |
| 🟡 **MEDIUM** | 1 | Bravox post against Emek Elektrik (Turkey) |
| 🟢 **LOW** | 0 | — |
| 🔵 **INFO** | 0 | — |

## 3. Priority Intelligence Items

### 3.1 The Gentlemen ransomware — eight-victim burst across four continents

**Source:** [RansomLook — The Gentlemen leak site](https://www.ransomlook.io//group/the%20gentlemen)

Between 05:51 and 06:25 UTC on 2026-05-24, the Gentlemen leak portal published eight new victim posts in a 34-minute window: Koa Glass (Japan, luxury glass packaging — Chanel/Shiseido/L'Oréal/Estée Lauder supplier), Openmind Networks (Ireland, telecom messaging — ~$20.1M revenue, processes 1.5B messages/day), Caka Grup Lojistik (Turkey, logistics), TRANSSYSTEM Group (Poland, intralogistics — Tesla/Goodyear/Michelin/KUKA supplier), ACAM Systemautomation (Austria, Siemens PLM integrator), Seeley Office Systems (USA, managed print services, NY), Le Perreux sur Marne (France, municipal), Sanatorio Delta (Argentina, healthcare) and Hussey Seatway. The group has now posted 433 victims all-time and 84 in the past 30 days, sustaining 28% average uptime on its primary onion. Correlation confidence on the shared-actor cluster is 0.95.

Tradecraft per the RansomLook fingerprint and Trend Micro's prior unmasking (referenced in the leak-site description): Tox protocol for C2 / negotiation messaging, Tor-hosted leak and chat infrastructure, double-extortion model, and an encryptor identifier hash of `F8E24C7F5B12CD69C44C73F438F65E9BF560ADF35EBBDF92CF9A9B84079F8F04060FF98D098E`. Reported MITRE techniques across the cluster: T1566 (Phishing), T1204 (User Execution), T1071 / T1071.001 (Application Layer Protocol / Web Protocols), T1486 (Data Encrypted for Impact), T1205 (Spearphishing via Service) and T1027.004 (Obfuscated Files or Information: Compile After Delivery).

**Affected sectors:** glass/packaging manufacturing, telecommunications, logistics, industrial engineering, healthcare, municipal government, office-systems / managed print, automotive supply chain (TRANSSYSTEM is a Tesla and Goodyear supplier — secondary supply-chain exposure is plausible).

#### Indicators of Compromise

```
Leak site (onion):   hxxp[://]tezwsse5czllksjb7cwp65rvnk4oobmzti2znn42i43bjdfd2prqqkad[.]onion/
Chat server (onion): hxxp[://]i2ohjeeqe37jre4f2u7pyq73cbm6lecumdxapkvrlryna6rc3it4zsid[.]onion/
Encryptor ID hash:   F8E24C7F5B12CD69C44C73F438F65E9BF560ADF35EBBDF92CF9A9B84079F8F04060FF98D098E
C2 protocol:         Tox (decentralised P2P messaging)
Reference research:  hxxps[://]www[.]trendmicro[.]com/en_us/research/25/i/unmasking-the-gentlemen-ransomware.html
```

> **SOC Action:** Block egress to Tox bootstrap nodes and the listed onion services at the proxy/firewall. Hunt EDR for processes initiating outbound traffic to UDP ports commonly used by Tox (33445/UDP and variants). If you are downstream of TRANSSYSTEM, ACAM, Seeley Office Systems or Koa Glass in any supply chain, raise the threshold on supplier-originated email and proactively rotate any shared portal credentials. Validate offline backups for production file shares — Gentlemen's encryptor maps to T1486.

---

### 3.2 Laravel Lang Composer packages hijacked via GitHub tag rewrite — DebugElevator credential stealer

**Source:** [BleepingComputer — Laravel Lang packages hijacked to deploy credential-stealing malware](https://www.bleepingcomputer.com/news/security/laravel-lang-packages-hijacked-to-deploy-credential-stealing-malware/)

On 2026-05-23, StepSecurity, Aikido Security and Socket disclosed a coordinated supply-chain compromise affecting four Laravel Lang organisation repositories: `laravel-lang/lang` (flagship, 502 tags), `laravel-lang/http-statuses`, `laravel-lang/attributes` and likely `laravel-lang/actions`. Rather than publishing new malicious releases, the actor abused a GitHub feature that allows tags to point to commits in repository forks: starting at 22:32 UTC against `laravel-lang/lang` and finishing by 00:00 UTC against `laravel-lang/actions`, every existing git tag was rewritten to point at a malicious commit in an attacker-controlled fork. Aikido reports 233 versions compromised across three repositories; Socket estimates ~700 historical versions may be affected. All four repos share the same fake author identity, the same modified files and the same payload behaviour — almost certainly a single actor with one credential carrying org-wide push access. These are third-party localisation packages and are **not** part of the official Laravel framework.

Installation via Composer triggers `src/helpers.php` (added to the autoload section of `composer.json`), which acts as a dropper for a second-stage PHP payload pulled from `flipboxstudio[.]info`. The stealer is cross-platform (Linux, macOS, Windows) and harvests cloud credentials, Kubernetes secrets, Vault tokens, Git credentials, CI/CD secrets, SSH keys, browser data, cryptocurrency wallets, password managers, VPN configurations and local `.env` files, using regex patterns to extract AWS keys, GitHub tokens, Slack tokens, Stripe secrets, JWTs and crypto recovery phrases. On Windows the PHP payload writes a base64-embedded executable — `DebugElevator` — to `%TEMP%\<random>.exe` and launches it; the binary targets Chrome, Brave and Edge to lift App-Bound Encryption keys for stored credential decryption. An embedded PDB path references the Windows username `Mero`. Mapped TTPs: T1195.002 (Compromise Software Supply Chain), T1566 (Phishing — referenced via the package distribution vector), T1071.001 (Application Layer Protocol: Web Protocols), T1555 / T1555.003 (Credentials from Password Stores / Web Browsers) and T1552 (Unsecured Credentials).

#### Indicators of Compromise

```
C2 / payload host:    flipboxstudio[.]info
Dropper file:         src/helpers.php (added to composer.json autoload)
Windows stealer:      DebugElevator (random-name .exe in %TEMP%)
PDB artefact:         path references Windows user "Mero"
Affected packages:    laravel-lang/lang, laravel-lang/http-statuses,
                      laravel-lang/attributes, laravel-lang/actions
Affected versions:    ~233 confirmed (Aikido); ~700 possible (Socket)
Compromise window:    2026-05-22 22:32 UTC → 2026-05-23 00:00 UTC
```

> **SOC Action:** Query CI/CD logs and developer endpoints for Composer installs or updates of `laravel-lang/*` packages since 2026-05-22 22:00 UTC. Block `flipboxstudio[.]info` at egress proxies and DNS. Hunt EDR for `php.exe` or unusual `.exe` writes into `%TEMP%` originating from PHP processes, and for any process named `DebugElevator` or short-name random executables spawned from a PHP CLI parent. Rotate any AWS keys, GitHub PATs, Slack tokens, Stripe secrets, SSH keys, Vault tokens and Kubernetes service-account tokens that were materialised in environments where the affected packages were installed. Treat browser-stored credentials on affected Windows hosts as compromised — force re-auth and clear App-Bound Encryption-protected stores.

---

### 3.3 ShinyHunters "pay-or-leak" extortion of 7-Eleven — 185,256 accounts published

**Source:** [HaveIBeenPwned — 7-Eleven breach record](https://haveibeenpwned.com/Breach/7-Eleven)

Have I Been Pwned added a 7-Eleven breach on 2026-05-24 covering 185,256 unique email addresses, with associated names, physical addresses, dates of birth and phone numbers; a smaller subset of records includes additional fields. 7-Eleven attributes the incident to compromised "certain 7-Eleven systems used to store franchisee documents," consistent with the exposed data classes. The breach occurred in April 2026 as part of a ShinyHunters "pay or leak" extortion campaign and the data was subsequently published the same month. ShinyHunters appears in the trending-entity list with 29 reports across the last 30 days, indicating sustained operational tempo.

#### Indicators of Compromise

```
Affected accounts:    185,256
Exposed fields:       names, email addresses, physical addresses,
                      dates of birth, phone numbers
Breach window:        April 2026 (publication same month)
Attribution:          ShinyHunters (confirmed by HIBP)
Affected system:      franchisee document storage (7-Eleven internal)
```

> **SOC Action:** If your organisation operates 7-Eleven franchise relationships or shared systems, treat any of the listed PII as exposed and assume credential-stuffing and targeted phishing follow-on. For consumer-facing SOCs, queue user notifications via HIBP integration; for franchisee identity-fraud risk, advise affected DOB+address holders to enable credit-file monitoring. Add ShinyHunters TTPs (extortion-only, no encryption; Telegram channel and clearnet leak-blog publication) to detection playbooks for data-staging and exfiltration anomalies.

---

### 3.4 Bravox affiliate adds Salvation Army Canada and Emek Elektrik

**Source:** [RansomLook — Bravox leak site](https://www.ransomlook.io//group/bravox)

The smaller Bravox leak operation (15 total posts since inception, 4 in the last 30 days, 96% uptime across two onion mirrors) added two victims in this cycle: the Salvation Army Canada (charitable / social services — published 2026-05-23 23:48 UTC, rated high) and Emek Elektrik (Turkish manufacturer of current transformers, voltage transformers and disconnectors — published 2026-05-24 01:50 UTC, rated medium). No TTPs, malware family or encryption details are disclosed in the RansomLook record for Bravox.

#### Indicators of Compromise

```
Leak site (onion):    hxxp[://]bravoxxtrmqeeevhl7gdh2yzvlrjxajr66d33c7ozosrccx4cz7cepad[.]onion/
Leak mirror (onion):  hxxp[://]bravoxxwcfz5qk43ychgveprpd5mw5hvxfs4a2uz2okx7mumiht4fzyd[.]onion/
```

> **SOC Action:** Non-profit and charity-sector defenders should treat the Salvation Army Canada listing as confirmation that NPO targeting is active and rotate exposed donor- and beneficiary-system credentials. Industrial-control vendors with grid-equipment exposure should monitor Emek Elektrik supplier-portal activity. Block the listed onion services at outbound proxy.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Exploitation of software vulnerabilities and supply-chain attacks are increasingly being used to deploy credential-stealing malware | Laravel Lang Composer hijack delivering DebugElevator; Roundcube CVE-2025-49113 (authenticated PHP object deserialisation → RCE) cited in same correlation batch |
| 🟠 **HIGH** | The Gentlemen ransomware group is targeting multiple sectors across multiple regions, indicating a broad and coordinated campaign | 8 leak-site posts in 34 minutes (Openmind Networks, Koa Glass, ACAM Systemautomation, TRANSSYSTEM Group, Caka Grup Lojistik, Sanatorio Delta, Seeley Office Systems, Hussey Seatway); correlation confidence 0.95 |
| 🟠 **HIGH** | Shared User-Execution (T1204) tradecraft links ransomware leak-site activity to recent open-source RCE chains | Openmind Networks (Gentlemen), Seeley Office Systems (Gentlemen) and Roundcube CVE-2025-49113 share T1204 at correlation confidence 0.75 |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **Qilin** (108 reports) — sustained leak-site cadence; pipeline-leading volume over the last 30 days
- **Akira** (68 reports) — second-most-active group; consistent multi-sector targeting
- **The Gentlemen** (64 reports) — first observed 2026-04-29; today's 8-victim burst confirms accelerating tempo
- **TeamPCP** (35 reports) — steady leak activity
- **ShinyHunters** (29 reports) — extortion-only operation; today driven by the 7-Eleven publication
- **Inc Ransom** (24 reports) — active across multiple verticals
- **Safepay** (19 reports) — moderate cadence
- **Lockbit5** (19 reports) — successor branding; activity continuing
- **Everest** (18 reports) — periodic posting
- **FulcrumSec** (17 reports) — emerging affiliate

### Malware Families

- **RansomLook** (135 reports) — note: this is the OSINT aggregator tag, not a malware family per se; appears in every RansomLook-sourced report
- **Akira ransomware** (37 reports) — paired with Akira actor activity
- **Tox1** (34 reports) — Gentlemen's encrypted-comms tooling; today's posts add 4 fresh mentions
- **Other1** (23 reports) — Gentlemen-associated tooling tag
- **Akira** (21 reports) — malware namespace overlap with the actor entity
- **Tox** (18 reports) — base Tox protocol references
- **Qilin** (15 reports) — Qilin-named ransomware payload references
- **The Gentlemen** (14 reports) — malware-tagged variant of the actor name
- **Akira Ransomware** (14 reports) — duplicate-tagged Akira encryptor references
- **RaaS** (11 reports) — generic ransomware-as-a-service tag

> Vulnerability-entity trending returned no records in the last 30-day window for this cycle.

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| RansomLook | 11 | [link](https://www.ransomlook.io) | Drove the entire ransomware leak-site picture this cycle: 9 Gentlemen, 2 Bravox |
| BleepingComputer | 1 | [link](https://www.bleepingcomputer.com/news/security/laravel-lang-packages-hijacked-to-deploy-credential-stealing-malware/) | Single highest-impact narrative report: Laravel Lang supply-chain compromise |
| HaveIBeenPwned | 1 | [link](https://haveibeenpwned.com/Breach/7-Eleven) | Authoritative breach record for the ShinyHunters / 7-Eleven extortion |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Audit Composer dependency manifests organisation-wide for any reference to `laravel-lang/lang`, `laravel-lang/http-statuses`, `laravel-lang/attributes` or `laravel-lang/actions`. If found, pin to a known-good pre-2026-05-22 commit hash (not a tag), block `flipboxstudio[.]info` at egress, hunt for `DebugElevator` and PHP-spawned `%TEMP%\*.exe` activity, and rotate every credential class enumerated in §3.2 (AWS, GitHub PATs, Slack, Stripe, JWTs, SSH keys, Vault, K8s service accounts, browser-stored secrets).
- 🔴 **IMMEDIATE:** Block the two Gentlemen onion services and both Bravox mirrors at proxy/DNS; alert on Tox bootstrap traffic (UDP/33445 and known bootstrap node IPs). If your organisation supplies or is supplied by TRANSSYSTEM Group, ACAM Systemautomation, Koa Glass, Openmind Networks or Seeley Office Systems, raise vigilance on supplier-originated email and pre-emptively rotate any shared portal credentials.
- 🟠 **SHORT-TERM:** Stand up detection content for the Gentlemen cluster's MITRE chain — T1566 → T1204 → T1071.001 → T1486 — focused on phishing-delivered loader execution, anomalous outbound web-protocol C2 from non-browser processes, and mass file rename / extension change on production shares. Validate offline (air-gapped or immutable) backup integrity for the verticals listed in §3.1.
- 🟠 **SHORT-TERM:** Onboard the HIBP 7-Eleven dataset into user-notification and credential-stuffing detection pipelines; for any workforce identities matching the exposed PII, force MFA re-enrolment and watch for ShinyHunters-style staging on the Telegram channels and clearnet leak blogs they operate.
- 🟡 **AWARENESS:** The correlation engine has now linked Gentlemen-cluster T1204 (User Execution) tradecraft with Roundcube CVE-2025-49113 in the same batch. Patch Roundcube webmail to a post-49113 build and review web-server process lineage for PHP deserialisation indicators, even though no in-the-wild exploitation of Roundcube appears in today's report set.
- 🟢 **STRATEGIC:** Treat tag-rewrite supply-chain attacks (Laravel Lang) as the canonical pattern for the next 12 months: move CI/CD pipelines from tag-based to commit-SHA-pinned dependency resolution for all language ecosystems that allow it (Composer, npm, pip via hashes, Go modules with `go.sum`, Maven with checksums). Adopt provenance verification (e.g., Sigstore / npm provenance / SLSA Level 3) where the ecosystem supports it.

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 13 reports processed across 2 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
