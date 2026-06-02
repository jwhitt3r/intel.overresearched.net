---
layout: post
title:  "CTI Daily Brief: 2026-06-01 — Android Zero-Day CVE-2025-48595 Under Active Exploitation, CISA Adds Oracle WebLogic CVE-2024-21182 to KEV, Mini Shai-Hulud Hits Red Hat npm"
date:   2026-06-02 20:05:48 +0000
description: "Google patches an actively exploited Android Framework zero-day; CISA adds a two-year-old Oracle WebLogic flaw to KEV; a Mini Shai-Hulud variant (Miasma) compromises 32 @redhat-cloud-services npm packages; Gamaredon and Turla confirmed operating jointly against Ukraine."
category: daily
tags: [cti, daily-brief, teampcp, gamaredon, turla, mini-shai-hulud, miasma, cve-2025-48595, cve-2024-21182]
classification: TLP:CLEAR
reporting_period: "2026-06-01"
generated: "2026-06-02"
draft: true
severity: critical
report_count: 112
sources:
  - Microsoft
  - RansomLook
  - BleepingComputer
  - RecordedFutures
  - Unit42
  - SentinelOne
  - SANS
  - Schneier
  - Wired Security
  - CertEU
  - CISA
  - Elastic Security Labs
  - Sysdig
  - Upwind
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-06-01 (24h) | TLP:CLEAR | 2026-06-02 |

## 1. Executive Summary

The pipeline processed 112 reports across 14 named sources in the last 24 hours, with 9 rated critical and 60 high. The dominant theme is software supply chain risk: a Mini Shai-Hulud variant named **Miasma** compromised at least 32 packages under the `@redhat-cloud-services` npm namespace, prompting Red Hat to purge the packages and Unit 42 to publish a refreshed npm threat landscape report. Google released June Android patches addressing **CVE-2025-48595**, an Android Framework privilege-escalation flaw under limited targeted exploitation. CISA added **CVE-2024-21182** (Oracle WebLogic Server T3/IIOP unauthenticated RCE) to the KEV catalogue with a 4 June federal remediation deadline. Microsoft pushed eight additional critical CVEs spanning GnuTLS, PHP-FPM, CoreDNS (TSIG auth bypass over DoH/DoH3/gRPC/QUIC) and the `golang.org/x/crypto/ssh` package (two auth-bypass class issues). Ransomware leak-site activity remains elevated, with Qilin, Safepay, Krybit, Nova and Coinbase Cartel posting victims across manufacturing, healthcare and construction.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 9 | Unit42 npm landscape; Android zero-day CVE-2025-48595; Microsoft criticals in GnuTLS, PHP-FPM, CoreDNS, Go x/crypto/ssh |
| 🟠 **HIGH** | 60 | RansomLook leak posts (Qilin, Safepay, Krybit, Nova, Coinbase Cartel); CISA Oracle WebLogic KEV add; Gamaredon×Turla; Operation FlutterBridge; Meta AI account theft |
| 🟡 **MEDIUM** | 31 | Misc CVE advisories, secondary blog coverage |
| 🟢 **LOW** | 1 | SANS ISC daily stormcast item |
| 🔵 **INFO** | 11 | Vendor blog notices, sector briefings |

## 3. Priority Intelligence Items

### 3.1 Mini Shai-Hulud "Miasma" Variant Compromises Red Hat Cloud Services npm Packages

**Source:** [Unit 42](https://unit42.paloaltonetworks.com/monitoring-npm-supply-chain-attacks/), [Recorded Future News](https://therecord.media/red-hat-removes-tainted-packages-after-software-pipeline-compromise)

A compromised GitHub account was used on 1 June to push a credential-stealing payload into 32 packages under the `@redhat-cloud-services` npm namespace, which collectively receive ~117,000 weekly downloads. The payload, named **Miasma** by its authors, is a cosmetic re-skin of the **Mini Shai-Hulud** worm whose source TeamPCP published on 12 May along with a $1,000 BreachForums "largest supply chain attack" contest. Red Hat removed the packages and states no customer action is required based on preliminary analysis. Unit 42's parallel write-up confirms Mini Shai-Hulud is "no longer scoped to TeamPCP" — copycat activity using the leaked source is muddying attribution. Recent activity in this cluster includes the March LiteLLM compromise (which led to a Mercor breach) and a separate axios JavaScript library campaign attributed to North Korean operators.

**Affected:** npm `@redhat-cloud-services/*` packages; downstream CI/CD pipelines that consumed those packages between commit time and Red Hat's pull. **Sector:** software development, cloud services.

**MITRE ATT&CK:** T1195.002 (Supply Chain Compromise: Software Dependencies), T1566.001 (Spearphishing Attachment — earlier Shai-Hulud waves), T1071 (Application Layer Protocol), T1197.001 (File Deletion).

> **SOC Action:** Query SCA/SBOM inventories for any `@redhat-cloud-services/*` package installed on or after 2026-06-01. Rotate npm tokens, GitHub PATs and any cloud credentials referenced in build environments that pulled affected versions. Add detections for outbound connections from build agents to non-Red-Hat endpoints during `npm install` windows. Block `postinstall` scripts on developer workstations where business-justifiable.

### 3.2 Google Patches Actively Exploited Android Framework Zero-Day CVE-2025-48595

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/google-fixes-one-actively-exploited-android-zero-day-124-flaws/)

Google's June Android Security Bulletin addresses 124 vulnerabilities, including **CVE-2025-48595**, an Android Framework flaw under "limited, targeted exploitation". The flaw allows local code execution and privilege escalation on Android 14+ devices without user interaction. Google has not released technical details; historically, similar Framework zero-days have been weaponised by commercial spyware vendors and nation-state operators against journalists, dissidents and government targets. Two patch levels were issued: 2026-06-01 and 2026-06-05 (the latter bundling Qualcomm and kernel fixes). Pixel devices receive updates immediately; OEM rollouts will lag.

**Affected:** Android 14, 15, and 16 devices across all OEMs.

**MITRE ATT&CK:** T1068 (Exploitation for Privilege Escalation), T1404 (Exploitation for Client Execution).

> **SOC Action:** Enforce mobile SPL ≥ 2026-06-05 via MDM. Flag managed Android devices stuck below the 2026-06-01 SPL for forced compliance within 7 days. For executive-protection populations, audit sideloaded apps and review recent SafetyNet/Play Integrity attestation failures.

### 3.3 CISA Adds Oracle WebLogic CVE-2024-21182 to KEV — Federal Deadline 4 June

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/cisa-orders-feds-to-patch-actively-exploited-oracle-weblogic-flaw/)

CISA added **CVE-2024-21182** to the Known Exploited Vulnerabilities catalogue and issued a BOD 22-01 directive requiring federal agencies to patch by midnight 4 June 2026. The flaw, patched by Oracle in July 2024, allows an unauthenticated remote attacker with network access via T3 or IIOP to take complete control of Oracle WebLogic Server 12.2.1.4.0 and 14.1.1.0.0. Shodan currently identifies 1,592 internet-exposed vulnerable instances (961 on 12.2.1.4.0; 631 on 14.1.1.0.0). CISA explicitly urged private-sector defenders to apply the same urgency.

**Affected:** Oracle WebLogic Server 12.2.1.4.0 and 14.1.1.0.0 with T3/IIOP exposed.

**MITRE ATT&CK:** T1190 (Exploit Public-Facing Application), T1021 (Remote Services), T1071.001 (Web Protocols).

> **SOC Action:** Inventory WebLogic deployments; block T3 and IIOP at the perimeter where not business-essential. Hunt outbound traffic from WebLogic JVMs spawning `java`-child processes such as `cmd.exe`, `powershell.exe`, `wscript.exe`, or reverse-shell tooling. Verify the July 2024 Oracle CPU is applied.

### 3.4 Critical Library CVE Cluster: GnuTLS, PHP-FPM, CoreDNS, golang.org/x/crypto/ssh

**Source:** Microsoft MSRC update guide — [CVE-2026-42015 GnuTLS](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-42015), [CVE-2026-35579 CoreDNS](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-35579), [CVE-2026-46595 x/crypto/ssh](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-46595)

Microsoft published eight critical-severity advisories on 2 June covering widely deployed open-source libraries:

- **CVE-2026-42015** — GnuTLS off-by-one in PKCS#12 bag handling; memory corruption with potential RCE on systems parsing attacker-supplied PKCS#12 (TLS clients, mail systems, certificate pipelines).
- **CVE-2026-35579** — CoreDNS TSIG authentication bypass on gRPC, QUIC, DoH and DoH3 transports. Unauthorised zone-transfer / DNS record access where CoreDNS exposes those transports.
- **CVE-2026-46595** — `golang.org/x/crypto/ssh` `VerifiedPublicKeyCallback` skips permissions enforcement, enabling authentication bypass in Go SSH servers using public-key auth.
- **CVE-2026-42508** — `golang.org/x/crypto/ssh/knownhosts` fails to enforce `@revoked` status — revoked keys remain trusted.
- **CVE-2026-25680** — `golang.org/x/net/html` DoS via malformed HTML parsing.
- **CVE-2026-6735** — XSS within PHP-FPM status endpoint.
- **CVE-2025-14179** — pdo_firebird SQL injection via NUL bytes in quoted strings.
- **CVE-2026-7261** — SoapServer session-persisted object use-after-free via SOAP header fault (rated high; same cluster).

No in-the-wild exploitation is reported for any of these advisories.

**MITRE ATT&CK:** T1190 (Public-Facing Application), T1078 (Valid Accounts — via SSH auth bypass), T1499 (Endpoint DoS).

> **SOC Action:** Sweep SCA reports for affected Go module versions (`golang.org/x/crypto`, `golang.org/x/net`), GnuTLS, CoreDNS and PHP-FPM. Prioritise: (a) Go SSH bastions or jump-hosts that authenticate via `VerifiedPublicKeyCallback`; (b) CoreDNS instances exposing gRPC/QUIC/DoH/DoH3 transports (common in service-mesh and resolver deployments); (c) certificate ingestion pipelines that parse PKCS#12 with GnuTLS. Rebuild and redeploy.

### 3.5 Gamaredon × Turla — Confirmed Joint Operations Against Ukraine

**Source:** [SentinelOne LABScon](https://www.sentinelone.com/labs/labscon25-replay-gamaredon-x-turla-unveiling-a-2025-espionage-alliance-targeting-ukraine/)

ESET researchers Matthieu Faou and Zoltán Rusnák presented LABScon evidence that **Gamaredon** tooling (PteroGraphin, PteroOdd) was used between February and June 2025 to deploy **Turla's Kazuar** backdoor on Ukrainian military and government targets — and in at least one instance to restore Turla's access after the group lost its foothold. This is the first technical confirmation of operational hand-off between the two Russian state-aligned actors, suggesting an access-broker / advanced-implant division of labour. The talk also examines Kazuar v2 and v3 capabilities. Correlated with separate FSB Gamaredon coverage (GammaPhish/GammaWorm) in the same batch.

**Affected:** Ukrainian government, military, defence-industrial base.

**MITRE ATT&CK:** T1566 (Phishing — Gamaredon spearphishing), T1071.001 (Web Protocols), T1027 (Obfuscated Files), T1082 (System Information Discovery).

> **SOC Action:** For organisations supporting Ukraine operations, hunt for PteroGraphin / PteroOdd loader artefacts (LNK + HTA / `mshta.exe` lineage from user `%TEMP%`), Kazuar C2 patterns, and persistence via scheduled tasks or registry Run keys with random-named values. Block macro execution from external sources; alert on `mshta.exe` spawned by `outlook.exe` or `explorer.exe`.

### 3.6 Meta AI Abused to Hijack High-Value Instagram Accounts

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/instagram-users-locked-out-after-meta-ai-abused-to-steal-accounts/)

Multiple Instagram users — including accounts previously used by the Obama White House team, researcher Jane Manchun Wong, `@hey`, and `@korn` — reported takeovers in which attackers convinced Meta's AI-powered support to change the account email. Attackers pulled the target's profile photo, animated it via an AI video generator, and submitted the resulting "selfie video" to Meta's identity-verification flow, which accepted the synthetic media and bypassed 2FA. VPN endpoints in the target's home region were used to pass geolocation checks. Recovery is hampered by Meta's removal of human support pathways. Meta VP Andy Stone said the "issue has been resolved" for affected accounts; the underlying control gap (AI accepting deepfaked selfie video) is not publicly resolved.

**Affected:** Instagram users; broader risk to any platform that gates account recovery on AI-evaluated liveness/selfie checks.

**MITRE ATT&CK:** T1566 (Phishing — social engineering), T1078 (Valid Accounts), T1133 (External Remote Services).

> **SOC Action:** Brief executive-protection clients about the attack pattern. For corporate-managed social accounts, enable hardware-key 2FA where available, lock email-change actions behind admin approval, and pre-stage break-glass contacts via Meta Business support tier. Treat platform account-recovery flows that rely solely on AI verification as compromised by design.

### 3.7 Operation FlutterBridge — macOS Malvertising Drops FlutterShell Backdoor

**Source:** [Unit 42](https://unit42.paloaltonetworks.com/flutterbridge-new-fluttershell-backdoor/)

Unit 42 tracks an expanding macOS malvertising campaign (cluster **CL-CRI-1089**, a successor to JSCoreRunner) distributing **FlutterShell**, a Flutter-framework backdoor with shell-execution, filesystem manipulation, and AI-summarisation abuse for data exfiltration (documents routed through an attacker-controlled summariser before processing). Distribution is via hundreds of Google-verified ads using shell-company advertisers; targeting emphasises Anglophone and Western European markets. Google has suspended the advertiser accounts. CL-CRI-1089 also runs Windows operations (RecipeLister, Calendaromatic — previously bucketed under "TamperedChef").

**Affected:** macOS desktops in Anglophone / Western European user populations.

**MITRE ATT&CK:** T1566.002 (Spearphishing Link — via search-ad), T1071.001 (Web Protocols), T1059 (Command & Scripting Interpreter), T1567 (Exfiltration Over Web Service).

> **SOC Action:** Hunt macOS endpoints for unsigned Flutter-built applications in `~/Applications` and `/Applications`, processes spawning `osascript` or `sh` from `Contents/MacOS/`, and outbound connections from such processes to recently-registered domains. Block ad-network click-through downloads in browser policy. Add an EDR rule for AI-summarisation API calls originating from non-browser binaries.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Supply chain attacks exploiting npm packages and software development ecosystems | Unit 42 npm landscape (Jun 2); Red Hat Mini Shai-Hulud / Miasma compromise; copycat activity post-TeamPCP source release |
| 🟠 **HIGH** | Ransomware activity across manufacturing, healthcare, education and construction | Qilin (Nova Medical Products, Clinica Maitenes); Safepay (iql-nog.com); Krybit (activ88-interim, transbras); Nova (Everlite, IBENA); Coinbase Cartel (Cambridge Mobile Telematics, Panasonic.Aero) |
| 🟠 **HIGH** | Phishing and account-takeover leveraging AI and social engineering | Meta AI / Instagram account theft; "browser as front line for AI security" (BleepingComputer); CertEU May 2026 briefing |
| 🟠 **HIGH** | State-sponsored espionage against government and critical infrastructure | Gamaredon×Turla LABScon disclosure; FSB Gamaredon "matryoshka" (GammaPhish/GammaWorm); CISA WebLogic KEV add (government-sector exposure) |
| 🟠 **HIGH** | Application-layer protocol and user-execution vulnerability exploitation | CVE-2026-44839 RabbitMQ XSS; CVE-2025-14179 pdo_firebird SQLi; CISA WebLogic T3/IIOP |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **Qilin** (79 reports) — High-volume RaaS; new healthcare victims today (Nova Medical Products, Clinica Maitenes)
- **Akira** (74 reports) — Sustained RaaS posting; no new activity in this 24-hour window
- **The Gentlemen** (63 reports) — Mid-tier ransomware operator
- **DragonForce** (33 reports) — Ransomware/extortion crew
- **TeamPCP** (32 reports) — Mini Shai-Hulud author; post-open-source attribution now ambiguous
- **ShinyHunters** (32 reports) — Data-theft and extortion brand
- **Safepay** (21 reports) — Active today (iql-nog.com)
- **Genesis** (20 reports) — Stealer-log marketplace activity
- **Nova** (19 reports) — Active today (Everlite concept, IBENA Textilwerke)
- **Inc Ransom** (19 reports) — Ransomware operator

### Malware Families

- **RansomLook tracker entries** (123 reports) — Aggregated leak-site postings (Qilin, Akira, Safepay, Krybit, Nova, Coinbase Cartel)
- **Akira ransomware** (38 reports) — Active operator family
- **Tox1** / **Tox** (31 / 17 reports) — Tracked ransomware codebase variants
- **Mini Shai-Hulud** (12 reports) — npm self-propagating worm; Miasma variant active today
- **RALord** (11 reports) — Emerging ransomware family
- **Kazuar** — Turla backdoor (LABScon disclosure)
- **FlutterShell** — New macOS backdoor (Unit 42, CL-CRI-1089)

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| Microsoft | 65 | [link](https://msrc.microsoft.com/update-guide) | Primary CVE advisory stream; 8 criticals today |
| RansomLook | 19 | [link](https://www.ransomlook.io) | Ransomware leak-site aggregator (Qilin, Safepay, Krybit, Nova, Coinbase Cartel) |
| BleepingComputer | 8 | [link](https://www.bleepingcomputer.com) | Android zero-day; CISA Oracle KEV; Meta AI hijacks |
| RecordedFutures | 5 | [link](https://therecord.media/red-hat-removes-tainted-packages-after-software-pipeline-compromise) | Red Hat npm compromise coverage |
| Unit42 | 2 | [link](https://unit42.paloaltonetworks.com/monitoring-npm-supply-chain-attacks/) | npm threat landscape; FlutterBridge / FlutterShell |
| SANS | 2 | [link](https://isc.sans.edu) | ISC daily stormcast |
| Schneier | 2 | [link](https://www.schneier.com/blog/) | Security commentary |
| Wired Security | 2 | [link](https://www.wired.com/category/security/) | Security long-form |
| Sentinel One | 1 | [link](https://www.sentinelone.com/labs/labscon25-replay-gamaredon-x-turla-unveiling-a-2025-espionage-alliance-targeting-ukraine/) | LABScon Gamaredon×Turla disclosure |
| CertEU | 1 | [link](https://www.cert.europa.eu/publications/security-advisories) | Monthly cyber brief (26-06) |
| CISA | 1 | [link](https://www.cisa.gov/news-events/cybersecurity-advisories) | KEV-related coverage |
| Elastic Security Labs | 1 | [link](https://www.elastic.co/security-labs) | Vendor threat research |
| Sysdig | 1 | [link](https://sysdig.com/blog/) | Cloud security research |
| Upwind | 1 | [link](https://www.upwind.io) | Cloud security research |
| Unknown | 1 | — | Source attribution unavailable |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Sweep CI/CD and developer machines for `@redhat-cloud-services/*` npm packages installed on or after 2026-06-01; rotate npm tokens, GitHub PATs and cloud secrets in any environment where those packages were resolved (§3.1).
- 🔴 **IMMEDIATE:** Apply June Android SPL ≥ 2026-06-05 to managed mobile fleet; force compliance for executive and high-risk populations within 7 days (§3.2).
- 🔴 **IMMEDIATE:** Patch or isolate Oracle WebLogic 12.2.1.4.0 / 14.1.1.0.0 instances; block T3 and IIOP at the perimeter ahead of CISA's 4 June federal deadline (§3.3).
- 🟠 **SHORT-TERM:** Rebuild any service exposing CoreDNS over gRPC/QUIC/DoH/DoH3 (CVE-2026-35579) or running Go SSH servers using `golang.org/x/crypto/ssh` (CVE-2026-46595, CVE-2026-42508); patch GnuTLS (CVE-2026-42015) wherever PKCS#12 is parsed (§3.4).
- 🟠 **SHORT-TERM:** Deploy hunting for PteroGraphin/PteroOdd → Kazuar chains on systems supporting Ukrainian government/defence partners (§3.5).
- 🟡 **AWARENESS:** Brief executive-protection clients on AI-deepfake-driven Instagram account takeover; review account-recovery posture for corporate-managed social presences (§3.6).
- 🟢 **STRATEGIC:** Treat `npm install` as a privileged operation; track Mini Shai-Hulud derivatives. Expect sustained increase in supply-chain attacks given the open-sourced Mini Shai-Hulud code and active $1,000 BreachForums contest.

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 112 reports processed across 3 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
