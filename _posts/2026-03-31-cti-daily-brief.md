---
layout: post
title: "CTI Daily Brief: 2026-03-31 — Axios npm Supply Chain Attack Attributed to North Korea; Chrome Zero-Day CVE-2026-5281 Exploited in the Wild"
date: 2026-04-01 20:33:00 +0000
description: "Supply chain attacks dominate the threat landscape as the DPRK-attributed axios npm compromise and ongoing TeamPCP campaign against security tooling converge with a fourth Chrome zero-day, mass Android malware on Google Play, and sustained multi-group ransomware operations across critical sectors."
category: daily
tags: [cti, daily-brief, unc1069, teampcp, axios, darksword, novoice, akira, qilin, shinyhunters]
classification: TLP:CLEAR
reporting_period: "2026-03-31"
generated: "2026-04-01"
draft: true
severity: critical
report_count: 100
sources:
  - Microsoft
  - RansomLock
  - BleepingComputer
  - RecordedFutures
  - AlienVault
  - SANS
  - Unit42
  - Wired Security
  - Schneier
  - CertEU
  - RedCanary
  - Elastic Security Labs
  - BellingCat
  - HaveIBeenPwned
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-03-31 (24h) | TLP:CLEAR | 2026-04-01 |

## 1. Executive Summary

The pipeline processed 100 reports from 15 sources over the past 24 hours, with 26 rated critical and 26 high — an exceptionally elevated threat posture driven by two converging supply chain crises. Google's Threat Intelligence Group attributed the axios npm supply chain compromise to DPRK-linked threat actor UNC1069, while Unit 42 published a comprehensive analysis of TeamPCP's ongoing multi-stage campaign against security infrastructure including Trivy, KICS, and LiteLLM, with Mercor AI confirming it as the first public victim. Google patched a fourth Chrome zero-day in 2026 (CVE-2026-5281), a use-after-free in Dawn's WebGPU implementation confirmed exploited in the wild. A new Android malware family, NoVoice, infected 2.3 million devices via Google Play before removal. Ransomware activity remained intense, with Akira, Qilin, Nightspire, DragonForce, and ShinyHunters all posting new victims, including a claimed breach of Cisco Systems by ShinyHunters involving over 3 million Salesforce records.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 26 | Axios supply chain (DPRK/UNC1069); TeamPCP/CanisterWorm campaign; Chrome zero-day CVE-2026-5281; NoVoice Android malware; GIGABYTE RCE CVE-2026-4415; Handlebars.js injection CVE-2026-33937; Akira/DragonForce/Qilin ransomware claims |
| 🟠 **HIGH** | 26 | Apple DarkSword backported patches; Mercor breach confirmation; Romania daily cyberattack barrage; CrystalX MaaS RAT; Casbaneiro phishing campaigns; Nightspire/Worldleaks/Everest ransomware operations |
| 🟡 **MEDIUM** | 31 | Microsoft CVE advisories (OpenSC, brace-expansion); CERT-EU March Cyber Brief; credential dumping analysis; ESET monthly roundup |
| 🟢 **LOW** | 5 | Remcos RAT analysis; Samsung compatibility advisories |
| 🔵 **INFO** | 12 | Security tooling releases; awareness articles |

## 3. Priority Intelligence Items

### 3.1 Axios npm Supply Chain Attack — Attributed to DPRK Actor UNC1069

**Source:** [Unit42](https://unit42.paloaltonetworks.com/axios-supply-chain-attack/), [Recorded Future News](https://therecord.media/google-links-axios-supply-chain-attack-north-korea), [AlienVault/NSFOCUS](https://nsfocusglobal.com/axios-front-end-library-npm-supply-chain-poisoning-alert/), [Elastic Security Labs](https://elastic.co)

Attackers hijacked the npm account of axios maintainer Jason Saayman — changing the account email to an anonymous ProtonMail address — and published malicious versions v1.14.1 and v0.30.4 on March 31. No axios source code was modified; instead, a hidden runtime dependency `plain-crypto-js@4.2.1` was injected into `package.json`. This dependency executes a heavily obfuscated `setup.js` dropper during `npm install` that uses two-layer encoding (string reversal, Base64, XOR with key `OrDeR_7077`) before fetching platform-specific RAT payloads from a C2 server.

Google Threat Intelligence Group attributed the operation to UNC1069, a financially motivated DPRK-linked group previously observed deploying WAVESHAPER malware in fake Zoom campaigns targeting cryptocurrency firms. The backdoors deployed during the axios attack share code overlap with WAVESHAPER.

The malicious versions were live for approximately three hours before npm revoked all tokens and removed the packages. Given axios processes over 300 million downloads per week, the blast radius remains under assessment.

**Affected platforms:** Windows, macOS, Linux

**Timeline:**
- 2026-03-30 05:57 UTC — `plain-crypto-js@4.2.0` published (clean camouflage)
- 2026-03-30 23:59 UTC — `plain-crypto-js@4.2.1` published (malicious payload)
- 2026-03-31 00:21 UTC — `axios@1.14.1` published via npm CLI
- 2026-03-31 01:00 UTC — `axios@0.30.4` published via npm CLI
- 2026-03-31 03:40 UTC — npm removed malicious versions, revoked tokens

#### Indicators of Compromise
```
C2: sfrclak[.]com:8000
Dependency: plain-crypto-js@4.2.1
Malicious versions: axios@1.14.1, axios@0.30.4
XOR key: OrDeR_7077
macOS persistence: /Library/Caches/com.apple.act.mond
npm account email: Ifstap@proton[.]me
Camouflage account: nrwise@proton[.]me
```

> **SOC Action:** Immediately audit all Node.js projects for axios versions 1.14.1 or 0.30.4 and the `plain-crypto-js` dependency using `npm list axios | grep -E "1\.14\.1|0\.30\.4"` and `ls node_modules/plain-crypto-js`. Check CI/CD pipeline logs for any `npm install` or `npm update` that ran between 2026-03-31 00:21 and 03:40 UTC. If found, assume host compromise — rotate all credentials accessible from that environment. Hunt for outbound connections to `sfrclak[.]com` on port 8000 in proxy and DNS logs. (T1195.002 — Supply Chain Compromise: Compromise Software Supply Chain)

### 3.2 TeamPCP Multi-Stage Supply Chain Campaign — First Confirmed Victim, Cloud Enumeration Documented

**Source:** [Unit42](https://unit42.paloaltonetworks.com/teampcp-supply-chain-attacks/), [SANS ISC](https://isc.sans.edu/diary/rss/32856), [Recorded Future News](https://therecord.media/mercor-confirms-security-incident-tied-to-litellm)

TeamPCP's campaign against security infrastructure escalated with two significant developments. First, AI recruiting startup Mercor publicly confirmed it was breached as a direct consequence of the LiteLLM supply chain compromise, becoming the first organization to officially acknowledge victimization. LAPSUS$ claimed exfiltration of approximately 4TB of Mercor data, including 939GB of source code, a 211GB user database, and 3TB of video interviews and identity verification documents. Initial access was reportedly via a compromised Tailscale VPN credential.

Second, Wiz's Cloud Incident Response Team published detailed documentation of TeamPCP's post-compromise operations: the group uses TruffleHog to validate stolen credentials, transitions to discovery within 24 hours, and enumerates IAM roles, EC2 instances, Lambda functions, RDS databases, S3 buckets, and ECS clusters. They used conspicuous resource names including "pawn" and "massive-exfil" in compromised environments.

The broader campaign compromised Trivy, KICS, LiteLLM, and the Telnyx Python SDK, injecting CanisterWorm — a malware family featuring decentralised C2 and wiper components — into GitHub Actions and PyPI registries. An estimated 300GB of data and 500,000 credentials have been exfiltrated from approximately 500,000 machines.

#### Indicators of Compromise
```
Malware family: CanisterWorm
Compromised packages: litellm v1.82.7, litellm v1.82.8
Affected tools: Trivy, KICS, Telnyx Python SDK
CVE: CVE-2025-55182
```

> **SOC Action:** Organizations that used LiteLLM v1.82.7 or v1.82.8 should treat the Mercor disclosure as confirmation that credential exploitation is actively underway. Rotate all VPN credentials, cloud access tokens, SSH keys, and Kubernetes secrets accessible from compromised environments. Audit GitHub Actions workflows for unauthorised modifications. Query cloud audit logs for enumeration patterns targeting IAM, EC2, Lambda, RDS, S3, and ECS resources. Search for TruffleHog execution in endpoint telemetry. (T1195.001 — Supply Chain Compromise: Compromise Software Dependencies and Development Tools)

### 3.3 Chrome Zero-Day CVE-2026-5281 — Fourth Actively Exploited Chrome Vulnerability in 2026

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/google-fixes-fourth-chrome-zero-day-exploited-in-attacks-in-2026/)

Google released an emergency update to fix CVE-2026-5281, a use-after-free vulnerability in Dawn, the cross-platform implementation of the WebGPU standard used by Chromium. The flaw allows attackers to trigger browser crashes, data corruption, or code execution. Google confirmed active exploitation in the wild but withheld technical details pending user adoption of the patch.

This is the fourth actively exploited Chrome zero-day patched in 2026, following CVE-2026-2441 (CSSFontFeatureValuesMap iterator invalidation), CVE-2026-3909 (Skia OOB write), and CVE-2026-3910 (V8 inappropriate implementation).

Patched versions: Windows/macOS 146.0.7680.177/.178, Linux 146.0.7680.177.

> **SOC Action:** Verify all managed Chrome and Chromium-based browsers are updated to version 146.0.7680.177 or later. Query endpoint management for browser versions and flag any instances below the patched version. Block or alert on WebGPU-related crash reports in browser telemetry as potential exploitation indicators. (T1203 — Exploitation for Client Execution)

### 3.4 NoVoice Android Malware — 2.3 Million Google Play Infections with Persistent Rootkit

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/novoice-android-malware-on-google-play-infected-23-million-devices/)

McAfee researchers discovered NoVoice, a new Android malware family hidden in over 50 Google Play apps collectively downloaded 2.3 million times. The malware uses steganography to conceal an encrypted payload inside a PNG file, exploits unpatched Android vulnerabilities from 2016–2021 for root access, and replaces system libraries with hooked wrappers to intercept system calls. McAfee observed 22 exploits including use-after-free kernel bugs and Mali GPU driver flaws.

After rooting, NoVoice establishes persistence via recovery scripts, system crash handler replacement, and fallback payloads on the system partition — surviving factory resets. A watchdog daemon runs every 60 seconds to verify rootkit integrity. The primary post-exploitation target is WhatsApp session data, including encryption databases and Signal protocol keys.

The malware shares similarities with the Triada Android trojan but has not been attributed to a specific threat actor.

#### Indicators of Compromise
```
Package namespace: com.facebook.utils (abused)
Payload: enc.apk (hidden via steganography in PNG)
Extracted: h.apk
C2 polling: 60-second interval
```

> **SOC Action:** Mobile device management teams should verify all managed Android devices are patched to at least the latest available security patch level. Audit managed device application lists for apps removed from Google Play in the past 48 hours. On BYOD networks, consider blocking connections from Android devices running security patch levels older than January 2022 to sensitive resources. Monitor for anomalous WhatsApp data exfiltration patterns. (T1398 — Modify OS Kernel or Boot Partition)

### 3.5 Apple Backports DarkSword Patches to iOS 18 — Rare Policy Shift

**Source:** [Wired Security](https://www.wired.com/story/apple-will-push-out-rare-backported-patches-to-protect-ios-18-users-from-darksword-hacking-tool/)

Apple announced it will backport security patches to iOS 18 to protect users from DarkSword, a sophisticated hacking tool capable of silently compromising iPhones via infected websites. This marks a rare departure from Apple's standard policy of requiring users to upgrade to the latest iOS version. iOS 26 users were already protected; the backport targets the estimated quarter of iPhone users who remain on iOS 18, many due to the unpopularity of iOS 26's interface changes.

DarkSword has been used by various hacker groups for espionage and cryptocurrency theft in Malaysia, Saudi Arabia, Turkey, and Ukraine. The exploit code was left in a reusable state on compromised legitimate websites with developer comments, making it easy to repurpose.

> **SOC Action:** Verify all managed iOS devices are updated. For organisations with BYOD policies, notify users on iOS 18 that critical security patches are now available without requiring an iOS 26 upgrade. Monitor web proxy logs for connections to known DarkSword watering-hole domains. (T1189 — Drive-by Compromise)

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Supply chain attacks becoming more prevalent | TeamPCP's campaign against Trivy/KICS/LiteLLM; DPRK-attributed axios npm compromise via UNC1069 |
| 🔴 **CRITICAL** | State-nexus actors targeting government and critical infrastructure | Operation TrueChaos (Southeast Asian government targets); Cisco breach; CISA Citrix NetScaler directive; Dutch Finance Ministry breach |
| 🟠 **HIGH** | Increased ransomware activity targeting multiple sectors | ShinyHunters (Cisco), Everest (Nissan), Payoutsking (Del Monte Foods, UFP Technologies), Qilin (Seeing Machines, Service Star Freightways, SERAM SpA) |
| 🟠 **HIGH** | Phishing and credential access techniques proliferating across sectors | LinkedIn phishing campaigns; EvilTokens device code phishing-as-a-service; Augmented Marauder Casbaneiro campaigns |
| 🟡 **MEDIUM** | Phishing remains a common TTP across various campaigns | Correlation across 9 reports linking phishing to ransomware delivery, supply chain compromise, and credential harvesting |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **Qilin** (34 reports) — Most active ransomware operator in the pipeline; RaaS operation targeting manufacturing, logistics, and technology sectors globally
- **TeamPCP** (23 reports) — Supply chain threat actor behind CanisterWorm; compromised Trivy, KICS, LiteLLM, and Telnyx SDK; first confirmed victim (Mercor) disclosed
- **Nightspire** (21 reports) — Prolific ransomware group with 8+ new victim postings in the reporting period across multiple sectors
- **Akira** (16 reports) — Continued high-volume ransomware operations targeting insurance (Starr Insurance), manufacturing (Swagelok), and professional services
- **Hive** (13 reports) — Persistent ransomware operation maintaining steady victim posting cadence
- **Handala** (12 reports) — Pro-Iran hacktivist group linked to data wiping attacks against US and Albanian targets
- **ShinyHunters** (10 reports) — Data breach specialist claiming Cisco compromise with 3M+ Salesforce records

### Malware Families

- **Akira ransomware** (12 reports) — Primary ransomware payload associated with the Akira threat actor
- **CanisterWorm** (6 reports) — TeamPCP's bespoke malware with decentralised C2 and wiper capabilities, deployed via supply chain compromise
- **DragonForce ransomware** (6 reports) — Active RaaS operation with new victim postings including financial services targets
- **DarkSword** (4 reports) — iOS exploitation framework prompting rare Apple backported patches; used for espionage and cryptocurrency theft
- **NoVoice** (1 report) — Newly discovered Android rootkit malware infecting 2.3M devices via Google Play; targets WhatsApp data
- **CrystalX** (1 report) — New MaaS offering combining spyware, stealer, keylogger, clipper, and RAT capabilities; distributed via Telegram

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| Microsoft | 29 | [link](https://msrc.microsoft.com) | CVE advisories for OpenSC, brace-expansion, Handlebars.js, and other components |
| RansomLock | 29 | [link](https://www.ransomlook.io) | Ransomware victim tracking across Akira, Qilin, Nightspire, DragonForce, ShinyHunters, Everest, Worldleaks |
| BleepingComputer | 11 | [link](https://www.bleepingcomputer.com) | Primary coverage of Chrome zero-day, NoVoice malware, GIGABYTE vulnerability |
| RecordedFutures | 6 | [link](https://therecord.media) | Axios DPRK attribution, Mercor breach confirmation, Romania cyberattacks |
| AlienVault | 5 | [link](https://otx.alienvault.com) | TeamPCP analysis, Casbaneiro campaigns, CrystalX MaaS, axios advisory |
| SANS | 3 | [link](https://isc.sans.edu) | TeamPCP campaign Update 005 with post-compromise cloud enumeration details |
| Unit42 | 2 | [link](https://unit42.paloaltonetworks.com) | Axios supply chain deep-dive and TeamPCP comprehensive analysis |
| Wired Security | 2 | [link](https://www.wired.com) | Apple DarkSword backported patches coverage |
| Schneier | 1 | [link](https://www.schneier.com) | Security commentary |
| CertEU | 1 | [link](https://cert.europa.eu) | March 2026 Cyber Brief covering EU-wide threat landscape |
| RedCanary | 1 | [link](https://redcanary.com) | Detection engineering content |
| Elastic Security Labs | 1 | [link](https://www.elastic.co/security-labs) | Axios supply chain detection signatures |
| BellingCat | 1 | [link](https://www.bellingcat.com) | OSINT investigation |
| HaveIBeenPwned | 1 | [link](https://haveibeenpwned.com) | Breach notification data |
| Unknown | 7 | — | Telegram-sourced vulnerability disclosures (CVE-2026-4747, CVE-2026-34714) and other unattributed reports |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Audit all Node.js projects and CI/CD pipelines for axios versions 1.14.1 or 0.30.4 and the `plain-crypto-js` dependency. If either is found, treat the host as compromised — rotate all accessible credentials and hunt for C2 traffic to `sfrclak[.]com:8000`. Organisations that used LiteLLM v1.82.7 or v1.82.8 must rotate VPN credentials, cloud tokens, SSH keys, and Kubernetes secrets immediately given confirmed exploitation at Mercor.

- 🔴 **IMMEDIATE:** Push Chrome updates to all managed endpoints to version 146.0.7680.177 or later to remediate actively exploited zero-day CVE-2026-5281 in Dawn/WebGPU. Notify iOS 18 users that backported DarkSword patches are now available without requiring upgrade to iOS 26.

- 🟠 **SHORT-TERM:** Audit GitHub Actions workflows and PyPI dependencies for signs of TeamPCP compromise. Search cloud audit logs (AWS CloudTrail, Azure Activity Log) for enumeration patterns across IAM, EC2, Lambda, RDS, S3, and ECS. Flag any TruffleHog execution in endpoint telemetry as potentially related to TeamPCP credential validation.

- 🟠 **SHORT-TERM:** Review GIGABYTE Control Center versions across the fleet — any system running version 25.07.21.01 or earlier with the 'pairing' feature enabled is remotely exploitable (CVE-2026-4415, CVSS 9.2). Upgrade to version 25.12.10.01 immediately.

- 🟡 **AWARENESS:** CERT-EU's March 2026 Cyber Brief documents EU sanctions against Chinese and Iranian entities for cyberattacks, the dismantling of SocksEscort proxy service, and exposure of FancyBear cyberespionage infrastructure. Romania reports 10,000+ daily cyberattack attempts against government institutions, predominantly linked to Russia. These geopolitical developments increase the probability of retaliatory cyber operations against Western targets.

- 🟢 **STRATEGIC:** The convergence of two major supply chain attacks (axios/UNC1069 and TeamPCP) within the same week underscores the need to harden software supply chain controls. Evaluate adoption of npm provenance checks, lock file integrity verification, and mandatory code signing for internal packages. Conduct tabletop exercises around supply chain compromise scenarios involving trusted security tooling.

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 100 reports processed across 3 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
