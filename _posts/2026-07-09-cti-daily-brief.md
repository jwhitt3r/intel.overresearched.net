---
layout: post
title:  "CTI Daily Brief: 2026-07-09 - Gitea Docker Auth Bypass Actively Exploited, CISA Adds 2 to KEV, Injective SDK npm Supply-Chain Compromise"
date:   2026-07-10 20:06:27 +0000
description: "84 reports across 8 sources: three critical items dominate — active exploitation of a Gitea Docker auth-bypass, a Zimbra Classic Web Client XSS patch advisory, and an npm supply-chain attack on the Injective Labs SDK stealing crypto wallet keys. CISA added two file-upload CVEs (iCagenda, Balbooa Forms) to the KEV catalogue. Ransomware pressure remains dominated by The Gentlemen, Lockbit5, Deadlock, Qilin and Gunra, while a China/India-nexus espionage convergence on Pakistani law enforcement and a Progress ShareFile 'credible threat' advisory round out the operational picture."
category: daily
tags: [cti, daily-brief, the-gentlemen, lockbit5, qilin, deadlock, cve-2026-48939, cve-2026-56291, injective-sdk, gitea, zimbra, sharefile]
classification: TLP:CLEAR
reporting_period: "2026-07-09"
generated: "2026-07-10"
draft: true
severity: critical
report_count: 84
sources:
  - BleepingComputer
  - RansomLock
  - AlienVault
  - SANS
  - Microsoft
  - RecordedFutures
  - CISA
  - Schneier
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-07-09 (24h) | TLP:CLEAR | 2026-07-10 |

## 1. Executive Summary

The pipeline processed 84 reports across 8 sources in the last 24 hours, with 3 rated critical, 58 high, 15 medium and 8 informational. Three items require immediate action: active in-the-wild exploitation of a Gitea Docker image authentication bypass permitting arbitrary user impersonation, an npm supply-chain compromise of the Injective Labs SDK exfiltrating cryptocurrency wallet private keys and mnemonic seed phrases, and Zimbra's advisory to patch a critical XSS flaw in the Classic Web Client. CISA added two file-upload vulnerabilities (CVE-2026-48939 in iCagenda and CVE-2026-56291 in Balbooa Forms) to the KEV catalogue with confirmed exploitation. Progress Software emailed ShareFile customers running Storage Zone Controllers to shut down servers immediately over a "credible external security threat." Ransomware leak-site volume was dominated by The Gentlemen (14 new victims), Lockbit5 (11), Deadlock (12), Qilin (4) and Gunra (3), while AlienVault reported a China/India-nexus espionage convergence on Pakistan's Balochistan Police using PlugX, ShadowPad, Cobalt Strike, AsyncRAT and Remcos.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 3 | Gitea Docker auth-bypass exploited in the wild; Injective SDK npm wallet stealer; Zimbra Classic Web Client XSS |
| 🟠 **HIGH** | 58 | The Gentlemen, Lockbit5, Deadlock, Qilin, Gunra leak-site posts; CISA KEV additions; Progress ShareFile advisory; Pakistan espionage convergence |
| 🟡 **MEDIUM** | 15 | Routine vendor advisories; secondary correlation coverage |
| 🔵 **INFO** | 8 | Ecosystem/tooling posts, non-actionable summaries |

## 3. Priority Intelligence Items

### 3.1 Active Exploitation — Gitea Docker Image Authentication Bypass

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/hackers-exploit-critical-auth-bypass-in-gitea-docker-image/)

Attackers are actively exploiting a critical authentication-bypass flaw in the official Docker image for the Gitea self-hosted Git service. The vulnerability permits impersonation of any user, including administrators, granting unauthorized access to source repositories and potentially the underlying container host. Because Gitea is widely used for internal source-code hosting, exploitation carries a direct source-code theft and CI/CD pipeline poisoning risk. MITRE mapping in the report: T1078 (Valid Accounts) and T1552.001 (Credentials in Files / Impersonation).

Affected: Organisations running the official Gitea Docker image, especially those exposing the Gitea web UI or API to untrusted networks.

> **SOC Action:** Inventory all Gitea Docker deployments and confirm they are pulled from a patched tag; block external exposure of Gitea endpoints at the edge until patched; audit `giteaadmin`, `admin` and service-account login events in Gitea access logs for the past 14 days; review recent repository writes, webhook creations, and SSH key additions on any Gitea instance for anomalous author identities.

### 3.2 Critical — Zimbra Classic Web Client XSS

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/zimbra-urges-customers-to-patch-critical-web-client-xss-flaw/)

Zimbra's security team has urged customers to patch a critical cross-site scripting vulnerability in the Classic Web Client used to access Zimbra Collaboration. Successful exploitation permits arbitrary script execution in the victim's browser session, which historically has been chained to mailbox theft, session hijacking and OAuth token exfiltration in Zimbra-targeting campaigns. MITRE mapping: T1204 (User Execution) and T1550 (Use Alternate Authentication Material).

Affected: Zimbra Collaboration deployments serving the Classic Web Client.

> **SOC Action:** Apply the Zimbra patch to all Collaboration nodes in the next maintenance window and treat as an emergency change on internet-exposed instances; if patching is not possible within 72h, disable the Classic Web Client and force users to the Modern Web Client; hunt mailbox rule creations, forwarding rules and OAuth grants from the last 30 days for anomalies.

### 3.3 Critical — Injective Labs SDK npm Supply-Chain Compromise (Wallet Stealer)

**Sources:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/injective-sdk-on-npm-infected-with-cryptocurrency-wallet-stealer/), [AlienVault (OTX)](https://otx.alienvault.com/pulse/6a501da43fb3cb230cc9a9b9)

Attackers compromised the Injective Labs SDK GitHub repository and published a malicious `@injectivelabs/sdk-ts` npm package that harvests cryptocurrency wallet private keys and mnemonic seed phrases from developer workstations and downstream applications. The compromise chain includes trusted-repository publishing that bypasses conventional dependency-trust checks, mirroring the wider pattern of the Fake Paysafe / Skrill SDK typosquats reported earlier in the week. MITRE mapping: T1195.002 (Compromise Software Supply Chain), T1071 (Application Layer Protocol), T1566 (Phishing).

Affected: Any Web3 / cryptocurrency project or developer with `@injectivelabs/sdk-ts` in a `package.json` or lockfile after the compromise window.

> **SOC Action:** Grep all monorepos and CI caches for `@injectivelabs/sdk-ts`, pin to a known-good version prior to the compromise, purge npm caches and node_modules on developer laptops that installed the package, and rotate every mnemonic or private key that was ever loaded on those hosts; add egress alerting for the domains and TLS fingerprints identified in the vendor IOCs.

### 3.4 CISA KEV — Two Actively Exploited File-Upload CVEs Added

**Source:** [CISA](https://www.cisa.gov/news-events/alerts/2026/07/10/cisa-adds-two-known-exploited-vulnerabilities-catalog)

CISA added two vulnerabilities to the Known Exploited Vulnerabilities Catalogue based on confirmed active exploitation:

- **CVE-2026-48939** — iCagenda Unrestricted Upload of File with Dangerous Type
- **CVE-2026-56291** — Balbooa Forms Unrestricted Upload of File with Dangerous Type

Both are Joomla-extension file-upload flaws that permit remote code execution via unrestricted file type uploads. BOD 26-04 obliges FCEB agencies to remediate promptly; commercial defenders should treat these as the same tier of urgency for any internet-exposed Joomla estate.

> **SOC Action:** Enumerate Joomla instances running iCagenda or Balbooa Forms extensions across all environments; if patched versions are not yet available, disable the extensions and block file-upload endpoints at WAF; hunt for recently created PHP files under Joomla `tmp/`, `media/` and `images/` directories with mtime in the last 45 days; correlate with anomalous POST requests to extension endpoints in web-server logs.

### 3.5 Progress ShareFile — Emergency "Credible Threat" Advisory

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/progress-urges-sharefile-customers-to-shut-down-servers-over-credible-threat/)

Progress Software is emailing ShareFile customers who use on-premises Storage Zone Controllers to shut down affected servers immediately, citing a "credible external security threat" against the file-sharing platform. Progress has a recent history (MOVEit, WhatsUp Gold) of pre-CVE disclosures that preceded mass-exploitation events, so the advisory should be treated as a probable imminent-exploitation warning rather than a routine notice.

Affected: On-premises ShareFile deployments using Storage Zone Controllers.

> **SOC Action:** Shut down Storage Zone Controllers per Progress guidance until a patched version is available; capture forensic memory and disk images before shutdown of any internet-exposed controller for later triage; hunt for anomalous outbound TLS to unfamiliar destinations and for `w3wp.exe`/`csvc.exe` spawning `cmd.exe`, `powershell.exe` or `net.exe` in the last 30 days.

### 3.6 China / India-Nexus Espionage Convergence — Pakistan Balochistan Police

**Source:** [AlienVault (CyberArmor / SentinelLabs republication)](https://otx.alienvault.com/pulse/6a501da43fb3cb230cc9a9b9)

Two separate cyberespionage actors — attributed with hedged confidence to China-nexus and India-nexus groups — independently maintained sustained intrusions into Pakistan's Balochistan Police between February 2024 and April 2026. The suspected China-nexus actor weaponised the police Complaint Management System web application by deploying custom implants disguised as portal updates, hitting both police personnel and citizens interacting with the portal. Deployed tooling includes PlugX (S0013), ShadowPad (S0596), Cobalt Strike (S0154), AsyncRAT, DestroyRAT, POISONPLUG.SHADOW and Remcos. Intrusion set TAG-179 is referenced. MITRE mapping includes T1190, T1566, T1071.001, T1204.002, T1505.003, T1573.

Attribution note: The source hedges attribution as "suspected" for both nexuses; this brief preserves that hedging and does not upgrade it to confirmed.

#### Indicators of Compromise

```
Hostname:   cms.balochistanpolice.gov[.]pk
URL:        hxxp[:]//cms.balochistanpolice.gov[.]pk/client%20scripts/
URL:        hxxp[:]//cms.balochistanpolice.gov[.]pk/client%20scripts/cms_plugin.exe
IPv4:       142.171.183[.]8
IPv4:       172.111.233[.]12 / .26 / .36 / .96 / .105
IPv4:       172.94.9[.]19 / .43 / .49
IPv4:       193.42.25[.]65
IPv4:       41.216.188[.]140
IPv4:       45.125.32[.]218
IPv4:       45.74.6[.]17
IPv4:       89.31.121[.]220
SHA-256:    1fd8ba64a687247466fa6e8b7d194154439ef527746fdb8c18b3c3d65b6d2390
SHA-256:    71fa6a00314701fef5c6f32c17e1438063d05616198ac9a12004aeab957e11ae
SHA-256:    7ea0930a332788c2e88e5822e4908d77cdcaad57e0e97401ed8fe4b117fdfc95
SHA-256:    9fb6f4c55e5198739123264f8007cf6e22b3821af97a00a471bd54b30991ecd0
```

> **SOC Action:** For any organisation with a Pakistani operating footprint, block the listed IPv4s and hostname at the perimeter and search EDR telemetry for the SHA-256 hashes across the last 24 months; for defenders more broadly, add the C2 IPs to threat-intel enrichment and hunt for PlugX/ShadowPad DLL side-loading patterns (T1574.002) on any Windows host that has visited external Pakistani government infrastructure.

### 3.7 Vercel-Hosted LogMeIn RAT Delivery Chain

**Source:** [AlienVault (CyberArmor)](https://www.cyberarmor.tech/blog/threat-insight-cybercriminals-abusing-vercel-to-deliver-remote-access-malware)

CyberArmor tracked 28+ distinct phishing campaigns delivering a LogMeIn-based remote-access implant hosted on legitimate Vercel deployments, impacting more than 1,271 users over two months. Lures impersonate DHL waybills, unpaid invoices and Adobe PDF viewers; the executable payload silently installs LogMeIn and hands persistent remote control to the attacker. MITRE mapping: T1566.002, T1553.005, T1204.002, T1547.001, T1071.001, T1219.

#### Indicators of Compromise

```
SHA-256: 0a1a85a026b6d477f59bc3d965b07d0d06e6ff2d34381aff79ea71c38fed802b
MD5:     f3f8379ce6e0b8f80faf259db2443f13
MD5:     e230bf859e582fe95df0b203892048df
MD5:     f782c936249b9786cc7fac580da3ae0f
MD5:     322a92b443faefe48fce629e8947e4e2
Domain:  unpaidinvoiceremitaath.vercel[.]app
Domain:  waybill-deliveryticket.vercel[.]app
Domain:  invstatement2025.vercel[.]app
Domain:  invstatement.vercel[.]app
Domain:  windowscorps.vercel[.]app
Domain:  invoices-attachedpdf.vercel[.]app
Domain:  dhl-delivery-report.vercel[.]app
Domain:  dhl-shipment-detail.vercel[.]app
Domain:  dhl-shipment-document.vercel[.]app
Domain:  express-delivery-note.vercel[.]app
Domain:  invoice-statement-overdue.vercel[.]app
Domain:  docreview-rho.vercel[.]app
Domain:  docsignstatements.vercel[.]app
Domain:  invoices-overdues100.vercel[.]app
Domain:  waybill-directory-express.vercel[.]app
Domain:  statment-inv.vercel[.]app
Domain:  shipment-docspdf.surge[.]sh
```

> **SOC Action:** Block `*.vercel[.]app` subdomain patterns matching invoice/DHL/statement lures at the mail gateway and web proxy where policy permits, and add the listed hashes to EDR blocklists; hunt EDR for `LogMeIn`, `LMI_Rescue` service creations and outbound TLS to `*.logmein.com` from hosts that have no business-justified LogMeIn use.

### 3.8 Albiriox Android Banking RAT — UniCredit Impersonation via Telegram

**Source:** [AlienVault (D3Lab)](https://www.d3lab.net/fake-banking-rewards-telegram-delivery-and-albiriox-anatomy-of-an-android-malware-campaign/)

D3Lab detected a newly registered domain `unicredit-tme[.]shop` impersonating UniCredit and offering a fake $100 reward. Victims are funnelled through a Telegram bot into installing a malicious APK that acts as a dropper for **Albiriox**, an Android banking trojan with accessibility abuse, overlay attacks, SMS interception and TCP C2. The C2 endpoint `179.43.159[.]210:5555` matches public Albiriox panel screenshots. MITRE mapping: T1566, T1204, T1608. Telegram delivery channel referenced but not linked per policy.

#### Indicators of Compromise

```
Domain: unicredit-tme[.]shop
C2:     179.43.159[.]210:5555 (primary)
C2:     179.43.159[.]210:5552 (auxiliary)
SHA-256: 146c62f408b6d7db4c832a6b5f7bdacb1cff2c69121b9b2f7e80646c37910abd
SHA-256: 1e99972b1d84b131eb55a6b49f64871c5c0c6a1bb2a099a84313001b69dc53e8
SHA-256: 206fdbe992b44ebd6720c49c79a5da3bdcb48d0d799a0ff3458323caac3cc490
SHA-256: 4b9a95ebf5e471d11443fa2f19b75595fc1fcf6be234024cc1d4a2255068c19b
SHA-256: e0fc365c042e708c8d04b5431238958586194cc4a8cbe069411a26dcfcc4e9b6
SHA-256: efc81267da3ad48cc779e9aed8f9232504ed7c85abf3958a87ba2ae68056ae23
SHA-256: fb43c4191c40f159167a98a4ac20bf23ae66a8ec27a919f703e953933e22a266
```

> **SOC Action:** For Italian-market retail-banking defenders, sinkhole `unicredit-tme[.]shop`, share the C2 IP and hashes with fraud-and-brand-protection teams, and issue customer-facing warnings on the Telegram-bot lure pattern; MDM policy should reject sideloaded APKs on managed devices; add MobileIron/Intune queries for accessibility-service consent events on unmanaged BYOD estate.

### 3.9 Ryuk / Blackcat Prosecutions — Law-Enforcement Update

**Source:** [The Record (Recorded Future News)](https://therecord.media/ryuk-operator-pleads-guilty-alphv-conspirator-sentenced)

An Armenian national extradited from Ukraine (Karen Serobovich Vardanyan, 34) pleaded guilty in Oregon federal court to conspiracy and computer fraud for Ryuk deployments from late 2019. Angelo Martino, a Florida-based former DigitalMint ransomware negotiator, was sentenced to 70 months for helping BlackCat/AlphV extort victims by leaking his employer's negotiating positions. Two additional co-conspirators (Ryan Goldberg, Kevin Martin) received four-year sentences earlier this year. DigitalMint has moved all negotiations onto auditable cloud platforms and put a co-founder in personal oversight. Historical relevance rather than active TTP change, but the negotiator-insider vector is a persistent third-party risk vector worth briefing to incident-response counsel.

> **SOC Action:** Review contractual and technical controls around any third-party ransomware negotiator you might engage; require negotiations over auditable channels with call recording, ban unaudited direct-communication channels with attackers, and treat negotiator selection as a due-diligence exercise on the same footing as breach counsel.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Phishing remains a prevalent tactic among ransomware groups targeting financial services and cryptocurrency sectors, raising data-breach risk. | "Not-so-anonymous telemetry: The @injectivelabs/sdk-ts backdoor"; "Injective SDK on npm infected with cryptocurrency wallet stealer" |
| 🔴 **CRITICAL** | Ransomware targeting critical infrastructure sectors. | "OpenPLC v3"; "Schneider Electric Easergy MiCOM Px40 Series" (batch 220) |
| 🟠 **HIGH** | The Gentlemen ransomware group is actively targeting multiple sectors with consistent use of Tox1 and phishing techniques. | "Lopes Law By the gentlemen"; "Carita By the gentlemen" |
| 🟠 **HIGH** | Lockbit5 ransomware operations are expanding across sectors, particularly education and engineering, using similar TTPs. | "hotel-bourse.com By lockbit5"; "magna.com.do By lockbit5" |
| 🟠 **HIGH** | Sophisticated phishing campaigns using AI and multi-ecosystem strategies. | "New Forg365 phishing platform uses AI to target Microsoft 365 accounts"; "Coordinated npm and PyPI Campaign Typosquats Popular Secure Payment Apps" |
| 🟠 **HIGH** | Increased exploitation of public-facing applications and cloud vulnerabilities. | "Wiz in the Verizon DBIR"; "Continues building ORB networks using new malware" |

Latest batch (222, 10 July 2026) landscape summary: "significant increase in ransomware activities…Qilin and Gunra employing double-extortion models…AI evasion methods such as 'comment stuffing'…geopolitical tensions manifesting in the cyber domain with China-nexus and India-nexus actors targeting Pakistani law enforcement…critical vulnerabilities in widely used software platforms such as Gitea Docker images being actively exploited."

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **The Gentlemen** (110 reports) — active RaaS crew posting 14 new leak-site victims today across legal, retail, medical and manufacturing sectors; consistent Tox1 negotiation channel and phishing initial access
- **Qilin** (88 reports) — global double-extortion operator hitting real-estate, hospitality and BPO sectors; Tor-based infrastructure with intermittent uptime
- **Deadlock** (66 reports) — 12 new leak-site victims today concentrated in engineering and public-sector; heavy European footprint
- **Lockbit5** (36 reports) — 11 new leak-site victims today across education and hospitality; expansion continues into engineering (batch-220 trend)
- **DragonForce** (26 reports) — persistent presence, no new tier-1 activity today
- **Akira** (23 reports) — one new victim today (Vandalia Rental)
- **ShinyHunters / Shinyhunters** (20/19 reports) — case-variant duplication in the entity table; still recurring
- **Nova** (17 reports) — one new victim (Hynet)
- **Stormous** (16 reports) — no new tier-1 activity today

### Malware Families

- **RansomLook** (166 reports) — pipeline aggregator source label rather than an executable family
- **Tox1** (74 reports) — negotiation-channel primitive used by The Gentlemen and others
- **Other1** / **Tox** (46 / 45 reports) — pipeline-tag artefacts alongside Tox1
- **Qilin ransomware** (12), **Akira ransomware** (12), **Deadlock** (12), **The Gentlemen Ransomware** (12) — executable payload counters mirroring leak-site counts
- **Anubis ransomware** (11) — active in prior week's batches
- **Albiriox** — Android banking trojan (D3Lab / this brief)
- **PlugX, ShadowPad, Cobalt Strike, AsyncRAT, DestroyRAT, Remcos, POISONPLUG.SHADOW** — Pakistan espionage campaign (this brief)

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| RansomLock | 59 | [link](https://www.ransomlook.io) | Ransomware leak-site aggregator; dominant volume driver — see Section 5 |
| BleepingComputer | 10 | [link](https://www.bleepingcomputer.com) | Primary source of all three critical items (Gitea, Zimbra, Injective SDK) and Progress ShareFile advisory |
| AlienVault | 4 | [link](https://otx.alienvault.com) | Pakistan espionage, Vercel RAT and Albiriox banking-trojan pulses |
| SANS | 3 | [link](https://isc.sans.edu) | Routine ISC diary coverage |
| Microsoft | 3 | [link](https://msrc.microsoft.com) | CVE-2026-56288 GNU patch NULL-deref; CVE-2026-59818 etcd cert-revocation bypass |
| RecordedFutures | 3 | [link](https://therecord.media) | Ryuk / BlackCat prosecutions; nation-state coverage |
| CISA | 1 | [link](https://www.cisa.gov/news-events/cybersecurity-advisories) | KEV additions CVE-2026-48939 (iCagenda), CVE-2026-56291 (Balbooa Forms) |
| Schneier | 1 | [link](https://www.schneier.com/blog/) | Commentary post |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Patch or take offline every Gitea Docker deployment and every on-premises ShareFile Storage Zone Controller today; both have concrete evidence of active or imminent exploitation (Section 3.1, 3.5).
- 🔴 **IMMEDIATE:** Grep every codebase and CI cache for `@injectivelabs/sdk-ts`, pin to a known-good version, and rotate any wallet mnemonic or private key that transited an affected developer host (Section 3.3).
- 🟠 **SHORT-TERM:** Apply the Zimbra Classic Web Client patch on all Collaboration nodes within the next 72 hours; disable the Classic client on internet-facing instances until patched (Section 3.2).
- 🟠 **SHORT-TERM:** Enumerate Joomla estate for iCagenda and Balbooa Forms; patch, disable or WAF-block per CVE-2026-48939 and CVE-2026-56291; align to BOD 26-04 timelines even in non-FCEB environments (Section 3.4).
- 🟡 **AWARENESS:** Add the Vercel-hosted phishing domains, Albiriox C2 and Pakistan-espionage indicators to enrichment feeds; brief mail-gateway and mobile-security teams on the invoice / DHL / banking-reward lure patterns (Sections 3.6, 3.7, 3.8).
- 🟢 **STRATEGIC:** Revisit third-party ransomware-negotiator controls in light of the Martino / DigitalMint prosecution — mandate auditable-channel negotiations, call recording, and due-diligence on negotiator selection (Section 3.9).

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 84 reports processed across 4 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
