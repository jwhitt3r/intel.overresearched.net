---
layout: post
title:  "CTI Daily Brief: 2026-06-10 — CISA BOD 26-04 mandates 3-day KEV patching; Langflow CVE-2026-5027 exploited in the wild; ShinyHunters claims University of Nottingham PeopleSoft breach"
date:   2026-06-11 20:15:00 +0000
description: "CISA Binding Operational Directive 26-04 shortens federal KEV-patching timelines to three days. Critical hard-coded credentials disclosed in Yarbo IoT robots (CVE-2026-10557, CVSS 9.8). Path traversal CVE-2026-5027 in AI dev platform Langflow exploited in active attacks. ShinyHunters leaks 454,635 University of Nottingham records via Oracle PeopleSoft compromise. Khmer Shadow espionage hits Cambodian government with NIGHTFORGE/Havoc Demon. Russian national linked to Void Blizzard appears in U.S. court. Miasma supply-chain worm source code leaked on GitHub."
category: daily
tags: [cti, daily-brief, shinyhunters, qilin, dragonforce, void-blizzard, khmer-shadow, miasma, langflow, cve-2026-5027, cve-2026-10557]
classification: TLP:CLEAR
reporting_period: "2026-06-10"
generated: "2026-06-11"
draft: true
severity: critical
report_count: 91
sources:
  - BleepingComputer
  - CISA
  - AlienVault
  - RecordedFutures
  - Wired Security
  - RansomLook
  - HaveIBeenPwned
  - Datadog
  - Unit42
  - SANS
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-06-10 (24h) | TLP:CLEAR | 2026-06-11 |

## 1. Executive Summary

The pipeline processed 91 reports across 15 sources in the last 24 hours, with two critical-severity items and 53 high-severity items dominated by ransomware victim disclosures from Qilin, DragonForce, M3rx and ShinyHunters. The defining story of the cycle is CISA's release of **Binding Operational Directive 26-04**, which compresses federal KEV-listed vulnerability remediation to as little as **three days** and supersedes BOD 19-02 and BOD 22-01. In parallel, VulnCheck confirmed **in-the-wild exploitation of CVE-2026-5027** — a path traversal flaw in the AI development platform Langflow — against roughly 7,000 internet-exposed instances. CISA also issued ICS Advisory ICSA-26-162-01 for **Yarbo robots**, disclosing hard-coded MQTT credentials (CVE-2026-10557, CVSS 9.8) granting fleet-wide command access. Headline incidents include **ShinyHunters' 454,635-record University of Nottingham breach** via an alleged Oracle PeopleSoft zero-day chain, an Acronis-disclosed **Khmer Shadow espionage campaign against Cambodian government** entities using the NIGHTFORGE loader and Havoc Demon, and a U.S. federal indictment of a Russian national linked to the **Void Blizzard** Kremlin-aligned cyberespionage group. Law enforcement also dismantled the **AudiA6 crypto-laundering service** (€380M+ moved) and seized 13 China-linked fake-consulting domains targeting U.S. clearance holders.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 2 | CISA BOD 26-04 (KEV 3-day patching); Yarbo IoT hard-coded credentials (CVE-2026-10557, CVSS 9.8) |
| 🟠 **HIGH** | 53 | Qilin/DragonForce/M3rx/ShinyHunters ransomware leak-site disclosures; Langflow CVE-2026-5027 exploited; Nottingham University breach; Khmer Shadow espionage; Void Blizzard indictment |
| 🟡 **MEDIUM** | 12 | Shinyhunters notice posts; secondary ransomware coverage |
| 🟢 **LOW** | 4 | Lower-confidence underground forum chatter |
| 🔵 **INFO** | 20 | RansomLook routine victim postings; underground forum mirror traffic |

## 3. Priority Intelligence Items

### 3.1 CISA Binding Operational Directive 26-04 — 3-Day KEV Remediation Mandate

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/cisa-tells-govt-agencies-to-patch-critical-exploited-flaws-in-3-days/), [Wired Security](https://www.wired.com/category/security)

CISA published **BOD 26-04**, replacing BOD 19-02 (2019) and BOD 22-01 (2021), and requiring U.S. Federal Civilian Executive Branch (FCEB) agencies to remediate CISA KEV-listed vulnerabilities on accelerated timelines. Prioritisation is driven by four factors: public exposure, presence in the KEV catalog, whether exploitation can be automated, and whether exploitation grants partial or full system control. The most severe combination — publicly exposed, KEV-listed, automatable, full-control — collapses the patch window to **three days**; less severe combinations get up to two weeks. The directive applies to on-premise, third-party hosted and FedRAMP/non-FedRAMP cloud environments. Agencies must update vulnerability-management policies within 60 days and be fully aligned with the new remediation timelines within 180 days. Although the directive binds only FCEB agencies, CISA expects it to set the de-facto patching cadence across the broader U.S. critical infrastructure community.

> **SOC Action:** Even outside FCEB, align internal SLAs to BOD 26-04 tiers. Automate ingestion of the CISA KEV JSON feed (`https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`) into your vulnerability management platform, tag assets meeting the four prioritisation criteria (internet-exposed + KEV + automatable + full control) and enforce 72-hour patch SLAs on that subset. Generate an executive-level KEV exposure report weekly.

### 3.2 Yarbo IoT — Hard-Coded MQTT Credentials Expose Global Robot Fleet (CVE-2026-10557, CVE-2026-7368)

**Source:** [CISA ICSA-26-162-01](https://www.cisa.gov/news-events/ics-advisories/icsa-26-162-01)

CISA issued ICS Advisory ICSA-26-162-01 covering the **Yarbo Android/iOS app and cloud MQTT infrastructure** (commercial-facilities sector, China-headquartered vendor, deployed worldwide). **CVE-2026-10557 (CVSS 3.1: 9.8 / 4.0: 9.3, CWE-798)** — the mobile app ships with hard-coded MQTT broker credentials, identical for all users and all devices and trivially extractable via APK decompilation. Those credentials provide wildcard subscription to all robot telemetry topics globally and publish capability to any robot's command topic using only the robot's serial number. **CVE-2026-7368 (CVSS 3.1: 8.1, CWE-862)** — the cloud broker enforces no per-device or per-user authorisation, meaning even after the hard-coded credentials are revoked, a single compromised credential still grants fleet-wide control. Yarbo recommends upgrading the app to v3.17.4 or later; server-side broker authorisation will be enforced automatically when the May 2026 update is deployed.

> **SOC Action:** If Yarbo devices are deployed in your environment, push v3.17.4 immediately and block app versions below 3.17.4 via MDM. For any commercial-facilities/IoT vendor, demand SBOM disclosure of embedded MQTT/AMQP credentials and require per-device certificate authentication. Treat any CWE-798 finding in vendor mobile binaries as a critical risk and add APK/IPA static-credential scanning (e.g., MobSF) to procurement gates.

### 3.3 Langflow CVE-2026-5027 — Path Traversal Actively Exploited Against AI Development Platform

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/path-traversal-flaw-in-ai-dev-platform-langflow-exploited-in-attacks/)

VulnCheck honeypots have observed in-the-wild exploitation of **CVE-2026-5027**, a high-severity path traversal flaw in the popular open-source AI development platform Langflow (149k+ GitHub stars). The flaw lives in `POST /api/v2/files`, where the `filename` multipart parameter is not sanitised against `../` traversal, allowing arbitrary file write on the host. Because **Langflow enables unauthenticated auto-login by default**, a single unauthenticated request retrieves a valid session token, after which exploitation is one-shot. Tenable disclosed the vulnerability on 27 March 2026; Snyk reported a fix in `langflow-base` 0.8.3 and Langflow 1.9.0, with version **1.10.0 now recommended**. Censys identified roughly **7,000 publicly exposed Langflow instances** historically. This is the latest in a string of Langflow vulnerabilities exploited in attacks (prior CVEs include CVE-2026-0770, CVE-2026-21445, CVE-2026-33017, and the older CVE-2025-3248, the latter linked by VulnCheck to the **Iranian threat group MuddyWater**). Mapped to MITRE T1078 and T1133.

> **SOC Action:** Inventory all Langflow deployments and upgrade to 1.10.0. Where upgrade is blocked, place Langflow behind authenticated reverse proxy and disable auto-login (`LANGFLOW_AUTO_LOGIN=False`, set `LANGFLOW_SUPERUSER`/`LANGFLOW_SUPERUSER_PASSWORD`). Hunt EDR for unexpected file writes by Langflow process under `/usr/src/app/`, `/tmp/`, or container WORKDIR paths originating from web requests, and for outbound connections from Langflow containers to unfamiliar hosts.

### 3.4 ShinyHunters — University of Nottingham Breach (454,635 Records) via Oracle PeopleSoft Compromise

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/nottingham-university-data-breach-affects-over-450-000-students/), [Have I Been Pwned](https://haveibeenpwned.com/Breach/UniversityOfNottingham), [Recorded Future News](https://therecord.media)

The University of Nottingham confirmed a cyber incident affecting its student records system; the **ShinyHunters** extortion gang claimed responsibility and posted a 40GB sample to its dark-web leak site. Stolen content reportedly spans student finance, billing and payment data, payment card details, campus portal exports, and records from the Nottingham Malaysia and China campuses. Have I Been Pwned independently assessed the breach at **454,635 unique accounts** including names, addresses, phone numbers, ethnicities, disability flags, passport numbers and academic/fee data. ShinyHunters told BleepingComputer the campaign exploits a **"gadget chain" of zero-days and older vulnerabilities in Oracle PeopleSoft**, with success dependent on individual instance configuration; the same campaign has now hit **100+ organisations** and was preceded by the recent University of Oxford CareerConnect compromise. Mapped to T1190 and T1566. This activity ties to Qilin/ShinyHunters trend ID 391 in correlation batch 167. (UK ICO and Action Fraud have been notified.)

> **SOC Action:** Inventory all Oracle PeopleSoft Campus Solutions, HCM and FIN instances (both on-prem and cloud-hosted). Validate against Oracle's most recent Critical Patch Update, force re-auth and rotate integration service-account credentials, and restrict PeopleSoft web tier to authenticated VPN/SSO only. Hunt PeopleSoft application logs for anomalous report-runner activity, mass-export jobs outside business hours and `psprt` / `n-Vision` invocations from non-administrator accounts. Treat any unverified `psadmin` or `PS` schema queries as high priority.

### 3.5 Khmer Shadow — Espionage Campaign Targeting Cambodian Government with NIGHTFORGE / Havoc Demon

**Source:** [AlienVault OTX](https://otx.alienvault.com/pulse/6a2aa0fe417d1a6f2b89eec1)

Acronis Threat Research Unit attributed two espionage campaigns against Cambodia's **Information Collection Bureau** and **Ministry of Public Works and Transport** to a cluster tracked as **Khmer Shadow**. Meeting-themed lures delivered self-extracting archives carrying **NIGHTFORGE**, a custom C++ loader using **NTDLL unhooking** and **Hell's Gate** syscall resolution to in-memory decrypt and execute a **Havoc Demon** payload. NIGHTFORGE DLL-sideloads via the legitimate VMware-signed `VMwareNamespaceCmd.exe` and establishes persistence through COM-based scheduled tasks. The actor demonstrated poor operational security by reusing identical payloads and infrastructure across both campaigns. MITRE ATT&CK coverage includes T1055.001, T1027.002, T1036.005, T1053.005, T1071.001, T1140, T1204.002, T1497.001, T1562.002, T1566.001, T1573.002 and T1574.002.

#### Indicators of Compromise

```
C2/Infra: 193.169.240[.]38
Domain:   linkednewsapi[.]top
Domain:   sharingfile[.]cloud
Host:     www.sharingfile[.]cloud
SHA-256:  15278c52f4e0d8b5bbfe288a5e826ab2ebeaedb7fb85572940cf1263e384761f
SHA-256:  1852120a84a328edd1995e633dfd2009867898a8e3f0b385e2490cf21c77a994
SHA-256:  90bbfa9e7af176b85d110f4f1789cae6777fcb60813b047133c8f12caa344a17
SHA-256:  b3e853eee14fb7948c6907888ee07139085ba9af4231c30e97ff6236b86ca024
```

> **SOC Action:** Add the indicators above to network blocklists and EDR file-hash watchlists. Alert on any process tree where `VMwareNamespaceCmd.exe` loads non-VMware-signed DLLs from non-standard paths, or where a child process resolves syscalls via direct stub patterns consistent with Hell's Gate. Hunt scheduled tasks created via COM (`Schedule.Service`/`ITaskFolder.RegisterTask`) under user contexts on Windows servers — Khmer Shadow uses this for persistence (T1053.005).

### 3.6 Void Blizzard — Russian National Charged in U.S. for Supporting Kremlin-Aligned Cyberespionage

**Source:** [Recorded Future News](https://therecord.media/hacker-linked-to-void-blizzard-faces-charges)

Denis Obrezko, 36, a Russian national from Stavropol, appeared in U.S. federal court in Boston after extradition from Thailand. Prosecutors allege he provided VPS and domain infrastructure — purchased with cryptocurrency — used by the Russian state-aligned **Void Blizzard** group to access at least 11 confirmed U.S. company victims (FBI affidavit states the true number is "significantly higher"). Void Blizzard typically uses purchased or stolen credentials to compromise government agencies, defence contractors, transportation, media, healthcare and NGOs across Europe and North America, exfiltrating mailboxes and internal documents. Obrezko was arrested by Thai authorities and FBI in Phuket in November 2025, with laptops, phones and crypto wallets seized; Russia has placed him on its international wanted list and sought his return.

> **SOC Action:** Re-check identity provider logs (Entra ID, Okta) for impossible-travel and credential-stuffing patterns aligned with Void Blizzard's purchased-credential TTPs. Validate MFA enforcement on all privileged accounts, enable Microsoft 365 unified audit log retention to 1 year minimum, and review eDiscovery and mailbox forwarding rules — Void Blizzard's primary objective is mailbox content theft. Block authentications from VPS-class ASNs (Hetzner, Choopa, M247, OVH residential ranges) on Tier-0 admin accounts.

### 3.7 FBI Seizes 13 China-Linked Fake Consulting Domains Targeting U.S. Clearance Holders

**Source:** [AlienVault OTX / HackRead](https://hackread.com/fbi-seizes-china-fake-consulting-sites-us-clearance/)

DOJ and FBI seized 13 domains used since November 2023 in a suspected PRC intelligence operation to recruit current and former U.S. clearance holders, military personnel and government employees through fake "consulting" roles advertised on Upwork, Expertia AI, Hubstaff Talent, Wellfound and Post Job Free. Operators used AI-generated profile photos, stolen identities, encrypted messaging and crypto payments, paying for innocuous research reports before pivoting candidates toward classified or insider information. Mapped to T1098, T1110 and T1566.

#### Indicators of Compromise (Seized Domains — Now FBI-Controlled)

```
gpf-ina[.]org
gulfpeace[.]org
thehorizzen[.]com
vandercons[.]com
pulsewaveglobal[.]com
safesec-group[.]com
thetruthinfo[.]com
cydfconsulting[.]com
geoindopacific[.]com
rightinfoconsult[.]com
catalystglobalsolutions[.]com
centrikglobalconsulting[.]com
finnaclevesperconsulting[.]com
```

> **SOC Action:** Add the 13 domains to insider-threat watchlists and DNS/web proxy block policies. Cross-reference HR and security-clearance rosters against any past visits to these domains (web proxy 90-day lookback) and any inbound email from the same domains. Brief cleared workforce on AI-generated persona recruitment patterns and require reporting of any unsolicited "consulting opportunity" through Upwork / Wellfound / freelance platforms.

### 3.8 Miasma Worm Source Code Leaked on GitHub — Shai-Hulud Successor

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/the-miasma-worm-source-code-briefly-leaked-on-github/)

SafeDep researchers reported that the source code of the **Miasma** credential-stealing supply-chain worm — an evolution of the previously-leaked Shai-Hulud worm — was deliberately posted to GitHub across multiple compromised developer accounts under the repo name `Miasma-Open-Source-Release`. Miasma was previously linked to attacks on Red Hat npm packages and a recent compromise of 73 Microsoft GitHub repositories. The toolkit requires **no C2 infrastructure** (it uses GitHub itself), harvests credentials from cloud providers, CI/CD systems, password managers, Kubernetes and secret stores, and trojanises npm, PyPI, RubyGems, GitHub Actions workflows and JFrog Artifactory. It also moves laterally via SSH and AWS SSM and **poisons AI coding-tool configs** (Claude, Gemini, Cursor, Copilot, Kiro, Cline). A "dead-man switch" tied to GitHub token validity triggers `rm -rf ~/; rm -rf ~/Documents` if the token is revoked, running as a systemd user service or LaunchAgent for up to 72 hours. The build pipeline produces unique payloads per build via per-file AES-256-GCM, randomised obfuscation and a self-extracting loader. As with Shai-Hulud, the leak is expected to drive copycat variants and elevated supply-chain attack rates. Mapped to T1003, T1078, T1531 and T1566.001.

> **SOC Action:** Pin all production project dependencies and introduce a **multi-day quarantine** before adopting newly-published npm/PyPI/RubyGems versions. Audit and rotate any developer machines' GitHub PATs and cloud CLI sessions; alert on `~/.config/claude*`, `~/.cursor*`, `~/.continue*`, `~/.copilot*` and `~/.gemini*` modifications by non-user processes. Add detection for systemd user services / LaunchAgents created in the last 72 hours that monitor GitHub APIs, and for any `rm -rf $HOME` style commands originating from non-interactive shells. Review GitHub org logs for repositories named with the pattern `*-Open-Source-Release`.

### 3.9 Europol Dismantles AudiA6 Crypto-Laundering Service (€380M+)

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/legal/authorities-dismantle-audia6-ransomware-crypto-laundering-service/)

Europol, supported by authorities from 11 countries, dismantled the **AudiA6** cryptocurrency mixing service that laundered over €380M in ransomware and cybercrime proceeds between 2022 and 2025. Two senior administrators — Ukrainian Ruslan Igorevich Tkachuk (37) and Russian Alexander Vladimirovich Ledenev (25) — were arrested in Georgia. Operations also seized 25 domains, 80 vehicles/properties, €86k in crypto and froze €692k more. Approximately 10,333 BTC passed through the service; ~393 BTC ($19.2M) came directly from known darknet markets, ransomware operations and cybercrime services. Investigators also recovered 6,000 KYC records linked to money-mule accounts created with stolen/purchased identities and blocked associated Telegram accounts. The operation was unlocked by the September 2025 arrest of a Ukrainian national in Poland. Europol linked AudiA6 to more than 15 ransomware investigations worldwide.

> **SOC Action:** If your organisation suffered a 2022–2025 ransomware incident and paid in crypto, contact your local cyber-crime unit and Europol — recovery may now be possible. Update money-mule and KYC anomaly detection rules; treat the cluster of stolen-identity exchange accounts as a known typology when reviewing onboarding fraud.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Exploitation of vulnerabilities in AI development platforms | Path traversal flaw in AI dev platform Langflow exploited in attacks (CVE-2026-5027) |
| 🔴 **CRITICAL** | Exploitation of vulnerabilities in widely used software and systems | Microsoft June 2026 Patch Tuesday (206 vulnerabilities, three publicly-disclosed zero-days: YellowKey, GreenPlasma, MiniPlasma) |
| 🟠 **HIGH** | Ransomware groups targeting multiple sectors with similar TTPs and malware | M3rx leak-site postings (werkstoff-service.de, fasadeconsult.no, maringoodman.com, ktwhs.com, suppcenter.global) |
| 🟠 **HIGH** | Increased use of phishing and web protocols in ransomware campaigns | DragonForce (Areco, Cekok, Hong Kong Parkview); Qilin (Maui Divers Jewelry) |
| 🟠 **HIGH** | Shift from hacktivism to financially-motivated RaaS operations | DragonForce victims (Areco, Brian Cox, Cekok, Hong Kong Parkview) |
| 🟠 **HIGH** | Increased ransomware activity by Qilin and ShinyHunters across sectors | Notice By shinyhunters; University of Nottingham (454,635); Miller & Zois; Iliff By qilin |
| 🟠 **HIGH** | Phishing campaigns leveraging social-media platforms for credential theft | Voicemail Phishing Kit (SSO hijacking, credential theft, RMM delivery); MLTBackdoor technical analysis |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **Qilin** (90 reports) — RaaS operator; pipeline's most prolific actor across legal, retail, manufacturing and hospitality victims
- **The Gentlemen** (55 reports) — ransomware group active across multiple regions
- **DragonForce** (39 reports) — RaaS shifting from hacktivism to financial motivation
- **Akira** (34 reports) — sustained ransomware activity; enterprise targeting
- **TeamPCP** (28 reports) — underground forum cluster
- **ShinyHunters** (22 reports) — extortion gang; Oracle PeopleSoft "gadget chain" campaign affecting 100+ orgs
- **Nova** (22 reports) — emerging ransomware operator
- **Lockbit5** (20 reports) — successor branding under continued tracking
- **Nightspire** (20 reports) — active ransomware group
- **Stormous** (18 reports) — opportunistic extortion operator

### Malware Families

- **RansomLook** (114 reports) — pipeline's most-referenced malware label, dominated by RansomLook leak-site aggregation
- **Tox1 / Tox** (34 / 21 reports) — underground tooling clusters
- **Other1** (25 reports) — unattributed cluster
- **Akira ransomware / Akira** (18 / 13 reports) — sustained operations
- **The Gentlemen** (13 reports) — actor-malware dual label
- **Shai-Hulud / Mini Shai-Hulud** (13 / 13 reports) — supply-chain worm lineage, now extended by today's Miasma source-code leak
- **RALord** (12 reports) — emerging family

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| RansomLook | 37 | [link](https://www.ransomlook.io) | Ransomware leak-site aggregation; primary feed for Qilin / DragonForce / M3rx / the gentlemen / inc ransom postings |
| Unknown (Telegram-origin) | 20 | — | BlackNet-00 ransomware development and victim notice channels; Telegram (channel name redacted) |
| BleepingComputer | 8 | [link](https://www.bleepingcomputer.com/news/security/cisa-tells-govt-agencies-to-patch-critical-exploited-flaws-in-3-days/) | Primary coverage of CISA BOD 26-04, Langflow exploitation, Nottingham breach, Miasma leak, AudiA6 takedown |
| AlienVault | 4 | [link](https://otx.alienvault.com/pulse/6a2aa0fe417d1a6f2b89eec1) | OTX Pulses — Khmer Shadow / NIGHTFORGE; FBI China consulting domain seizure; Sniper's Nest browser-hijacking |
| Wired Security | 4 | [link](https://www.wired.com/category/security) | Secondary coverage of CISA BOD 26-04 / AI threat framing |
| RecordedFutures | 4 | [link](https://therecord.media/hacker-linked-to-void-blizzard-faces-charges) | Void Blizzard indictment; Nottingham confirmation; nation-state coverage |
| CISA | 3 | [link](https://www.cisa.gov/news-events/ics-advisories/icsa-26-162-01) | ICS Advisories — Yarbo (ICSA-26-162-01), Brickcom Cameras, Naxclow IoT Platform |
| HaveIBeenPwned | 1 | [link](https://haveibeenpwned.com/Breach/UniversityOfNottingham) | Independent breach quantification: 454,635 accounts |
| Datadog | 1 | [link](https://securitylabs.datadoghq.com) | Entra Agent ID blueprint blast-radius research |
| Unit42 | 1 | [link](https://unit42.paloaltonetworks.com) | AI agent supply-chain integrity verification |
| SANS | 1 | [link](https://isc.sans.edu) | ISC diary coverage |
| Schneier, Permiso, Crowdstrike, SentinelOne, Upwind | 1 each | various | Single-report secondary analyses |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Upgrade Langflow deployments to v1.10.0 and disable unauthenticated auto-login. Active in-the-wild exploitation of CVE-2026-5027 against ~7,000 historically exposed instances; one unauthenticated request is sufficient for full file-write compromise. (Section 3.3)
- 🔴 **IMMEDIATE:** Block Yarbo mobile app versions below 3.17.4 via MDM and confirm the May 2026 server-side broker-authorisation rollout. CVE-2026-10557 (CVSS 9.8) hard-coded MQTT credentials grant fleet-wide control over deployed robots. (Section 3.2)
- 🟠 **SHORT-TERM:** Audit Oracle PeopleSoft Campus Solutions / HCM / FIN exposure and restrict web-tier access to authenticated VPN/SSO only. ShinyHunters' "gadget chain" has compromised 100+ orgs, with 454,635 records exfiltrated from University of Nottingham alone. (Section 3.4)
- 🟠 **SHORT-TERM:** Operationalise CISA BOD 26-04 internally — automate KEV ingestion, tag publicly-exposed + KEV + automatable + full-control assets, enforce 72-hour patch SLAs on that subset. (Section 3.1)
- 🟡 **AWARENESS:** Pin dependencies and introduce multi-day quarantine on new npm/PyPI/RubyGems versions; audit developer AI-coding-tool configs for tampering. The Miasma source code leak is expected to drive copycat supply-chain worms within days. (Section 3.8)
- 🟡 **AWARENESS:** Add the Khmer Shadow and FBI-seized China-consulting indicators to network blocklists and watchlists; brief cleared workforce on AI-generated persona recruitment tactics on freelance platforms. (Sections 3.5, 3.7)
- 🟢 **STRATEGIC:** Stand up an AI-platform attack-surface programme covering Langflow, ChromaDB, LiteLLM, MCP servers and agent-orchestration frameworks. The critical-risk correlation trend "exploitation of vulnerabilities in AI development platforms" — anchored by CVE-2026-5027 today — is now a recurring weekly pattern. (Section 4)

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 91 reports processed across 2 correlation batches (IDs 167, 168). A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
