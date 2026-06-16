---
layout: post
title:  "CTI Daily Brief: 2026-06-16 — Fortinet FortiSandbox actively exploited; CISA adds LiteSpeed cPanel flaw to KEV; DragonForce abuses Microsoft Teams TURN relays"
date:   2026-06-16 20:10:00 +0000
description: "Active exploitation of critical Fortinet FortiSandbox CVEs, a fresh CISA KEV addition for LiteSpeed cPanel, DragonForce ransomware hiding C2 inside Microsoft Teams infrastructure, and Earth Lusca government targeting dominate today's intelligence."
category: daily
tags: [cti, daily-brief, dragonforce, earth-lusca, cloak, fortinet, cve-2026-39813, cve-2026-48172]
classification: TLP:CLEAR
reporting_period: "2026-06-16"
generated: "2026-06-16"
draft: true
severity: critical
report_count: 58
sources:
  - BleepingComputer
  - AlienVault
  - Microsoft
  - CISA
  - RansomLook
  - Unit42
  - Permiso
  - Datadog
  - SANS
  - Schneier
  - Wired Security
  - RecordedFutures
  - Crowdstrike
  - Upwind
  - Wiz
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-06-16 (24h) | TLP:CLEAR | 2026-06-16 |

## 1. Executive Summary

The pipeline ingested 58 reports across 15 sources in the last 24 hours, with one critical and 40 high-severity items dominating the picture. BleepingComputer confirms in-the-wild exploitation of three critical Fortinet FortiSandbox flaws (CVE-2026-39813, CVE-2026-39808, CVE-2026-25089), and CISA added LiteSpeed cPanel plugin flaw CVE-2026-48172 to the Known Exploited Vulnerabilities Catalog under Binding Operational Directive 26-04, giving federal agencies three days to patch. Symantec and BleepingComputer report a DragonForce ransomware intrusion that hid command-and-control traffic inside legitimate Microsoft Teams TURN relays using a custom Go-based backdoor (Backdoor.Turn) plus a novel BYOVD chain abusing Huawei's HWAuidoOs2Ec.sys driver. ESET attributes Windows variants of the SprySOCKS backdoor to China-linked Earth Lusca/FishMonger targeting government organisations in Taiwan, Thailand, Pakistan and Honduras. Ransomware leak-site activity remains heavy with Inc Ransom, Aurora, Cloak, Nightspire and DragonForce all posting new victims, while Steam Workshop's Wallpaper Engine is being actively abused to push DarkKomet, Lumma and Vidar.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 1 | Fortinet FortiSandbox CVE-2026-39813/39808/25089 active exploitation |
| 🟠 **HIGH** | 40 | DragonForce/Backdoor.Turn; LiteSpeed cPanel KEV; Earth Lusca SprySOCKS; Steam Workshop malware; Rockwell ICS advisories; ransomware leak-site posts |
| 🟡 **MEDIUM** | 3 | FTC $3.5B imposter-scam report; CVE-2026-34182 CMS AuthEnvelopedData; MediaFire ZIP NetSupport chain |
| 🟢 **LOW** | 2 | CVE-2026-40371 Dynamics 365 EoP; Telegram proxy advert |
| 🔵 **INFO** | 12 | Microsoft revisions (CVE-2026-42915, 45602); Wired AI export-control story; UK age-verification; vendor blogs |

## 3. Priority Intelligence Items

### 3.1 Fortinet FortiSandbox — Three Critical CVEs Now Exploited in the Wild

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/critical-fortinet-fortisandbox-flaws-now-exploited-in-attacks/)

Threat-intelligence firm Defused observed exploitation of three critical FortiSandbox vulnerabilities — CVE-2026-39813, CVE-2026-39808 and CVE-2026-25089 — patched by Fortinet on 14 April. The flaws allow unauthenticated remote code execution and privilege escalation via low-complexity command injection with no user interaction. A medium-severity path-traversal flaw (CVE-2025-61624) is also being chained for authenticated privilege escalation. Defused notes a working exploit for CVE-2026-25089 has not yet been publicly disclosed, suggesting the current activity uses internally developed or "vibecoded" exploits. CISA already tracks 26 historically exploited Fortinet vulnerabilities; ransomware affiliates have abused 13 of them. MITRE techniques: T1059, T1190, T1218.001.

> **SOC Action:** Verify all FortiSandbox appliances are on the April-2026 fixed train or later. Until patched, restrict management-plane reachability to a jump host and alert on outbound connections from the FortiSandbox appliance to non-Fortinet infrastructure. Audit `/var/log` for unexpected command-injection patterns against the management API.

### 3.2 CISA Adds LiteSpeed cPanel Plugin Flaw (CVE-2026-48172) to KEV — Three-Day Patch Window

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/cisa-warns-of-another-actively-exploited-cpanel-plugin-flaw/)

CISA added LiteSpeed cPanel user-end plugin vulnerability CVE-2026-48172 to the KEV catalogue and issued a three-day patch deadline under BOD 26-04. The flaw is a UNIX-symlink-following weakness allowing attackers with FTP or web-shell access to escalate to root on shared hosting servers running CloudLinux/CageFS. All plugin versions before 2.4.8 are vulnerable. LiteSpeed published a grep-based detection one-liner:

```
grep -rE 'cpanel_jsonapi_func=(generateEcCert|packageUserSize)|cert_action_entry .*geneccert' /usr/local/cpanel/logs/ /var/cpanel/logs/ 2>/dev/null
```

> **SOC Action:** For any managed-hosting or shared-tenant cPanel infrastructure, upgrade the LiteSpeed user-end plugin to ≥2.4.8 today. Run the LiteSpeed detection grep against `/usr/local/cpanel/logs/` and `/var/cpanel/logs/` — non-empty output is a compromise indicator and warrants full hosting-account triage and credential rotation.

### 3.3 DragonForce Hides C2 in Microsoft Teams TURN Relays — New "Backdoor.Turn" Tooling

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/ransomware-gang-abuses-microsoft-teams-relays-to-hide-malicious-traffic/), [Symantec via AlienVault OTX](https://www.security.com/threat-intelligence/dragonforce-msteams-backdoor)

Symantec describes a months-long DragonForce ransomware intrusion at a major U.S. services firm where the attackers used a custom Go-based backdoor (Backdoor.Turn) to obtain anonymous Microsoft Teams visitor tokens, establish a connection via a legitimate Microsoft TURN relay, then tunnel QUIC C2 traffic to attacker-controlled infrastructure. Defenders saw only outbound traffic to Microsoft Teams. Initial access was likely SQL/MSSQL server exploitation. The attackers used DLL side-loading against VirtualBox/DbgView, BYOVD via Huawei `HWAuidoOs2Ec.sys` (a novel "Havoc Process Terminator" technique), plus exploitation of CVE-2023-52271 (Topaz `wsftprm.sys`), CVE-2025-61155 (Tower of Fantasy `Gamedriverx64.sys`) and CVE-2025-1055 (K7 `K7RKScan.sys`). MITRE techniques include T1190, T1574.002, T1562.001/006, T1071.001, T1567 and T1486.

#### Indicators of Compromise

```
C2 IP: 62.164.177[.]25
Staging URL: hxxp[:]//192.36.27[.]51/TechSupV18Fix3.zip
Domains (DGA-style C2/proxy):
  comunidadesparentais[.]com[.]br
  glanz-gmbh[.]de
  mysimerp[.]net
  professionalhomebasedbusiness[.]com
  projetosmecanicos[.]com[.]br
  safefire[.]jo
  socialbizsolutions[.]com
  turnkeyaiagents[.]com
SHA-256 (sample):
  048e18416177de2ead251abdf4d89837f6807c6aba4d5b1debe49adfdecbf05c
  65ab49119c845801f29a57e8aa177146b2ffbd289d4278109b146f933380f951
  6bbf10bcbef7ac5102b54c81137859891a3802dbacd888be90f990d50e18b0b4
  821da79d727351dd67ce5df7950e9a3de6647a3cf474bb3a093f67507fed92a6
  aea26980059ef2ad11e99556a4edfa1f8ec769fa9f06aa573b81bedf319954b5
  cd078957167e1af4de39aecdb981cd14156fa81d5a9c6ac51e74ae5b6199a12a
```

> **SOC Action:** Block known Backdoor.Turn SHA-256s and the listed domains/IPs at the proxy and DNS layer. Hunt for outbound TURN/QUIC traffic to Microsoft Teams relays originating from non-Teams processes — especially server-class hosts that should not be running Teams. Audit kernel-driver loads for `HWAuidoOs2Ec.sys`, `wsftprm.sys`, `Gamedriverx64.sys` and `K7RKScan.sys`; any of these on production infrastructure is highly suspicious. Look for VirtualBox/DbgView side-loading anomalies (`vboxrt.dll` loaded from unusual paths).

### 3.4 Earth Lusca (China) Deploys Windows SprySOCKS Variants Against Government Targets

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/windows-version-of-sprysocks-linux-malware-used-to-attack-govt-orgs/)

ESET attributes — with high confidence — new Windows variants of the SprySOCKS backdoor (WIN_DRV and WIN_PLUS) to the China-linked Earth Lusca cluster, also tracked as FishMonger, Aquatic Panda, Red Dev 10 and TAG-22. Attacks between 2023 and 2024 targeted government organisations in Taiwan, Thailand, Pakistan and Honduras. WIN_DRV loads a memory-resident driver (`RawWNPF`) via signed loader `fsdiskbit.sys` (a leaked PastDSE GitHub certificate) to hide processes, files, network connections and registry keys. WIN_PLUS persists as a Windows Print Processor (`VSPMsg`). The backdoor supports 30+ C2 commands over TCP/UDP/WebSocket, SOCKS proxy, keylogging, clipboard capture and TCP traffic diversion that allows command injection without exposing a listening port. ESET notes possible UEFI bootkit activity referencing CVE-2023-24932 (Secure Boot bypass), but evidence is incomplete. MITRE techniques: T1036, T1059, T1071.001.

> **SOC Action:** For government and defence-adjacent customers, hunt for unsigned or anomalously signed kernel drivers — particularly `RawWNPF`, `fsdiskbit.sys` or drivers signed by the leaked PastDSE certificate. Inspect `HKLM\SYSTEM\CurrentControlSet\Control\Print\Environments\Windows x64\Print Processors\` for unknown processors such as `VSPMsg`. Alert on Image File Execution Options keys pointing to `vds.exe` and scheduled tasks running it.

### 3.5 Steam Workshop / Wallpaper Engine Abused to Distribute Stealers, Backdoors and Ransomware

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/steam-workshop-abused-to-spread-malware-via-wallpaper-engine-app/), [AlienVault OTX (Kaspersky)](https://otx.alienvault.com/pulse/6a311c5582f3c51d5631d979)

Kaspersky documents a campaign — active since at least late 2025 — abusing the "application wallpaper" feature in Steam's Wallpaper Engine (≈1 million reviews) to ship executable wallpapers laced with DarkKomet backdoor, Lumma and Vidar infostealers, cryptocurrency miners, botnet loaders, RanEngine and ransomware. Sample payload "NTRaholic" launches as a game while dropping a custom `AggregatorHost.dll` that searches for Steam accounts and exfiltrates credentials. Several malicious wallpapers had been downloaded "tens of thousands" of times. Steam has removed identified items, but Kaspersky warns of likely resubmission. Primarily impacts Chinese and Russian gamer populations. MITRE: T1566, T1078, T1055.

> **SOC Action:** For environments where employees may use personal/corporate machines for gaming, block execution of `wallpaper64.exe` / Wallpaper Engine application wallpapers via WDAC or AppLocker, and add Steam Workshop content paths to EDR scanning scope. Alert on file writes named `AggregatorHost.dll` outside legitimate Microsoft .NET install paths. Hunt for DarkKomet, Lumma and Vidar parent-process chains originating from `Steam.exe`.

### 3.6 Vertex AI SDK "Pickle in the Middle" — Cross-Tenant RCE via Bucket Squatting

**Source:** [Unit 42](https://unit42.paloaltonetworks.com/hijacking-vertex-ai-model/)

Unit 42 disclosed a now-patched Google Cloud Vertex AI Python SDK flaw (`google-cloud-aiplatform` 1.139.0 and 1.140.0; fixed in 1.148.0 on 15 April 2026). Vulnerable versions construct a deterministic default staging bucket from project ID and region, allowing an external attacker who knows the victim project ID to pre-create that bucket ("bucket squatting") and silently receive victim model artefacts. The attacker can swap in a malicious pickle payload that executes when the victim deploys the model, yielding cross-tenant RCE inside Vertex AI serving infrastructure. MITRE: T1068, T1204.

> **SOC Action:** Inventory all use of `google-cloud-aiplatform` in CI/CD and notebooks; pin to ≥1.148.0. Enforce explicit `staging_bucket` parameters on every model upload and disable default bucket creation via organisation policy. Hunt GCP audit logs for `storage.buckets.create` events on buckets matching the Vertex default pattern that were created by accounts outside the project.

### 3.7 Supporting Items Worth Noting

- **Rockwell Automation ICS advisory cluster (CISA ICSA-26-167-01..05):** PavilionX authorisation bypass (CVE-2025-14272), CompactLogix and Logix 5370/5570 CIP DoS (CVE-2026-11317), RSLinx Classic stack-buffer overflow (CVE-2020-13573), FLEX I/O EtherNet/IP missing-auth (CVE-2026-0647) and DoS (CVE-2026-0646). Patch to FLEX I/O 2.013 and PavilionX 7.01 minimum.
- **GhostTree (Varonis/BleepingComputer):** Non-CVE evasion technique using recursive NTFS junctions to create unbounded directory loops that EDR scanners cannot fully traverse. No admin required.
- **Permiso — GCP `serviceData` deprecation gap:** Deprecated `policyDelta` sub-property may be missing in audit-log exports, leaving detection gaps for IAM and audit-logging changes.
- **SANS ISC — Remcos RAT via VHDX:** ZIP→VHDX→JavaScript→WMI→PowerShell→.NET loader chain delivering Remcos and bypassing EDR via `WbemScripting.SWbemLocator`.
- **Socket — GlassWASM in Open VSX:** Three-stage TinyGo-compiled WebAssembly malware using Solana memos as C2 dead-drop in trojanised Open VSX extensions.
- **Zimperium — Rokarolla Android banker:** Overlay-attack banker targeting SA, BR, IN, VN, ID with OTP SMS interception and keylogging.
- **Microsoft MSRC — CVE-2026-50656:** Elevation-of-privilege in Microsoft Malware Protection Engine ("RoguePlanet"); update pending. CVE-2026-54411: Linux-PAM `pam_userdb` timing-side-channel password recovery (requires `crypt=none` misconfiguration).

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Ransomware groups leveraging double-extortion tactics and advanced techniques | Three Cloak leak-site posts deploying ARCrypter/Babuk variants with HC-128 + Curve25519 encryption |
| 🟠 **HIGH** | Increased exploitation of cloud-service vulnerabilities and misconfigurations | Permiso GCP `serviceData` audit-log gap; Datadog Salesforce threat-hunting guide |
| 🟠 **HIGH** | Targeting of critical manufacturing sectors with denial-of-service vulnerabilities | CISA advisories on Rockwell CompactLogix, RSLinx Classic, Logix 5370/5570 |
| 🟠 **HIGH** | Ransomware actor "DragonForce" extending TTPs into legitimate-service abuse | Symantec + BleepingComputer dual reporting on Backdoor.Turn TURN-relay tunnelling |
| 🟠 **HIGH** | Steam Workshop malware-delivery campaign correlated across two independent reports | BleepingComputer + Kaspersky pulse both naming DarkKomet/Lumma/Vidar |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **Qilin** (71 reports) — RaaS, currently most-mentioned actor; healthcare and education leak-site activity.
- **The Gentlemen** (70 reports) — Leak-site operator hitting healthcare and manufacturing.
- **Deadlock** (55 reports) — Decentralised leak-site that persists despite takedown attempts.
- **DragonForce** (40 reports) — RaaS; today's Backdoor.Turn/Teams-relay campaign.
- **Akira** (34 reports) — Double-extortion, Windows/Linux/ESXi; active leak-site posts.
- **Nightspire** (29 reports) — Active RaaS using Tor + Telegram; multiple new victims today.
- **Nova** (27 reports) — Rebranded from RALord; PGP-encrypted ransom notes.
- **TeamPCP** (25 reports) — Continued visibility in pipeline.
- **ShinyHunters** (23 reports) — Today's Ralph Lauren leak-site post.
- **Lockbit5** (20 reports) — Continued background activity.

### Malware Families

- **RansomLook** (144) — Source-tagging aggregator (pipeline artefact rather than malware).
- **Tox1 / Tox** (43 / 24) — Tox-protocol C2 used by multiple ransomware crews.
- **Akira ransomware / Akira** (17 / 13) — Persistent double-extortion family.
- **RALord / Nova** (15 / 13) — Rebrand-and-relaunch pattern.
- **Nightspire** (13) — Ransomware operator infrastructure tag.
- **Shai-Hulud** (12) — npm-supply-chain worm carried over from prior campaigns.
- **DarkKomet, Lumma, Vidar** — Featured in today's Steam Workshop campaign.
- **Backdoor.Turn** — New DragonForce custom Go backdoor (today).
- **SprySOCKS (WIN_DRV / WIN_PLUS)** — Earth Lusca Windows variants (today).

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| RansomLook | 20 | [link](https://www.ransomlook.io) | Ransomware leak-site aggregator (Inc Ransom, Aurora, Cloak, Nightspire, Qilin, DragonForce, Akira, ShinyHunters) |
| BleepingComputer | 8 | [link](https://www.bleepingcomputer.com) | Primary coverage of Fortinet, cPanel/KEV, DragonForce, Steam, SprySOCKS, GhostTree |
| AlienVault | 6 | [link](https://otx.alienvault.com) | Pulses on DragonForce/Teams, Steam wallpapers, Rokarolla, ClickFix/Potemkin, GlassWASM |
| Microsoft | 6 | [link](https://msrc.microsoft.com/update-guide) | MSRC advisories incl. CVE-2026-50656, CVE-2026-54411, Dynamics 365 EoP |
| CISA | 5 | [link](https://www.cisa.gov/news-events/ics-advisories) | Rockwell Automation ICS advisories ICSA-26-167-01..05 |
| Unknown | 3 | — | Telegram-origin proxy posts (channel name redacted) |
| Unit42 | 1 | [link](https://unit42.paloaltonetworks.com/hijacking-vertex-ai-model/) | Vertex AI SDK cross-tenant RCE |
| SANS | 1 | [link](https://isc.sans.edu/diary/rss/33080) | VHDX→Remcos chain |
| Permiso | 1 | [link](https://permiso.io/blog/gcp-servicedata-officially-deprecated-actively-dangerous) | GCP `serviceData` audit-log gap |
| Datadog | 1 | [link](https://securitylabs.datadoghq.com/articles/mapping-out-your-unknown-threat-hunters-guide-to-salesforce/) | Salesforce threat-hunting guide |
| Crowdstrike | 1 | [link](https://www.crowdstrike.com/en-us/blog/falcon-exposure-management-now-available-for-third-party-environments/) | Vendor product update |
| RecordedFutures | 1 | [link](https://therecord.media/india-blocks-telegram-over-cheating-fears) | Policy / India-Telegram block |
| Schneier | 1 | [link](https://www.schneier.com) | Flock camera misuse |
| Wired Security | 1 | [link](https://www.wired.com/story/dangerous-ai-models-are-coming-no-matter-what/) | AI export controls |
| Upwind | 1 | [link](https://www.upwind.io) | Vendor program announcement |
| Wiz | 1 | [link](https://www.wiz.io/blog/exposure-management-dashboard) | Vendor product blog |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Patch FortiSandbox to the April-2026 fixed train (CVE-2026-39813, -39808, -25089, -61624). Block management-plane access from untrusted networks until the upgrade is complete. (Item 3.1)
- 🔴 **IMMEDIATE:** For any shared/managed hosting, upgrade LiteSpeed cPanel user-end plugin to ≥2.4.8 within the CISA BOD 26-04 three-day window and run the LiteSpeed grep against cPanel logs to confirm no prior exploitation. (Item 3.2)
- 🟠 **SHORT-TERM:** Hunt for DragonForce / Backdoor.Turn indicators — block listed C2 (62.164.177[.]25, listed SHA-256s and domains), audit vulnerable-driver loads (`HWAuidoOs2Ec.sys`, `wsftprm.sys`, `Gamedriverx64.sys`, `K7RKScan.sys`), and review server outbound traffic to Microsoft Teams TURN relays from non-Teams processes. (Item 3.3)
- 🟠 **SHORT-TERM:** Inventory all `google-cloud-aiplatform` SDK usage; pin to ≥1.148.0, enforce explicit `staging_bucket` parameters, and audit GCP buckets matching the Vertex default naming pattern. (Item 3.6)
- 🟠 **SHORT-TERM:** Apply the Rockwell Automation patch set (FLEX I/O 2.013, PavilionX 7.01, latest CompactLogix/Logix and RSLinx Classic) on all ICS networks; segment management interfaces away from corporate VLANs. (Item 3.7)
- 🟡 **AWARENESS:** Brief gaming-friendly user populations on the Steam Workshop / Wallpaper Engine threat; consider AppLocker/WDAC block of application-wallpaper execution on managed endpoints. (Item 3.5)
- 🟡 **AWARENESS:** Government, technology and telecoms verticals should review for Earth Lusca / SprySOCKS Windows artefacts (anomalous Print Processors, `RawWNPF`, `fsdiskbit.sys`). (Item 3.4)
- 🟢 **STRATEGIC:** Address detection-engineering gaps highlighted today — Permiso's GCP `serviceData` log-export issue and the GhostTree NTFS-junction evasion both undermine common assumptions about logging and EDR completeness; validate that current pipelines do not silently truncate either.

---

*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 58 reports processed across 3 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
