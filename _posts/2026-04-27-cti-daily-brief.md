---
layout: post
title:  "CTI Daily Brief: 2026-04-27 - Critical GitHub RCE (CVE-2026-3854) actively exploitable; ShinyHunters, LAPSUS$ and Qilin dominate ransomware activity"
date:   2026-04-28 20:30:00 +0000
description: "Wiz disclosed CVE-2026-3854, a critical RCE in GitHub.com and GitHub Enterprise Server with 88% of GHES instances still unpatched. ShinyHunters monetised the Anodot supply-chain compromise (Vimeo, Pitney Bowes 8.2M breach), LAPSUS$ leaked 96GB of Checkmarx code via the Trivy supply-chain incident, Qilin published five new RaaS victims, and Finnish authorities arrested an alleged Scattered Spider operator."
category: daily
tags: [cti, daily-brief, cve-2026-3854, qilin, shinyhunters, lapsus, scattered-spider, kimsuky]
classification: TLP:CLEAR
reporting_period: "2026-04-27"
generated: "2026-04-28"
draft: true
severity: critical
report_count: 52
sources:
  - Wiz
  - BleepingComputer
  - RecordedFutures
  - AlienVault
  - HaveIBeenPwned
  - SANS
  - Schneier
  - CISA
  - Microsoft
  - Cisco Talos
  - Wired Security
  - RansomLook
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-04-27 (24h) | TLP:CLEAR | 2026-04-28 |

## 1. Executive Summary

The pipeline processed 52 reports across 14 sources in the last 24 hours, dominated by ransomware leak-site postings (29 high-severity items) and anchored by two critical disclosures. Wiz Research published CVE-2026-3854, a remote code execution vulnerability in GitHub's internal git infrastructure that compromises both GitHub.com and GitHub Enterprise Server via a single authenticated `git push`; 88% of GHES instances were still unpatched at disclosure. ShinyHunters continued to monetise the Anodot third-party compromise, claiming a 8.2 million-account dump from Pitney Bowes and adding Vimeo to its extortion site. LAPSUS$ leaked 96GB of Checkmarx GitHub data sourced from the Trivy supply-chain incident, while Finnish authorities charged a 19-year-old dual US/Estonian citizen ("Bouquet") as a Scattered Spider operator. Qilin pushed five fresh ransomware claims, and Citizen Lab and Breakglass Intelligence published infrastructure tracking on Chinese (GLITTER CARP / SEQUIN CARP) and DPRK (Kimsuky / APT43) phishing operations. No new CISA KEV additions were observed in the dataset.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 2 | CVE-2026-3854 GitHub/GHES RCE (Wiz disclosure) |
| 🟠 **HIGH** | 29 | Qilin/WorldLeaks/Inc Ransom/Clop leak postings; ShinyHunters Vimeo/Pitney Bowes; LAPSUS$ Checkmarx; Scattered Spider arrest; ZionSiphon OT malware; Kimsuky and Chinese phishing infrastructure; GlassWorm OpenVSX wave |
| 🟡 **MEDIUM** | 7 | NSA GRASSMARLIN CVE-2026-6807 advisory; X-Vercel-Set-Bypass-Cookie probing; Roblox credential-theft arrests; Remote Desktop warning UI bug |
| 🟢 **LOW** | 1 | Microsoft Exchange Online TLS 1.0/1.1 deprecation notice |
| 🔵 **INFO** | 13 | Telegram OSINT chatter; CyberCom midterm warnings; Anthropic Mythos commentary; routine SANS Stormcast |

## 3. Priority Intelligence Items

### 3.1 CVE-2026-3854 — Critical RCE in GitHub.com and GitHub Enterprise Server

**Source:** [Wiz Research](https://www.wiz.io/blog/github-rce-vulnerability-cve-2026-3854), [Telegram (channel name redacted)](—)

Wiz Research disclosed an injection flaw in GitHub's internal git protocol that allows any authenticated user to execute arbitrary commands on GitHub backend servers with a standard `git push -o`. On GitHub.com the bug exposed shared storage nodes hosting "millions of public and private repositories" before being mitigated within six hours of report. On GitHub Enterprise Server (GHES) the same defect grants full server compromise, including all hosted repositories and internal secrets. Wiz reports that at the time of publication 88% of GHES instances remained on a vulnerable version. GitHub assigned this finding one of the highest payouts in its bug bounty programme. Notably, Wiz attribute the discovery to AI-assisted analysis of closed-source binaries — a methodology shift worth tracking.

Affected products and versions: GitHub Enterprise Server ≤ 3.19.1 (and earlier supported branches). Fixed versions: 3.14.24, 3.15.19, 3.16.15, 3.17.12, 3.18.6, 3.19.3. GitHub.com requires no customer action.

#### Indicators of Compromise

```
CVE: CVE-2026-3854
Affected: GitHub Enterprise Server <= 3.19.1
Fixed:    GHES 3.14.24, 3.15.19, 3.16.15, 3.17.12, 3.18.6, 3.19.3
TTP:      T1190 - Exploit Public-Facing Application
          T1064 - Scripting (referenced in Wiz writeup)
```

> **SOC Action:** Inventory all GHES instances (self-hosted and cloud-managed) and confirm the running version against the fixed list above; treat any instance ≤ 3.19.1 as a P0 patch. Pull GHES web/audit logs for `git push` invocations carrying `-o` push-option arguments with shell metacharacters or unexpected length, and review any newly created admin or service-account sessions since 28 April. Rotate machine accounts, deploy keys, runner tokens, and OAuth/PAT credentials stored on or accessible to GHES if a vulnerable host cannot be patched within 24 hours.

### 3.2 ShinyHunters — Anodot supply-chain campaign reaches Vimeo and Pitney Bowes (8.2M records)

**Source:** [Recorded Future News (Vimeo)](https://therecord.media/vimeo-blames-security-incident-on-anodot-breach), [Have I Been Pwned (Pitney Bowes)](https://haveibeenpwned.com/Breach/PitneyBowes)

Vimeo confirmed that user and customer data accessed by ShinyHunters was exfiltrated via the Anodot analytics platform, not from a direct breach of Vimeo systems. The exposed data is described as "technical data, video titles and metadata, and in some cases customer email addresses" — no video content, user logins, or payment information. ShinyHunters added Vimeo to its leak portal with a Thursday ransom deadline. Separately, Have I Been Pwned ingested 8,243,989 Pitney Bowes records (email addresses, names, job titles, phone numbers, physical addresses) released by ShinyHunters after extortion negotiations failed. The Vimeo writeup explicitly links the campaign to ShinyHunters' previously reported abuse of Anodot OAuth tokens that grant lateral access into "more than a dozen" downstream cloud tenants without exploiting product vulnerabilities, alongside earlier 2026 victims McGraw Hill, ADT, and Rockstar Games.

> **SOC Action:** If your organisation integrates Anodot or has shared OAuth/API tokens with Anodot, immediately revoke those credentials, rotate any associated service account keys, and audit OAuth grant history (Microsoft Entra ID, Google Workspace, Okta) for tokens issued to or impersonating Anodot. Hunt SaaS audit logs for anomalous reads of analytics or video-metadata datasets between January and April 2026 (T1078.004 Cloud Accounts, T1550.001 Application Access Token).

### 3.3 LAPSUS$ leaks 96GB of Checkmarx GitHub data via Trivy supply-chain compromise

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/checkmarx-confirms-lapsus-hackers-leaked-its-stolen-github-data/)

Checkmarx confirmed that LAPSUS$ has published a 96GB data pack stolen from its private GitHub repositories, and traced the initial access to the Trivy supply-chain attack attributed to "TeamPCP". Stolen credentials from the Trivy incident granted GitHub access on 23 March 2026; on 22 April the attacker used that persistence to publish malicious Docker images and trojanised VSCode/OpenVSX extensions for Checkmarx's KICS scanner that exfiltrated credentials, keys, tokens, and configuration files. Checkmarx states the leaked archive does not include customer data because customer information is not held in the GitHub environment. Notably the leak is being distributed on clearnet portals as well as the LAPSUS$ extortion site.

> **SOC Action:** Block and quarantine any cached Docker images, VSCode extensions, or OpenVSX KICS extensions pulled between 22 April and 28 April 2026; rotate developer credentials, CI tokens, and cloud secrets that any engineer ran KICS against in that window. Add IOC monitoring for the LAPSUS$ dump distribution domains and treat any developer machine that auto-updated KICS extensions as potentially compromised (T1195.002 Compromise Software Supply Chain).

### 3.4 GlassWorm returns with 73 "sleeper" OpenVSX extensions

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/glassworm-malware-attacks-return-via-73-openvsx-sleeper-extensions/)

Socket researchers identified a new GlassWorm wave on the OpenVSX marketplace consisting of 73 extensions that initially upload as benign clones of legitimate listings (matching icons, naming, and descriptions) before turning malicious in subsequent updates. Six are confirmed active payload deliverers; the remainder are dormant but assessed with high confidence as part of the campaign. Loader behaviour fetches a secondary VSIX from GitHub, loads platform-specific `.node` modules, or executes obfuscated JavaScript that decodes payload URLs at runtime. Historical GlassWorm variants targeted cryptocurrency wallets, SSH keys, access tokens, and developer environment data; payload functionality of the latest wave was not detailed by Socket at publication.

> **SOC Action:** Cross-reference your OpenVSX/VSCode extension inventories against Socket's published list of the 73 extensions; rotate all developer secrets (SSH keys, cloud tokens, package-registry credentials, signing keys) for any machine that installed a flagged extension. Block outbound `.vsix` downloads from GitHub Releases at the egress proxy where feasible, and add EDR detections for VSCode loading platform-specific `.node` files from extension directories (T1195.002, T1059.007 JavaScript).

### 3.5 ZionSiphon — OT-focused malware targets Israeli water infrastructure

**Source:** [AlienVault OTX (BreakGlass)](https://otx.alienvault.com/pulse/69f06bcd55d11c96e260dbdd)

A malware sample dubbed ZionSiphon demonstrates ICS-aware capabilities aimed at Israeli water treatment and desalination facilities, including Modbus interaction and partial DNP3/S7comm support. Geographic and environmental validation routines restrict execution to Israeli systems. Embedded pro-Iran/anti-Israel messaging indicates politically motivated intent, but no specific actor attribution has been established. Functionality includes network discovery of industrial devices, manipulation of chlorine dosing and flow-control processes, registry autorun persistence, privilege escalation, and propagation via removable media. A validation flaw prevents the analysed sample from executing successfully, suggesting incomplete development or a test build.

#### Indicators of Compromise

```
SHA-256: 07c3bbe60d47240df7152f72beb98ea373d9600946860bad12f7bc617a5d6f5f
TTPs:    T1547.001 Registry Run Keys, T1091 Replication Through Removable Media,
         T1059.001 PowerShell, T1565.001 Stored Data Manipulation,
         T1106 Native API, T1105 Ingress Tool Transfer, T1046 Network Service
         Discovery, T1083 File and Directory Discovery, T1112 Modify Registry,
         T1027 Obfuscated Files or Information, T1021 Remote Services
```

> **SOC Action:** For OT/ICS environments — particularly water utilities — alert on any new outbound Modbus/DNP3/S7comm traffic from corporate IT segments and on processes invoking those protocols outside the engineering workstation allowlist. Deploy YARA/EDR detection for SHA-256 `07c3bbe6…f5f` across IT and DMZ hosts that bridge to OT, and verify that removable-media autorun is disabled on all engineering workstations.

### 3.6 Kimsuky / APT43 — third Vultr Seoul VPS hosting 60+ phishing domains

**Source:** [Breakglass Intelligence via AlienVault OTX](https://intel.breakglass.tech/post/kimsuky-third-vultr-seoul-60-domains-ddns-rotation-naver-nts)

Breakglass Intelligence documented a third Vultr Seoul VPS — `158.247.210[.]58` (AS20473) — under Kimsuky control since at least September 2020, hosting 60+ domains over an 18-month observation window. Domains impersonate Naver (NID, n-store, n-cloud, n-corp), the Korean National Tax Service (HomeTax / NTS), and Korean government portals (`govkr`, `ips-`). The actor exclusively uses dynamic DNS (`mydns.vc`, `mydns.bz`, `dynv6.net`, `dns.army`, `dns.navy`, `kro.kr`) and rotates providers as old ones are flagged. The infrastructure currently sits parked but ready to reactivate.

#### Indicators of Compromise

```
IP:        158.247.210[.]58 (AS20473 Vultr Seoul)
Hostnames: nid-login.mydns[.]vc, nid-user.mydns[.]bz, nts-store.n-login.dns[.]navy,
           tax-login.mydns[.]vc, htax-login.mydns[.]vc, n-cloud.mydns[.]bz,
           govkr-auth.mydns[.]bz, ips-govkr.mydns[.]bz, nts-auth.mydns[.]vc
Domain:    johnnytogdstudio[.]xyz (first-seen pivot, Sep 2020)
TTP:       T1566 Phishing, T1583.001 Acquire Infrastructure: Domains
```

> **SOC Action:** Block egress to `158.247.210[.]58` and the listed `*.mydns.bz`, `*.mydns.vc`, `*.dns.navy`, `*.dns.army`, and `*.kro.kr` Naver/NTS impersonation hostnames at the proxy and DNS resolver layers; alert on any user authentication or web traffic to these names. Korean-facing organisations should sweep mailboxes for credential-harvesting lures referencing Naver login, HomeTax, or NTS in the past 18 months.

### 3.7 Chinese contractors GLITTER CARP and SEQUIN CARP — impersonation of journalists and diaspora activists

**Source:** [Citizen Lab via AlienVault OTX](https://citizenlab.ca/research/how-chinese-actors-use-impersonation-and-stolen-narratives-to-perpetuate-digital-transnational-repression/)

Citizen Lab and ICIJ identified two PRC-aligned operators conducting digital transnational repression. GLITTER CARP, active since April 2025, runs sustained phishing and digital impersonation against Uyghur, Tibetan, Taiwanese, and Hong Kong diaspora activists and the journalists who cover them; the same infrastructure and impersonation personas are reused across targets. SEQUIN CARP, active since June 2025, targets ICIJ's "China Targets" investigation team using OAuth phishing to grant attacker-controlled apps persistent mailbox access. The activity is consistent with China's Military-Civil Fusion contractor model. Citizen Lab catalogued more than 90 attacker-controlled domains (selected: `signinacesspoint[.]com`, `signinacessint[.]com`, `userconsola[.]com`, `usrkonnect[.]com`, `entryfortify[.]com`, `gitlab-ai[.]com`, `google-document[.]com`, `chinadigitaltime[.]net`, `gnews[.]news`, `vonxnews[.]com`, `fileprev[.]info`, `1drv[.]one`, `sharedrive[.]cloud`).

> **SOC Action:** Add the published GLITTER CARP / SEQUIN CARP domain list to email-security URL block lists and proxy denylists. Audit OAuth consent grants in Microsoft 365 / Google Workspace for unrecognised third-party apps requesting `Mail.Read`, `Mail.ReadWrite`, or full delegated mailbox scopes (T1528 Steal Application Access Token, T1114.002 Email Collection); revoke and re-attest where in scope. Journalist, NGO, and academic sponsors should consider temporary rate-limits on OAuth consent for unverified publishers.

### 3.8 Qilin RaaS — five new victims claimed; correlation engine binds the cluster

**Source:** [RansomLook (Qilin)](https://www.ransomlook.io//group/qilin)

Qilin (and the lower-cased duplicate cluster the pipeline tracks alongside it) posted five new victims in 24 hours: Basch & Keegan, Silicon Alley, KarmaData, TYLin International Group – Taiwan Branch, and Construction Sciences. The pipeline correlation engine grouped all five at 0.90 actor confidence based on shared RansomLook infrastructure and T1071.001 (Application Layer Protocol: Web Protocols). Two additional Qilin posts (Lifeline PCS, Leone Film Group SpA) appeared in the prior batch. Qilin remains the most active threat-actor entity pipeline-wide (75 mentions over the trailing 30 days). Communications continue via Jabber (`qilin@exploit.im`) and Tox; ransom note pattern is `README-RECOVER-[rand].txt`.

> **SOC Action:** Block known Qilin Tor leak-site onion addresses at egress where Tor is permitted; alert SIEM on creation of files matching `README-RECOVER-*.txt` and on first-seen Jabber traffic to `exploit.im`. Construction, professional-services, and media organisations should treat unauthenticated VPN concentrators and exposed RDP/SMB as immediate hardening priorities given Qilin's recent sector spread.

### 3.9 Robinhood account-creation flaw weaponised for SPF/DKIM-passing phishing

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/robinhood-account-creation-flaw-abused-to-send-phishing-emails/)

Threat actors abused a missing input-sanitisation flaw in Robinhood's onboarding flow that allowed arbitrary HTML to be injected into the `Device:` metadata field. When Robinhood subsequently auto-sent the standard "Your recent login to Robinhood" confirmation email, the injected HTML rendered as a fake "Unrecognized Device Linked to Your Account" warning that linked to `robinhood[.]casevaultreview[.]com` (now offline). Because the messages originated from `noreply@robinhood.com`, they passed SPF and DKIM. Attackers used Gmail dot-aliasing to register accounts that funnel confirmation emails to harvested target addresses (likely sourced from the 2021 Robinhood breach of ~7M customers). Robinhood has removed the abused field and confirmed no system breach.

> **SOC Action:** Educate retail-customer-facing populations that legitimate Robinhood "Unrecognized Device" alerts may have been spoofed in this campaign and to verify directly via the app. For internal email security: review DMARC reports for any Robinhood-domain phishing patterns; for organisations that operate transactional email systems, audit metadata fields rendered in templates for HTML-injection vectors (T1566.002 Phishing: Spearphishing Link).

### 3.10 Scattered Spider operator "Bouquet" arrested in Finland; charged in the US

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/us-reportedly-charges-scattered-spider-hacker-arrested-in-finland/)

A 19-year-old US/Estonian dual citizen using the alias "Bouquet" was arrested at Helsinki airport on 10 April while boarding a flight to Japan; temporarily unsealed federal records describe wire-fraud, conspiracy, and computer-intrusion charges across at least four Scattered Spider breaches dating back to a March 2023 communications-platform compromise (committed when the suspect was 16). One unnamed multi-billion-dollar luxury retailer breach in May 2025 used IT helpdesk impersonation to reset MFA — consistent with Scattered Spider's documented tradecraft (T1566 Phishing, T1621 MFA Request Generation, T1556.006 MFA fatigue). This follows the recent guilty plea of Tyler Robert Buchanan, a suspected Scattered Spider leader.

> **SOC Action:** Re-validate IT helpdesk callback procedures and out-of-band identity verification for any high-privilege account reset, MFA reset, or device re-enrolment request. Alert SOC on bursts of MFA push prompts to a single user (>3 in 5 minutes) and on user-driven password/MFA resets initiated within an hour of a helpdesk ticket. Maintain a published "we will never call asking for credentials" reminder to all staff during ongoing law-enforcement disruption — copycat helpdesk-impersonation activity is likely.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Critical vulnerabilities in widely-used software platforms are being actively exploited, posing significant risks to global IT infrastructure. | CVE-2026-3854 GitHub.com / GHES RCE (Wiz Research); Telegram disclosure mirror |
| 🔴 **CRITICAL** | Growing focus on exploiting vulnerabilities in software and services. | CVE-2026-26149 Microsoft Power Apps Desktop spoofing; CVE-2026-42208 LiteLLM SQLi 36h after disclosure (carryover from earlier 2026-04-28 batch) |
| 🟠 **HIGH** | Ransomware-as-a-Service operations targeting diverse sectors with sophisticated TTPs. | Five Qilin victims (Basch & Keegan, Silicon Alley, KarmaData, TYLin Taiwan, Construction Sciences) sharing RansomLook + T1071.001 |
| 🟠 **HIGH** | Phishing as a primary attack vector across multiple sectors. | Super AI by Everest; Vimeo/Anodot by ShinyHunters; cybersecurity vendor by RansomHouse; Robinhood onboarding HTML-injection abuse |
| 🟠 **HIGH** | RaaS groups including Qilin and ShinyHunters expanding their target base. | Lifeline PCS, Leone Film Group, Pitney Bowes (8.2M) |
| 🟡 **MEDIUM** | Phishing remains a prevalent TTP across actors and campaigns, indicating continued effectiveness. | Vimeo / Anodot incident; Scattered Spider helpdesk-impersonation breaches; McKay (mnt6) targeting engineering and solar manufacturers |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **Qilin** (75 reports / 7 active in this brief) — RaaS operation; Jabber `qilin@exploit.im`; T1071.001
- **The Gentlemen** (58 reports) — Active extortion brand observed across April
- **Coinbase Cartel** (38 reports) — Persistent breach-claim cluster
- **DragonForce** (28 reports) — Continuing RaaS activity
- **ShinyHunters** (21 reports / 3 active in this brief) — Anodot supply-chain, Vimeo, Pitney Bowes 8.2M
- **WorldLeaks** (3 active in this brief) — Hunters International rebrand; pure-extortion EaaS, no encryption
- **LAPSUS$** — Checkmarx 96GB leak via Trivy supply-chain credentials
- **Scattered Spider / UNC3944 / Octo Tempest** — Helpdesk-impersonation MFA resets; "Bouquet" arrest in Finland
- **Kimsuky / APT43 (DPRK)** — Vultr Seoul VPS hosting 60+ Naver/NTS impersonation domains
- **GLITTER CARP / SEQUIN CARP (PRC)** — Diaspora-activist and journalist phishing under Military-Civil Fusion contractor model

### Malware Families

- **RansomLook / RansomLock** (45 / 21 reports) — Tracking infrastructure for multiple RaaS leak portals
- **RaaS** (26 reports) — Generic Ransomware-as-a-Service operational model
- **DragonForce ransomware** (21 reports)
- **Qilin** (10 reports) — Encryption family attributed to the eponymous group
- **Tox / Tox1** (18 / 11 reports) — Encrypted comms channel used by multiple ransomware operators
- **Gentlemen ransomware** (9 reports)
- **GlassWorm** — 73 OpenVSX sleeper extensions; supply-chain loaders; previously stole crypto wallets, SSH keys, dev secrets
- **ZionSiphon** — Israel-targeted OT/ICS malware with Modbus interaction; pro-Iran messaging
- **McKay (mnt6)** — Emerging RaaS targeting solar manufacturing and engineering sectors

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| RansomLook | 21 | [link](https://www.ransomlook.io/) | RaaS leak-site aggregator (Qilin, WorldLeaks, Inc Ransom, Clop, Krybit, Everest, RansomHouse, ShinyHunters, mnt6, leaknet) |
| BleepingComputer | 8 | [link](https://www.bleepingcomputer.com) | LAPSUS$/Checkmarx, Robinhood phishing, Scattered Spider arrest, GlassWorm OpenVSX, OPSEC playbook, RDP UI bug, TLS deprecation, Outlook reauth |
| RecordedFutures | 5 | [link](https://therecord.media) | Vimeo/Anodot, Roblox arrests, midterm warnings, geofence ruling, Tennessee crypto ATM ban |
| Unknown | 4 | — | Telegram OSINT (Darkfeed, proxy_bar) — channels redacted |
| AlienVault | 3 | [link](https://otx.alienvault.com) | ZionSiphon OT malware, Kimsuky Vultr Seoul, Citizen Lab GLITTER/SEQUIN CARP |
| SANS | 2 | [link](https://isc.sans.edu) | X-Vercel-Set-Bypass-Cookie probing; Stormcast |
| Wired Security | 2 | [link](https://www.wired.com/category/security/) | UAE screenshot law; FIDO AI agent payment standards |
| Wiz | 1 | [link](https://www.wiz.io/blog/github-rce-vulnerability-cve-2026-3854) | CVE-2026-3854 disclosure (primary critical item) |
| HaveIBeenPwned | 1 | [link](https://haveibeenpwned.com/Breach/PitneyBowes) | Pitney Bowes 8.2M breach |
| CISA | 1 | [link](https://www.cisa.gov/news-events/ics-advisories/icsa-26-118-01) | NSA GRASSMARLIN CVE-2026-6807 advisory (no patch — software unsupported) |
| Microsoft | 1 | [link](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-33103) | Dynamics 365 (On-Prem) Information Disclosure update |
| Cisco Talos | 1 | [link](https://blog.talosintelligence.com/five-defender-priorities-from-the-talos-year-in-review/) | Year-in-review defender priorities |
| Schneier | 1 | — | Anthropic "Mythos" cybersecurity commentary |
| Upwind | 1 | [link](https://www.upwind.io/feed/cloud-security-coverage) | Cloud security coverage dashboard |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Patch all GitHub Enterprise Server instances to 3.14.24 / 3.15.19 / 3.16.15 / 3.17.12 / 3.18.6 / 3.19.3 to remediate CVE-2026-3854; treat any GHES ≤ 3.19.1 as a P0 — Wiz reports 88% of instances were unpatched at disclosure. Audit GHES web/audit logs for `git push -o` invocations and rotate machine credentials accessible to vulnerable hosts.

- 🔴 **IMMEDIATE:** Revoke and rotate any Anodot OAuth tokens, API keys, and shared credentials; audit OAuth grant histories in Entra ID / Google Workspace / Okta for tokens issued to or impersonating Anodot, given ShinyHunters' continued exploitation of that vector against Vimeo, Pitney Bowes, McGraw Hill, ADT, and Rockstar Games (T1550.001).

- 🟠 **SHORT-TERM:** Cross-reference developer endpoints against Socket's published list of 73 GlassWorm OpenVSX extensions and against Checkmarx KICS extension installs since 22 April; rotate all developer secrets (cloud tokens, SSH keys, signing keys, package-registry credentials) on affected hosts and quarantine cached Docker images. Block outbound `.vsix` retrieval from arbitrary GitHub Releases at the proxy where workflow allows.

- 🟠 **SHORT-TERM:** Re-validate IT helpdesk identity-verification procedures for password/MFA resets and device enrolment in light of the Scattered Spider arrest and continued helpdesk-impersonation tradecraft. Implement out-of-band manager callback for high-privilege resets; alert on rapid MFA-push bursts and on user-initiated MFA resets within an hour of a helpdesk ticket.

- 🟡 **AWARENESS:** Push the Kimsuky (Vultr Seoul `158.247.210[.]58` and `*.mydns.bz`/`*.mydns.vc`/`*.dns.navy`/`*.dns.army`/`*.kro.kr` Naver/NTS impersonation hostnames) and GLITTER CARP / SEQUIN CARP domain lists to email-security and proxy denylists; Korean-facing and journalist/NGO-supporting organisations should sweep mailboxes for the past 18 months for relevant credential-harvesting lures.

- 🟢 **STRATEGIC:** OT and water-utility operators should harden segmentation between IT and OT and detect any new outbound Modbus/DNP3/S7comm traffic outside engineering-workstation allowlists, given the politically motivated ZionSiphon sample. More broadly, the recurring pattern of supply-chain compromise (Anodot, Trivy, OpenVSX) reinforces that third-party SaaS OAuth scopes and CI/CD developer-tooling pipelines remain the most productive intrusion vector — invest in continuous OAuth grant attestation and developer-machine secret rotation cadence.

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 52 reports processed across 2 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
