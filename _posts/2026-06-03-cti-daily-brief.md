---
layout: post
title:  "CTI Daily Brief: 2026-06-03 — Cisco Unified CM PoC, npm supply-chain worms, CISA ATG advisory"
date:   2026-06-04 20:30:00 +0000
description: "Cisco Unified CM critical SSRF with public PoC, Miasma worm hits Red Hat npm scope, IronWorm targets 36 packages, ShinyHunters leaks 2.6M DentaQuest records, CISA warns on fuel tank monitoring system attacks."
category: daily
tags: [cti, daily-brief, akira, shinyhunters, ta4922, gamaredon, miasma, ironworm, cve-2026-20230, cve-2026-9149, cve-2026-39835]
classification: TLP:CLEAR
reporting_period: "2026-06-03"
generated: "2026-06-04"
draft: true
severity: critical
report_count: 75
sources:
  - Microsoft
  - BleepingComputer
  - Upwind
  - AlienVault
  - CISA
  - RansomLock
  - Sekoia
  - Schneier
  - HaveIBeenPwned
  - Cisco Talos
  - Sysdig
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-06-03 (24h) | TLP:CLEAR | 2026-06-04 |

## 1. Executive Summary

The pipeline ingested 75 reports across 15 sources in the last 24 hours, with four critical and 37 high-severity items. The dominant theme is npm supply-chain compromise: the **Miasma** worm hijacked Red Hat's `@redhat-cloud-services` namespace via OIDC token abuse to publish 96 malicious versions across 32 packages, while a parallel **IronWorm** Rust-based campaign trojanized 36 unrelated npm packages with an eBPF rootkit. Cisco disclosed **CVE-2026-20230**, a critical Unified CM SSRF flaw with public PoC code that yields root via WebDialer-enabled hosts. CISA, FBI, NSA, and DOE issued a joint advisory on active exploitation of internet-exposed automatic tank gauge (ATG) systems in energy and chemical sectors, with prior CNN reporting attributing similar activity to Iranian operators. Healthcare took the largest hit: ShinyHunters leaked 2.6 million DentaQuest records after failed extortion negotiations. No CISA KEV additions were observed in the period, but the Cisco SSRF and dual libsolv/Go crypto/ssh critical CVEs warrant accelerated patch cycles.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 4 | Cisco Unified CM SSRF (CVE-2026-20230), Miasma npm worm, libsolv heap overflow (CVE-2026-9149), Go crypto/ssh panic (CVE-2026-39835) |
| 🟠 **HIGH** | 37 | IronWorm npm campaign; DentaQuest/ShinyHunters; TA4922 Atlas RAT; Gamaredon GammaSteel; Akira/Space Bears/DragonForce/Inc Ransom listings; multiple Go x/net & x/crypto CVEs; Hitachi/B&R ICS advisories |
| 🟡 **MEDIUM** | 14 | WFP Gaza breach (600k); CISA Hitachi MACH HiDraw, RTU500, NAVTOR NavBox advisories; Postfix CVE-2026-43964; Telegram proxy infrastructure indicators |
| 🟢 **LOW** | 4 | Microsoft Windows driver-cache misconfiguration; minor operational notices |
| 🔵 **INFO** | 16 | Background reporting and analyst notes |

## 3. Priority Intelligence Items

### 3.1 Cisco Unified CM SSRF with Public PoC — CVE-2026-20230

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/cisco-warns-of-critical-unified-cm-flaw-with-poc-exploit-code/)

Cisco issued an out-of-cycle advisory for a critical server-side request forgery flaw in Unified Communications Manager (Unified CM / CallManager). An unauthenticated remote attacker can send a crafted HTTP request that writes files to the underlying OS, enabling later privilege escalation to root. Cisco PSIRT confirms public PoC code is circulating but has not observed in-the-wild exploitation as of disclosure. The flaw only impacts hosts where the **WebDialer** service is enabled — disabled by default — but is commonly turned on in call-centre and click-to-dial deployments. Cisco has reserved CVE-2026-20045 history as recent: the prior critical Unified CM flaw was actively exploited as a zero-day in January 2026. Fixed releases are 14SU6 and 15SU5 (September 2026 COP).

> **SOC Action:** Inventory Unified CM hosts and check `Cisco Unified Serviceability → Tools → Service Activation → CTI Services` for the `Cisco WebDialer Web Service` flag. Disable WebDialer immediately on any host that does not require it; otherwise schedule emergency patching to 14SU6 / 15SU5. Hunt EDR/proxy logs for anomalous HTTP POSTs to `/ccmadmin/`, `/webdialer/`, or unexpected file writes under the Tomcat web root. Map to ATT&CK T1190 (Exploit Public-Facing Application) and T1505.003 (Web Shell).

### 3.2 Miasma — Worming npm Supply-Chain Attack on Red Hat Cloud Services

**Source:** [Upwind](https://www.upwind.io/feed/miasma-npm-supply-chain-worm-redhat-credential-harvest), [AlienVault OTX](https://otx.alienvault.com/pulse/6a214311a2c1a61296efbdc5)

On 1 June 2026, unauthorised orphan commits were pushed into multiple RedHatInsights GitHub repositories using a compromised Red Hat employee account, bypassing branch protections. Push-triggered GitHub Actions workflows requested `id-token: write` OIDC tokens, exchanged them for npm publish rights, and shipped 96 malicious versions across 32 `@redhat-cloud-services` packages in two waves (10:53 UTC and 13:44–13:46 UTC). Because Sigstore signed the attestations, the releases carried valid SLSA provenance. Affected packages include `chrome` (2.3.1–2.3.4), `frontend-components` (7.7.2–7.7.5), `types` (3.6.1–3.6.4), `rule-components` (4.7.2–4.7.3), and `rbac-client` (9.0.3–9.0.6). The 4.2 MB obfuscated payload runs via a `preinstall` hook and sweeps GitHub tokens, AWS/Azure/GCP cloud credentials, Vault tokens, Kubernetes SA tokens, SSH keys, Docker credentials, and `.env` files — then republishes itself across other packages the victim maintains using the `bypass_2fa` publish parameter. Vendor reporting attributes activity to the **TeamPCP** cluster, building on the public Mini Shai-Hulud codebase released 12 May 2026. Affected scope receives 80,000–117,000 weekly downloads. Red Hat's RHSB-2026-006 confirms no Hybrid Cloud Console, ARO, OpenShift Dedicated, ROSA, ACS Cloud Service, or AAP on Cloud release shipped during the compromise window.

#### Indicators of Compromise
```
GitHub repo fingerprint: description = "Miasma: The Spreading Blight"
Malicious npm scope: @redhat-cloud-services (32 packages, 96 versions, 2026-06-01)
Behaviour: preinstall hook -> 4.2MB obfuscated node payload -> 4-layer unpack
Credential targets: GitHub PATs, AWS IMDS/ECS, Azure IMDS OAuth2, GCP metadata,
                    Vault 127.0.0.1:8200, Kubernetes SA tokens, /proc/<pid>/mem
                    scrape of GitHub Actions Runner.Worker masked secrets
Propagation: npm publish API with bypass_2fa parameter using stolen OIDC tokens
```

> **SOC Action:** Audit npm and CI/CD environments for any `npm install` against `@redhat-cloud-services` packages on or after 2026-06-01. Treat all reachable cloud secrets, GitHub PATs, npm tokens, and Kubernetes SA tokens in those environments as exposed — rotate immediately. Search corporate GitHub orgs for public repositories created on 2026-06-01 onward with the description "Miasma: The Spreading Blight". Add SCA gating to block `preinstall` hook execution in CI, and require human review for any new `id-token: write` workflow on push triggers. MITRE: T1195.002, T1204.002, T1552.001, T1528, T1059.007.

### 3.3 IronWorm — Rust npm Worm with eBPF Rootkit and Tor C2

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/new-ironworm-malware-hits-36-packages-in-npm-supply-chain-attack/)

A second simultaneous npm campaign, dubbed **IronWorm** by JFrog, trojanized 36 packages starting from a compromised `asteroiddao` account. The payload is a Rust ELF binary executed via `preinstall`, with backdating tricks — commit author "claude", timestamps backdated up to 13 years — to evade investigation. IronWorm targets 86 environment variables and 20 credential file types (OpenAI, AWS, Anthropic, npm credentials, Vault configs, SSH keys, Exodus wallets), uses an eBPF kernel rootkit for stealth, and communicates over Tor. Self-propagation reuses stolen npm Trusted Publishing secrets. JFrog notes shared commit names with Shai Hulud, suggesting an evolution of TeamPCP tooling rather than a copy. A novel exfiltration mechanism (not used in this wave) writes serialised secrets to a file disguised as lint output and uploads it as a GitHub Actions build artifact — fully C2-less. Endor Labs and StepSecurity have separately observed a sibling JavaScript-based campaign named `binding.gyp` in the same window. Ox Security reports IronWorm was caught early before propagating into top-tier packages.

> **SOC Action:** Block egress to Tor entry/exit nodes from build agents and developer workstations. Add detection for `preinstall` hooks invoking Rust ELF binaries inside `node_modules`. Enable AppArmor/SELinux confinement for npm install operations in CI. Hunt for unexpected eBPF program loads on Linux build hosts (`bpftool prog list`, kernel auditd `BPF` syscalls). Rotate npm publish tokens and enforce hardware-key 2FA. MITRE: T1195.002, T1014 (Rootkit), T1090.003 (Multi-hop proxy / Tor).

### 3.4 DentaQuest Breach — 2.6 Million Records Leaked by ShinyHunters

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/dentaquest-data-breach-exposed-info-of-26-million-accounts/), [HaveIBeenPwned](https://haveibeenpwned.com/Breach/DentaQuest)

DentaQuest, a Sun Life dental benefits administrator serving 35 million customers across Medicaid and Medicare Advantage programs, confirmed unauthorised network access on 2 June 2026. After failed extortion negotiations, ShinyHunters published 234 GB of stolen data. HaveIBeenPwned validated 2.6 million unique accounts containing email addresses, full names, phone numbers, government-issued IDs, health insurance information, genders, and dates of birth. HIBP notes 66% of exposed records were already present from prior breaches — material uplift for credential-stuffing and targeted phishing against US healthcare beneficiaries. ShinyHunters' "pay or leak" pattern continues against US healthcare and SaaS providers throughout Q2 2026.

> **SOC Action:** US healthcare and dental insurance providers should treat any DentaQuest-linked patient identity (name + DOB + government ID) as compromised for identity-verification flows. Tune phishing detection for lures impersonating DentaQuest, Sun Life, Medicaid plan correspondence, or "benefits renewal" themes. Push alerts to fraud teams and member-facing call centres for the next 90 days. MITRE: T1078 (Valid Accounts), T1566 (Phishing), T1657 (Financial Theft).

### 3.5 CISA Joint Advisory — Active Exploitation of ATG Fuel Tank Systems

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/cisa-warns-of-cyberattacks-targeting-fuel-tank-monitoring-systems/)

CISA, FBI, NSA, DOE, and additional US partners published a joint advisory warning of unattributed compromises of internet-exposed automatic tank gauge (ATG) systems in the Energy, Chemical, Food and Agriculture, and Transportation Systems sectors. Attackers are gaining access via authentication bypass, hardcoded credentials, OS command execution, SQL injection, and privilege escalation flaws — then modifying network settings, product identifiers, tank volumes, and pump controls. Disabling alerts could mask real leaks or equipment failures. The advisory is explicitly unattributed, but follows May 2026 CNN reporting that Iranian operators conducted similar manipulation of ATG readings at US gas stations (without altering physical fuel levels in that case). The agencies recommend pulling ATG systems off the internet entirely, enforcing strong credentials and MFA, and continuous monitoring for unauthorised parameter changes.

> **SOC Action:** Critical-infrastructure operators must enumerate all internet-exposed ATG and SCADA endpoints (Shodan queries for Veeder-Root, OPW, Franklin Fueling, Gilbarco ATG protocols on TCP/10001). Block public access via firewall ACLs and require VPN + MFA for vendor remote access. Replace all default and hardcoded credentials. Enable change-monitoring on tank volume, pump control, and alert-threshold settings — any out-of-band modification is incident-worthy. MITRE: T1190, T1078.001 (Default Accounts), T1565.002 (Stored Data Manipulation).

### 3.6 TA4922 (Chinese-Speaking Cybercrime) — Atlas RAT Expands to Europe

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/chinese-hackers-use-new-atlas-rat-malware-in-european-cyberattacks/)

Proofpoint disclosed expanded operations by **TA4922**, a Chinese-speaking financially motivated cluster with overlaps to publicly reported **Silver Fox** and **Void Arachne** activity. Since March 2026, TA4922 has shifted targeting from East Asia to entities in Germany, Italy, the United Kingdom, and South Africa. Proofpoint assesses TA4922 currently runs more unique campaigns than any other tracked cybercrime actor and suspects LLM-assisted malware development based on placeholder values and code-comment patterns. Tooling includes **Atlas RAT** (keylogging, screenshot, audio/webcam capture, anti-sandbox checks for MDAG, CExecSvc, and OS UUID), **RomulusLoader** (process hollowing, shellcode injection — used to deploy AnyDesk and the China-popular SyncFuture remote-monitoring tool against German targets), **SilentRunLoader** (Python-based Chrome stealer), and **Winos4.0 / ValleyRAT**. Lures impersonate payroll, tax audits, VAT filings, and HR communications, with secondary contact via WhatsApp, LINE, and Microsoft Teams. Proofpoint notes surveillance capability could be repurposed for or sold to espionage actors.

> **SOC Action:** Tune email gateway for German/Italian-language payroll, VAT, and tax-audit lures with archive attachments. Block AnyDesk and SyncFuture on corporate endpoints absent explicit IT need; alert on installation of either. Detect Python-based browser data harvesting from Chrome's `Login Data` and `Cookies` SQLite databases. Monitor WhatsApp/LINE/Teams for inbound contact from external users impersonating finance or HR functions. MITRE: T1566.001/002, T1219 (Remote Access Software), T1555.003.

### 3.7 Gamaredon (FSB / UAC-0010) — GammaSteel Continues Ukraine Targeting

**Source:** [Sekoia](https://blog.sekoia.io/fsbs-matryoshka-3-3-gamaredons-gifts-that-keeps-unpacking-gammasteel/)

Part three of Sekoia.io TDR's investigation into the FSB-operated **Gamaredon** (UAC-0010 / Armageddon) intrusion-set details continued phishing-led campaigns against Ukrainian government and critical-infrastructure targets, with the **GammaSteel** payload as the persistent data-exfiltration component. Attribution is consistent across Sekoia, CERT-UA, and prior public reporting. Tradecraft remains familiar: spear-phishing with LNK/SFX droppers, layered VBS and PowerShell stagers, and DNS-based C2 rotation. Operational relevance for non-Ukrainian organisations is supply-chain and contractor-network exposure to Ukrainian government services.

> **SOC Action:** Western organisations with Ukrainian subsidiaries, partners, or aid-delivery operations should hunt for LNK-launched mshta.exe / wscript.exe / powershell.exe with parents under user Temp or Downloads. Block egress to dynamic DNS providers commonly used by Gamaredon (e.g., `.ddns.net`, `.hopto.org`) from non-IT endpoints. Map indicators to ATT&CK T1566.001, T1059.001/005, T1071.004 (DNS), T1547.001.

### 3.8 OFAC Sanctions Iran's Nobitex Crypto Exchange (IRGC-Linked Ransomware Nexus)

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/the-us-sanctions-nobitex-crypto-exchange-used-by-ransomware/)

OFAC sanctioned Nobitex — Iran's largest crypto exchange handling over 50% of Iranian digital-asset inflows in 2025 — along with executives Amir Hossein Rad (chairman), Seyed Ali Khoee (CEO), and co-founders. The Treasury cited Nobitex's processing of IRGC-linked transactions including "activity associated with IRGC-affiliated ransomware actors" and stablecoin flows used to prop up the rial. Additional Iranian exchanges Wallex, Bitpin, and Ramzinex were also designated under the "Economic Fury" campaign. Chainalysis assesses IRGC-linked addresses accounted for over 50% of value received by the Iranian crypto ecosystem in Q4 2025. The sanction freezes any US-jurisdiction assets and prohibits US-person business dealings.

> **SOC Action:** Compliance, AML, and fraud teams must add Nobitex, Wallex, Bitpin, Ramzinex, and the designated individuals to OFAC SDN screening pipelines. Incident-response playbooks should be updated to flag any ransomware payment workflow routed through Iranian exchanges as a sanctions-violation risk. Threat-hunting teams should retain IRGC-linked TTP data — Pioneer Kitten, MuddyWater, APT34 — for cross-reference where ATG/ICS or healthcare extortion incidents intersect with Iranian-nexus indicators.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Rising activity of ransomware groups targeting diverse sectors with sophisticated TTPs | Akira listings (National Standard Parts Associates, Northern Ohio Regional MLS); concurrent Inc Ransom, Space Bears, DragonForce, The Gentlemen, Stormous, Cmd Organization postings |
| 🔴 **CRITICAL** | Exploitation of vulnerabilities in widely used software packages, leading to potential widespread impact | CVE-2026-9149 (libsolv heap BOF, RCE); CVE-2026-39835 (golang.org/x/crypto/ssh server panic); supporting cluster of 8+ Go x/net & x/crypto CVEs disclosed same window |
| 🔴 **CRITICAL** | Targeting of critical infrastructure sectors including government and healthcare | TA4922 Atlas RAT in Europe; Gamaredon GammaSteel against Ukraine; The Gentlemen against Michigan Surgical Center; CISA ATG advisory |
| 🟠 **HIGH** | Increased focus on supply chain attacks targeting software development and cloud services | Miasma (32 @redhat-cloud-services packages); IronWorm (36 packages); sibling binding.gyp campaign reported by Endor Labs / StepSecurity |
| 🟠 **HIGH** | Increased use of phishing as a common TTP across multiple threat actors and campaigns | Space Bears (Sicol/Geske Haus/Stellar Telecom/Ridge Law); Stormous (SA2000.COM); Inc Ransom (CUSTOMSIGN); ShinyHunters (DentaQuest); TA4922 lures |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors
- **Akira** (79 reports, last seen 2026-06-04) — RaaS targeting Windows/Linux/VMware ESXi via unpatched VPN and RDP; double extortion
- **Qilin** (74 reports) — high-tempo RaaS operator across retail and manufacturing
- **The Gentlemen** (60 reports) — active against healthcare and manufacturing, including Michigan Surgical Center
- **DragonForce** (34 reports) — RaaS with affiliate-portal model; SETS Solutions listing this period
- **TeamPCP** (32 reports) — npm supply-chain operator attributed to Miasma; Mini Shai-Hulud heritage
- **ShinyHunters** (29 reports) — "pay or leak" extortion against US healthcare/SaaS; DentaQuest 2.6M leak
- **Inc Ransom** (20 reports) — ongoing dark-web operations with consistent victim engagement
- **TA4922 / Silver Fox / Void Arachne** — Chinese-speaking cybercrime expanding to Europe with Atlas RAT
- **Gamaredon (UAC-0010)** — FSB-operated; continued Ukrainian government targeting via GammaSteel
- **IRGC-affiliated ransomware actors** — surfaced via OFAC Nobitex action

### Malware Families
- **Akira ransomware** (42 reports) — `.akira` extension, CryptoAPI-based; ESXi-aware variants
- **Mini Shai-Hulud / Miasma** (11 reports) — open-source npm worm framework now weaponised against Red Hat scope
- **IronWorm** (new) — Rust + eBPF rootkit + Tor C2; 36-package npm campaign
- **Atlas RAT** (new) — TA4922 RAT with keylogging, screen/audio/webcam capture
- **RomulusLoader / SilentRunLoader / Winos4.0 (ValleyRAT)** — TA4922 loader/stealer suite
- **GammaSteel** — Gamaredon exfiltration payload
- **Havoc** — Brazilian campaign delivering Havoc Demon via fake Microsoft Defender DLP module
- **CastleRAT** — ClickFix social-engineering chain via Deno-executed JavaScript, Steam Community C2
- **Argamal** — RAT hidden in trojanized adult games using FFmpeg DLL hijack and COM persistence
- **C0XMO (Gafgyt variant)** — Linux router botnet propagating via CVE-2021-27137

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| Microsoft | 15 | [link](https://msrc.microsoft.com/update-guide/) | MSRC vulnerability advisories — libsolv, golang.org/x/net, x/crypto/ssh CVE cluster |
| Unknown / OSINT | 13 | — | Includes Telegram-origin TLP:AMBER+STRICT proxy infrastructure indicators (channel name redacted) |
| BleepingComputer | 10 | [link](https://www.bleepingcomputer.com/news/security/cisco-warns-of-critical-unified-cm-flaw-with-poc-exploit-code/) | Primary coverage of Cisco Unified CM, IronWorm, DentaQuest, CISA ATG advisory, OFAC Nobitex |
| RansomLook | 9 | [link](https://www.ransomlook.io/) | Akira, Inc Ransom, Space Bears, Stormous, DragonForce, The Gentlemen, Cmd Organization victim listings |
| AlienVault OTX | 6 | [link](https://otx.alienvault.com/) | CastleRAT (ClickFix/Deno), Argamal (hentai games), Miasma analysis, Brazilian Havoc, Browser Spy-Ons, Gafgyt C0XMO |
| CISA | 5 | [link](https://www.cisa.gov/news-events/ics-advisories) | ICS advisories for Hitachi Energy ITT600/MACH HiDraw/RTU500, B&R PPT30, NAVTOR NavBox |
| RecordedFutures | 3 | [link](https://www.recordedfuture.com/research) | Threat-intelligence research |
| Cisco Talos | 3 | [link](https://blog.talosintelligence.com/reporting-from-vegas-networking-ai-and-good-boys/) | Threat Hunting program update |
| Upwind | 2 | [link](https://www.upwind.io/feed/miasma-npm-supply-chain-worm-redhat-credential-harvest) | Lead reporting on Miasma worm |
| SANS | 2 | [link](https://isc.sans.edu/) | Internet Storm Center analyst notes |
| Sekoia | 1 | [link](https://blog.sekoia.io/fsbs-matryoshka-3-3-gamaredons-gifts-that-keeps-unpacking-gammasteel/) | Gamaredon GammaSteel investigation, part 3 |
| HaveIBeenPwned | 1 | [link](https://haveibeenpwned.com/Breach/DentaQuest) | DentaQuest breach validation (2.55M accounts) |
| Wiz | 1 | [link](https://www.wiz.io/blog) | Cloud-security research |
| BellingCat | 1 | [link](https://www.bellingcat.com/) | OSINT research |
| Schneier | 1 | [link](https://www.schneier.com/blog/) | Meta AI chatbot password-reset abuse |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Patch or mitigate Cisco Unified CM (CVE-2026-20230) — disable WebDialer service on any host that does not require it, schedule 14SU6/15SU5 deployment, and hunt for SSRF-pattern HTTP requests to `/webdialer/` endpoints. Public PoC exists.
- 🔴 **IMMEDIATE:** Audit all CI/CD and developer environments for `npm install` of `@redhat-cloud-services` packages on or after 2026-06-01, or any of the 36 IronWorm-affected packages. Rotate every cloud credential, GitHub PAT, npm token, Vault secret, and Kubernetes service-account token reachable from those environments. Search GitHub for new repositories with the "Miasma: The Spreading Blight" description.
- 🟠 **SHORT-TERM:** Critical-infrastructure operators in Energy, Chemical, Food & Agriculture, and Transportation must remove internet-exposed ATG systems per the CISA/FBI/NSA/DOE joint advisory. Replace default credentials, gate vendor access behind VPN + MFA, and continuously monitor for tank-volume, pump-control, and alert-threshold changes.
- 🟠 **SHORT-TERM:** Inventory and patch the Go cluster disclosed via MSRC — `golang.org/x/crypto/ssh` (CVE-2026-39835 panic, CVE-2026-39827 memory leak, CVE-2026-39828 cert-bypass, CVE-2026-46598 agent panic), `golang.org/x/net/html` (CVE-2026-25680/25681/27136/42502/42506), `libsolv` (CVE-2026-9149 critical, CVE-2026-9150 high), OpenSSH < 10.3 (CVE-2026-35414), Poetry path traversal (CVE-2026-41140). Many ship inside container base images and IDP/control-plane components.
- 🟡 **AWARENESS:** Update fraud, AML, and identity-verification pipelines for the DentaQuest 2.6M leak. Add Nobitex, Wallex, Bitpin, Ramzinex and named executives to OFAC SDN screening. Brief help-desk and member-services teams on a 90-day uplift in DentaQuest/Sun Life/Medicaid-themed social engineering.
- 🟢 **STRATEGIC:** Adopt npm supply-chain controls beyond 2FA: block `preinstall` hooks in CI without explicit allowlist, require hardware-key publish 2FA, restrict OIDC `id-token: write` workflows to protected refs only, and add SBOM-based exposure monitoring for the @redhat-cloud-services and IronWorm package lists. The Miasma/IronWorm pair confirms TeamPCP-style worm tooling is now both open-sourced (Mini Shai-Hulud) and operationally evolving (Rust + eBPF + Tor).

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 75 reports processed across 4 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
