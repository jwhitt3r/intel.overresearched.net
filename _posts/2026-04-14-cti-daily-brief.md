---
layout: post
title:  "CTI Daily Brief: 2026-04-14 — 15 Critical CVEs in OSS Crypto/Runtime Libraries; Signed Adware Killing AV; Trust Wallet Drainer Campaign"
date:   2026-04-15 20:10:00 +0000
description: "15 critical CVEs disclosed across wolfSSL, XZ Utils, Go runtime, libinput and Handlebars.js; Huntress exposes signed 'Dragon Boss Solutions' adware disabling AV on 23,500 hosts; AlienVault flags NWHStealer and Trust Wallet QR phishing drainer; AI workflow automation (n8n) abuse trending as a new attack surface."
category: daily
tags: [cti, daily-brief, coinbase-cartel, dragonforce, qilin, the-gentlemen, nwhstealer, cve-2026-5501, cve-2026-5460, wolfssl]
classification: TLP:CLEAR
reporting_period: "2026-04-14"
generated: "2026-04-15"
severity: critical
draft: true
report_count: 147
sources:
  - Microsoft
  - RansomLock
  - AlienVault
  - BleepingComputer
  - Sysdig
  - Schneier
  - SANS
  - RecordedFutures
  - Wired Security
  - Cisco Talos
---
| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-04-14 (24h) | TLP:CLEAR | 2026-04-15 |

## 1. Executive Summary

The pipeline processed 147 reports across 14 sources in the last 24 hours, dominated by 80 Microsoft MSRC vulnerability advisories and 36 RansomLock leak-site posts. Fifteen items are rated critical, all of them CVE disclosures in widely deployed open-source libraries — notably wolfSSL (three flaws including X.509 chain-validation bypass CVE-2026-5501 and TLS 1.3 heap UAF CVE-2026-5460), XZ Utils (CVE-2026-34743), the Go standard library and runtime, libinput (lua bytecode RCE CVE-2026-35093), and Handlebars.js. BleepingComputer reports that Huntress has disrupted a signed adware operation from "Dragon Boss Solutions LLC" that used Advanced Installer update logic to drop a SYSTEM-level antivirus killer (ClockRemoval.ps1) onto 23,500+ hosts across 124 countries, including education, government, utilities and healthcare. AlienVault pulses flag an active Trust Wallet QR-code drainer campaign abusing ERC-20 `approve()` to grant unlimited USDT allowance, and a widely distributed Windows infostealer tracked as NWHStealer using fake Proton VPN sites and gaming mods. Ransomware leak activity remains high, with Coinbase Cartel, Qilin, DragonForce and The Gentlemen each posting multiple new victims; no confirmed CISA KEV additions appeared in the period.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 15 | wolfSSL X.509/TLS1.3/AES-GCM flaws; XZ Utils buffer overflow; Go runtime Root.Chmod/FileInfo escapes; libinput lua RCE; Handlebars.js injection |
| 🟠 **HIGH** | 86 | Signed adware AV-killer (Huntress); NWHStealer; Trust Wallet QR drainer; fake YouTube copyright phishing; Coinbase Cartel / Qilin / The Gentlemen / DragonForce leak posts |
| 🟡 **MEDIUM** | 27 | Secondary Microsoft MSRC advisories; leak-site commentary |
| 🟢 **LOW** | 6 | Minor leak-site entries |
| 🔵 **INFO** | 13 | Source context and low-confidence feeds |

## 3. Priority Intelligence Items

### 3.1 wolfSSL — Three Critical Flaws Enable Forged Certificates, Auth Bypass and TLS 1.3 Memory Corruption

**Source:** [Microsoft MSRC — CVE-2026-5501](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-5501), [CVE-2026-5460](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-5460), [CVE-2026-5500](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-5500), [CVE-2026-5477](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-5477), [CVE-2026-5447](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-5447), [CVE-2026-5264](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-5264)

A cluster of critical disclosures hit wolfSSL in the period. **CVE-2026-5501** is an improper X.509 chain signature-verification flaw that allows an attacker to present a forged leaf certificate and impersonate TLS endpoints (MITM). **CVE-2026-5460** is a heap use-after-free in the TLS 1.3 PQC Hybrid KeyShare error-cleanup path that can lead to memory corruption and potential RCE during handshake error conditions. **CVE-2026-5500** enables authentication bypass via improper AES-GCM tag-length validation in PKCS#7. **CVE-2026-5477** is a prefix-substitution forgery via integer overflow in wolfCrypt CMAC; **CVE-2026-5447** is a heap buffer overflow in `CertFromX509()` via `AuthorityKeyIdentifier`; **CVE-2026-5264** is a DTLS 1.3 ACK heap buffer overflow. wolfSSL is widely embedded in IoT, automotive, industrial and networking equipment where patching is slow — cross-reference with the batch 70 "state-sponsored targeting of critical infrastructure" trend which explicitly cites CVE-2026-5460 as evidence.

ATT&CK: T1190 (Exploit Public-Facing Application), T1557 (Adversary-in-the-Middle).

> **SOC Action:** Inventory all wolfSSL deployments (including OEM firmware and embedded Linux images) with SBOM tooling; track wolfSSL vendor advisories and apply the release that rolls up 5501/5500/5477/5460/5447/5264. Where patching is not feasible (IoT/OT), enforce mutual TLS with pinned CA chains and disable TLS 1.3 PQC hybrid key shares on exposed services until patched.

### 3.2 XZ Utils, Go Runtime, libinput, Handlebars.js — Supply-Chain Critical CVEs

**Source:** [CVE-2026-34743 — XZ Utils](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-34743), [CVE-2026-32282 — Go Root.Chmod](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-32282), [CVE-2026-27139 — Go FileInfo Root escape](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-27139), [CVE-2026-27144 — Go CONVNOP miscompile](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-27144), [CVE-2026-33056 — tar-rs chmod via symlink](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-33056), [CVE-2026-35093 — libinput](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-35093), [CVE-2026-33940 — Handlebars.js](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-33940), [CVE-2026-31789 — hex conversion heap overflow](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-31789), [CVE-2026-4739 — ITK integer overflows](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-4739)

Nine additional critical advisories concentrate in the OSS build/runtime supply chain. **CVE-2026-34743** is a buffer overflow in `lzma_index_append()` in XZ Utils enabling arbitrary code execution at the privilege level of the decoding process. Two Go standard-library flaws (**CVE-2026-32282** `Root.Chmod` TOCTOU, **CVE-2026-27139** `FileInfo` Root escape) allow privilege-escalation or root escape on Linux; **CVE-2026-27144** is a compiler miscompilation that can corrupt memory in CONVNOP-wrapped array copies. **CVE-2026-33056** lets the Rust `tar-rs` crate `chmod` arbitrary directories by following attacker-controlled symlinks during unpack. **CVE-2026-35093** in libinput allows unauthorised code execution via malicious lua bytecode plugins, and **CVE-2026-33940** (Handlebars.js) allows JavaScript injection via AST type confusion on dynamic partials. The batch 70 correlation engine linked libinput and a libpng ARM NEON out-of-bounds-read advisory (CVE-2026-33636) through shared T1064 scripting behaviour.

ATT&CK: T1059 (Command and Scripting Interpreter), T1064 (Scripting), T1190.

> **SOC Action:** Rebuild and redeploy container images and CI pipelines using pinned upstream releases; re-scan SBOMs for xz-utils ≤ current, Go toolchain ≤ patched, Rust `tar-rs`, libinput, handlebars and libpng. Block untrusted tar archives from being unpacked by automation and restrict where Handlebars accepts user-supplied partial names.

### 3.3 Huntress — Signed "Dragon Boss Solutions" Adware Deploys SYSTEM-Level Antivirus Killer on 23,500 Hosts

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/signed-software-abused-to-deploy-antivirus-killing-scripts/)

Huntress detailed a campaign, first observed on 22 March 2026, in which digitally signed executables from "Dragon Boss Solutions LLC" (Chromstera, Chromnius, WorldWideWeb, Web Genius, Artificius Browser) abuse the commercial Advanced Installer update mechanism to silently deliver an MSI disguised as a GIF. The MSI runs reconnaissance (admin check, VM detection, AV enumeration for Malwarebytes, Kaspersky, McAfee, ESET) and drops `ClockRemoval.ps1`, which runs at boot, logon and every 30 minutes to stop services, kill processes, delete installation directories and registry entries, silently invoke vendor uninstallers, then null-route vendor update domains via the hosts file. Installers for Opera, Chrome, Firefox and Edge are also targeted. Huntress observed 23,500 infected hosts across 124 countries in a single day, including hosts in education, utilities, government and healthcare. Only five AV vendors on VirusTotal flag the MSI payload at disclosure time.

ATT&CK: T1562.001 (Impair Defenses: Disable or Modify Tools), T1070.004 (File Deletion), T1097.002 (Impair Defenses: Host-Based Firewall), T1082, T1565 (Service Stop), T1553.002 (Subvert Trust Controls: Code Signing).

> **SOC Action:** Block execution of any code signed by "Dragon Boss Solutions LLC" via WDAC/AppLocker publisher rules; hunt EDR for `ClockRemoval.ps1`, for MSI execution of `Setup.msi` extracted from GIF files, and for Advanced Installer update processes writing to `%ProgramData%` outside expected publishers. Audit `%SystemRoot%\System32\drivers\etc\hosts` for null-routed Malwarebytes/Kaspersky/McAfee/ESET update domains. Consider publishing-cert revocation requests via DigiCert/Entrust abuse channels.

### 3.4 AlienVault — Trust Wallet QR-Code Drainer Grants Unlimited USDT `approve()`

**Source:** [AlienVault OTX Pulse](https://otx.alienvault.com/pulse/69dfc7dfb590f3df513f5fee)

An active campaign distributes malicious QR codes via Telegram that chain through Trust Wallet deep links (`link.trustwallet.com/open_url?coin_id=60&url=…`) to Netlify-hosted phishing sites. Pages emulate a legitimate USDT transfer UI but covertly trigger an ERC-20 `approve()` transaction granting unlimited allowance to an attacker-controlled contract on BNB Smart Chain, enabling persistent drainage. The drainer is modular (`config.js` + `main.js`) with a Telegram-bot C2 for real-time transaction monitoring; analysts observed 52 transaction notifications confirming live exploitation. The report shows "Drainer-as-a-Service" tradecraft with multiple cloned phishing domains.

#### Indicators of Compromise

```
URL:    hxxps[:]//swift-wallat-usdt-send[.]netlify[.]app
URL:    hxxps[:]//send-usdt-09-admin[.]netlify[.]app
URL:    hxxps[:]//link[.]trustwallet[.]com/open_url?coin_id=60&url=hxxps[:]//swift-wallat-usdt-send[.]netlify[.]app
```

ATT&CK: T1566.002 (Spearphishing Link), T1204.002 (User Execution: Malicious File), T1528 (Steal Application Access Token), T1583.006 (Acquire Infrastructure: Web Services).

> **SOC Action:** Block `*.netlify.app` drainer domains listed above at secure web gateway and DNS; add URL-filtering rules for `link.trustwallet.com/open_url?...netlify.app`. Advise crypto-handling staff to review and revoke outstanding ERC-20 token approvals via `revoke.cash` or equivalent for any wallet that scanned a Telegram-sourced QR code.

### 3.5 AlienVault / Malwarebytes — NWHStealer Spreading via Fake Proton VPN, Hardware Utilities, Gaming Mods

**Source:** [AlienVault / Security Boulevard](https://securityboulevard.com/2026/04/from-fake-proton-vpn-sites-to-gaming-mods-this-windows-infostealer-is-everywhere/)

Malwarebytes documented a wide-reach Windows infostealer tracked as **NWHStealer** distributed via fake Proton VPN sites, hardware-utility lures (OhmGraphite, Pachtop, HardwareVisualizer, Sidebar Diagnostics), mining software, game cheats/mods (e.g. Xeno), and hosted on GitHub, GitLab, MediaFire, SourceForge and onworks[.]net. Execution chains include self-injection, RegAsm process injection, and DLL hijacking (malicious `WindowsCodecs.dll` alongside a renamed WinRAR binary). The loader uses AES-CBC via BCrypt APIs and resolves imports dynamically to evade static analysis; it steals browser data, saved credentials and cryptocurrency wallets.

#### Indicators of Compromise

```
Domain: get-proton-vpn[.]com
Domain: vpn-proton-setup[.]com
Domain: newworld-helloworld[.]icu
URL:    hxxps[:]//www[.]onworks[.]net/software/windows/app-hardware-visualizer
SHA256: 2494709b8a2646640b08b1d5d75b6bfb3167540ed4acdb55ded050f6df9c53b3
SHA256: e97cb6cbcf2583fe4d8dcabd70d3f67f6cc977fc9a8cbb42f8a2284efe24a1e3
```

ATT&CK: T1566 (Phishing), T1204 (User Execution), T1055.012 (Process Hollowing), T1574.002 (DLL Side-Loading), T1555.003 (Credentials from Web Browsers).

> **SOC Action:** Block the domains above and alert on the hashes in EDR/SWG; hunt for `RegAsm.exe` child processes with outbound TLS to uncategorised hosts and for `WindowsCodecs.dll` loaded from user-writeable paths next to a renamed WinRAR binary. Remind users that Proton VPN is only distributed from `proton.me`.

### 3.6 AlienVault / Malwarebytes — Fake YouTube Copyright-Strike Phishing → Google Account Takeover

**Source:** [AlienVault / Security Boulevard](https://securityboulevard.com/2026/04/fake-youtube-copyright-notices-can-steal-your-google-login/)

Phishing kit hosted at `dmca-notification[.]info` scrapes real YouTube channel metadata (avatar, subscriber count, latest video title/thumbnail, timestamps) to personalise fake copyright-strike notices and pressure creators to "Login via Google". Successful takeovers yield full Google account control (Gmail, Drive, Payments) plus the YouTube channel, which operators typically rebrand as a cryptocurrency livestream scam. A `suppressTelegramVisit` flag in the source code points to Telegram-based affiliate traffic coordination; the kit appears operated as a franchise with multiple affiliates.

#### Indicators of Compromise

```
Domain: dmca-notification[.]info
Domain: blacklivesmattergood4[.]com
Domain: dopozj[.]net
Domain: ec40pr[.]net
Domain: xddlov[.]net
```

ATT&CK: T1566.002 (Spearphishing Link), T1056.003 (Web Portal Capture), T1078.004 (Cloud Accounts).

> **SOC Action:** Block the domains at SWG/DNS; for corporate creators and social-media teams, enforce hardware-key (FIDO2) MFA on Google Workspace accounts and add conditional-access rules to require re-auth on suspicious geographies. Brief comms/PR teams that "YouTube copyright strike" emails are an active pretext.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Rise of AI-driven cyber threats and misuse of workflow automation platforms | "The n8n n8mare: How threat actors are misusing AI workflow automation"; Trust Wallet USDT drainer campaign (batch 70) |
| 🔴 **CRITICAL** | Persistent ransomware activity by groups such as DragonForce targeting multiple sectors | Curtis Design Group; McCOR; bela-pharm (all tagged `dragonforce`) (batch 69) |
| 🟠 **HIGH** | Targeting of critical infrastructure by state-sponsored and pro-state hacker groups | Sweden reports pro-Russian attempt to breach thermal power plant; wolfSSL TLS 1.3 UAF (CVE-2026-5460) (batch 70) |
| 🟠 **HIGH** | Increased exploitation of vulnerabilities in software development tools and libraries | CVE-2026-27140 (Go SWIG codegen RCE); CVE-2026-27143 (Go bound-check memory corruption) (batch 70) |
| 🟠 **HIGH** | Increased exploitation of vulnerabilities in libraries like libpng and Axios | CVE-2026-34757 (libpng UAF); CVE-2025-62718 (Axios NO_PROXY SSRF) (batch 69) |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors
- **Qilin** (54 reports) — active RaaS operator posting new victims in the period (e.g., "Limkon By qilin")
- **The Gentlemen** (48 reports) — multi-sector leak-site actor; batch 70 correlated pharma, precision engineering, consulting, wine and dairy victims
- **nightspire** (37 reports) — persistent leak-site activity
- **TeamPCP** (32 reports) — linked to the LiteLLM/Trivy campaign (S&P Global, guesty)
- **DragonForce / dragonforce** (27 + 24 reports) — critical-trend-cited RaaS hitting retail and manufacturing
- **Coinbase Cartel** (26 reports) — high-volume leak-site actor posting across finance, fashion, tech, logistics
- **Akira** (22 reports) — continuing operations

### Malware Families
- **RansomLock** (36 reports) — umbrella tag for ransomware leak-site content
- **DragonForce ransomware** (26 + 9 reports) — most-reported named family
- **Akira ransomware** (18 reports)
- **Tox1** (10 reports)
- **PLAY ransomware** (8 reports)
- **Gentlemen ransomware** (7 reports)
- **NWHStealer** (new, high-severity infostealer documented today)

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| Microsoft (MSRC) | 80 | [msrc.microsoft.com](https://msrc.microsoft.com/update-guide/) | All 15 critical CVE advisories (wolfSSL, XZ Utils, Go, libinput, Handlebars.js, ITK, tar-rs) |
| RansomLock | 36 | [ransomlook.io](https://www.ransomlook.io/) | Leak-site telemetry; Coinbase Cartel, Qilin, DragonForce, The Gentlemen, payoutsking, interlock, shadowbyt3$ postings |
| AlienVault | 7 | [otx.alienvault.com](https://otx.alienvault.com/) | Trust Wallet drainer; NWHStealer; fake YouTube copyright phishing |
| BleepingComputer | 6 | [bleepingcomputer.com](https://www.bleepingcomputer.com/) | Signed-adware AV killer; Microsoft Zero Day Quest $2.3M payout |
| Unknown | 5 | — | Low-confidence or unattributed feeds |
| Sysdig | 2 | [sysdig.com](https://sysdig.com/blog/) | Cloud/container threat research |
| Schneier | 2 | [schneier.com](https://www.schneier.com/) | Commentary |
| SANS ISC | 2 | [isc.sans.edu](https://isc.sans.edu/) | Diary posts |
| RecordedFutures | 2 | [therecord.media](https://therecord.media/) | Threat news |
| Wired Security | 1 | [wired.com/category/security](https://www.wired.com/category/security/) | Feature reporting |
| Upwind | 1 | [upwind.io](https://www.upwind.io/blog) | Cloud security |
| RedCanary | 1 | [redcanary.com](https://redcanary.com/blog/) | Detection research |
| Wiz | 1 | [wiz.io](https://www.wiz.io/blog) | Cloud security |
| Cisco Talos | 1 | [blog.talosintelligence.com](https://blog.talosintelligence.com/) | Threat research |

No Telegram-origin URLs were surfaced as primary sources in this period; any Telegram-adjacent intelligence (e.g., the Trust Wallet drainer's Telegram C2) is noted in-body without linking.

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Patch and redeploy wolfSSL across TLS-terminating services and embedded firmware to address CVE-2026-5501 / 5500 / 5477 / 5460 / 5447 / 5264; prioritise internet-facing endpoints and any CI where wolfSSL is statically linked. Until patched, disable TLS 1.3 PQC hybrid key shares on exposed services.
- 🔴 **IMMEDIATE:** Roll out WDAC/AppLocker publisher blocks for "Dragon Boss Solutions LLC" and hunt for `ClockRemoval.ps1`, Setup.msi-from-GIF execution, and Malwarebytes/Kaspersky/McAfee/ESET domains null-routed via `hosts`. Re-enable and verify AV agents on any detected host.
- 🟠 **SHORT-TERM:** Rebuild CI images and container bases against patched XZ Utils, Go toolchain, Rust `tar-rs`, libinput, Handlebars.js and libpng; re-scan SBOMs and surface any downstream artefacts still shipping vulnerable versions.
- 🟠 **SHORT-TERM:** Block the NWHStealer, Trust Wallet drainer, and fake-YouTube-copyright domains listed in Section 3 at secure web gateway and DNS; add the SHA-256 hashes to EDR deny-lists.
- 🟡 **AWARENESS:** Brief finance/crypto and social-media/creator teams on the Trust Wallet `approve()` drainer and the YouTube copyright-strike phishing kit; recommend FIDO2 hardware-key MFA for any Google Workspace account that administers customer-facing channels.
- 🟢 **STRATEGIC:** Add AI-workflow automation platforms (n8n and equivalents) to the enterprise SaaS risk register in response to the batch-70 critical trend on misuse of workflow automation; require SSO, audit logging and egress restrictions on any self-hosted n8n instance.

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 147 reports processed across 4 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
