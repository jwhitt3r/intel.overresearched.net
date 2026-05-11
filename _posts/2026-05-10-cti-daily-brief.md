---
layout: post
title:  "CTI Daily Brief: 2026-05-10 — Mr_Rot13 weaponises critical cPanel flaw (CVE-2026-41940); ShinyHunters extort Instructure via Canvas XSS; Linux 'Dirty Frag' container-escape exploit goes public"
date:   2026-05-11 20:06:39 +0000
description: "Mr_Rot13 (a six-year-old crew) actively exploits CVE-2026-41940 in cPanel with Telegram exfiltration; ShinyHunters re-breach Instructure Canvas to extort schools; Linux 'Dirty Frag' (CVE-2026-43284/-43500) has a working public exploit with no patch; TrickMo Android banker pivots its C2 onto the TON blockchain; Google GTIG reports the first observed AI-developed zero-day exploit."
category: daily
tags: [cti, daily-brief, mr-rot13, shinyhunters, trickmo, cve-2026-41940, cve-2026-43284]
classification: TLP:CLEAR
reporting_period: "2026-05-10"
generated: "2026-05-11"
draft: true
severity: critical
report_count: 84
sources:
  - Microsoft
  - BleepingComputer
  - AlienVault
  - RecordedFutures
  - SANS
  - Schneier
  - Wiz
  - RansomLook
  - BellingCat
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-05-10 (24h) | TLP:CLEAR | 2026-05-11 |

## 1. Executive Summary

The pipeline processed **84 reports across 10 sources** in the last 24 hours, with the day's signal dominated by active in-the-wild exploitation of public-facing infrastructure. Three items stand out: AlienVault/XLab attributed a six-year-old, low-detection threat cluster ("Mr_Rot13") to mass exploitation of the critical cPanel/WHM auth-bypass **CVE-2026-41940** (CVSS 9.8), deploying SSH backdoors and the Filemanager RAT against Southeast Asian servers; BleepingComputer confirmed **ShinyHunters** re-breached Instructure's Canvas LMS via stored-XSS, defacing 8,800+ school portals with a May 12 extortion deadline; and RecordedFuture disclosed a working public exploit for "**Dirty Frag**" (**CVE-2026-43284 / CVE-2026-43500**) — a Linux-kernel container-escape with no upstream patch after an embargo break. Google GTIG also reported the first observed AI-developed zero-day exploit (against an unnamed open-source web admin tool), and ThreatFabric flagged a TrickMo Android-banker variant moving C2 onto the TON blockchain to evade DNS-based takedowns. No CISA KEV additions appeared in this reporting window.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 3 | Mr_Rot13 cPanel exploitation (CVE-2026-41940); multiple Devs Palace ERP Online CVEs |
| 🟠 **HIGH** | 25 | Instructure/Canvas ShinyHunters extortion; Dirty Frag Linux kernel chain; TrickMo TON-based C2; Google AI-developed 0-day; Cl0p / South Staffordshire Water ICO fine; DDoS botnet via Jenkins scriptText |
| 🟡 **MEDIUM** | 34 | Microsoft-published Linux/AMDGPU/btrfs/kernel kfunc patches; AD breach hygiene guidance |
| 🟢 **LOW** | 10 | Lower-impact kernel hardening, miscellaneous patches |
| 🔵 **INFO** | 12 | Background advisories, vendor blog content |

## 3. Priority Intelligence Items

### 3.1 Mr_Rot13 actively exploits critical cPanel CVE-2026-41940 to deploy Filemanager RAT and SSH backdoors

**Source:** [AlienVault / XLab](https://blog.xlab.qianxin.com/mr_rot13-the-elusive-6-year-hacker-group-weaponizing-critical-cpanel-flaws-for-backdoor-deployment_cn/)

XLab attributed a previously-unnamed threat cluster — internally tracked as **Mr_Rot13** — to ongoing mass exploitation of **CVE-2026-41940**, an unauthenticated authentication-bypass in cPanel & WHM rated CVSS 9.8. Public disclosure on 28 April 2026 was followed by automated weaponisation from more than 2,000 attacking IPs (concentrated in DE/US/BR/NL). On 2 May, the actor breached a Southeast Asian government/military target and exfiltrated ~4.37 GB of files dated 2020–2024. Mr_Rot13's "Payload" infector (Go, statically linked, AI-generated logging in Turkish) overwrites the root password, plants an attacker SSH key (`ssh-ed25519 …cpanel-updater`), installs a Python webshell at `/usr/local/cpanel/cgi-sys/cpanel.py`, injects credential-stealing JS into Canvas/Cpanel login templates (ROT13-obfuscated C2), and finally deploys the cross-platform **Filemanager** RAT via `install.sh` from `wpsock[.]com`. Sensitive data and stolen creds are exfiltrated both to attacker HTTP collectors and to a Telegram bot (`log_FatherBot`, group `-443071772`). Affiliated infrastructure has been operational since at least 2020 at consistently near-zero AV detection. MITRE techniques observed: **T1190, T1505.003, T1136, T1098, T1078, T1219, T1027, T1071.001, T1567.002, T1041**.

**Affected:** Linux servers running cPanel/WHM (unpatched against CVE-2026-41940); heavy weighting toward Southeast Asian hosting and government tenants; secondary impact on WordPress sites colocated on compromised cPanel hosts.

#### Indicators of Compromise

```
Downloader URL:  hxxps[:]//cp.dene.de[.]com/Update
Webshell URL:    hxxps[:]//cp.dene.de[.]com/cpanel.py
Filemanager:     hxxps[:]//wpsock[.]com/cpanel/install.sh
Exfil HTTP:      hxxps[:]//cp.dene.de[.]com/collect.php
Credential exfil (ROT13-decoded): hxxps[:]//wrned[.]com/log[.]php?t=3
Domains:         cp.dene.de[.]com, wpsock[.]com, wrned[.]com
SHA-256:         b750c4ac80dcc6e382f3e81fdba843704038a4106d610244d725c8b654e7fde2
MD5 (Update):    fb1bc3f935fdeb3555465070ba2db33c
SSH key planted: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFIswJUfqrkbm2sIMfNHZn1sOYkxjNzEynqJKFU7qoez cpanel-updater
Root password set: root:123Qwe123C
Telegram exfil:  bot 1190043163 (token rotated), group -443071772
```

> **SOC Action:** Patch cPanel & WHM to the post-CVE-2026-41940 build immediately; audit `/root/.ssh/authorized_keys` for the `cpanel-updater` ed25519 key and remove if unrecognised; check `/usr/local/cpanel/cgi-sys/cpanel.py` and `/usr/local/cpanel/base/unprotected/cpanel/login.{js,tmpl}` for unexpected content; block egress to `cp.dene.de[.]com`, `wpsock[.]com`, `wrned[.]com` and to `api.telegram.org` from web-server segments; hunt EDR for outbound POSTs to `/collect.php`. Rotate all cPanel/WHM credentials and SSH keys on systems exposed between 28 April and patch date.

### 3.2 ShinyHunters re-breach Instructure Canvas via XSS and deface 8,800+ school portals

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/instructure-confirms-hackers-used-canvas-flaw-to-deface-portals/)

Instructure confirmed that **ShinyHunters** used multiple stored cross-site-scripting flaws in Canvas LMS's Free-for-Teacher environment to hijack authenticated admin sessions and deface login portals — including the University of Texas San Antonio — with a ransom message demanding negotiation by **12 May 2026**. The May 7 defacement followed an initial 29 April network intrusion in which the actor claims to have exfiltrated ~3.6 TB / 275 million records spanning 8,809 educational organisations. Instructure took the Free-for-Teacher tier offline and restored Canvas on 9 May after deploying additional safeguards. The correlation engine grouped this with the "Inside a phishing panel" report (`9c0939960e…`, `cb1d409278…` SHA-256s) and confirmed the actor's continued reliance on **adversary-in-the-middle phishing panels** with Okta-themed bait domains for identity-provider compromise. MITRE: **T1566, T1078**.

**Affected:** K-12 and higher-education institutions using Canvas LMS; downstream identity-provider tenants accessible via stolen Canvas admin sessions.

#### Indicators of Compromise

```
Threat actor: ShinyHunters (also tracked BlackFile / UNC6240 / UNC6661 / UNC6671)
Phishing-panel related SHA-256s (from correlated Push Security report):
  8a01bcb70ec1c101a163c9cb8e074781c1322096f7ae01789f02252854def44c
  9c0939960e49122196e44b6779fe55dd7a13ab437ce251c8cf35f8c6daf8be21
  9d65dd34384b441505e6b67647153c02d5c367bb53da36ce36a392e70b37940a
  c0df36ccf88d5c8434b13b58f7a55a9715643a126148b9d078a93075d09cad26
  cb1d409278b2247af23e7b00ac779b232baaf4ce5f63fdf5ebc3920a38cc6102
Okta-themed phishing domains (sample):
  addoktapasskey[.]com, keyokta[.]com, passkeyportalsetup[.]com,
  passkeysetup[.]com, passkeywork[.]com, enrollms[.]com,
  amazoninternal[.]com, mydropboxinternal[.]com, mysonossso[.]com,
  mydisneysso[.]com, epicgamessso[.]com, myadyeninternal[.]com,
  myxerointernal[.]com, sonosinternal[.]com
```

> **SOC Action:** If your institution uses Canvas Free-for-Teacher, force-reset all admin sessions and rotate API tokens; review Canvas audit logs for unsanctioned JavaScript in user-generated content fields; block and sinkhole the listed ShinyHunters bait domains at egress and DNS; alert helpdesk to refuse password-reset / MFA-enrolment requests originating from inbound voice calls (vishing precursor); enforce phishing-resistant MFA (FIDO2/passkey) on identity-provider accounts and disable any legacy push-notification MFA still in use.

### 3.3 "Dirty Frag" Linux kernel chain (CVE-2026-43284 / CVE-2026-43500) — public exploit, no upstream patch

**Source:** [Recorded Future News](https://therecord.media/dirty-frag-linux-kernel-hit-by-second-major-bug)

Researcher Hyunwoo Kim published a full write-up and working PoC after a coordinated disclosure embargo collapsed on 7 May: an unrelated third party leaked the exploit early. **Dirty Frag** chains two networking-stack flaws (**CVE-2026-43284** and **CVE-2026-43500**) to allow any local user to escalate to root and to escape containers — the second such kernel break in two weeks following the related "Copy Fail" issue. Red Hat rated both as Important and shipped patches for supported RHEL streams; AlmaLinux and Ubuntu published mitigations by 8 May; SUSE, Debian, Fedora and Amazon Linux acknowledged with patches in progress. Because the technique corrupts memory-resident file copies without touching disk, standard host-based monitoring may miss it. The correlation engine linked Dirty Frag to the cloud-computing sector and to a corresponding btrfs-area CVE batch in the Microsoft-published Linux series. MITRE: **T1068, T1597**.

**Affected:** All current Linux distributions in the kernel networking code path; particularly acute for multi-tenant Kubernetes / container hosts and any shared-cloud Linux estate.

> **SOC Action:** Apply distro vendor patches for CVE-2026-43284 / CVE-2026-43500 across all Linux hosts within the next 24–48 hours, prioritising Kubernetes worker nodes and shared-tenancy hypervisors; where patches are not yet available (SUSE, Debian, Fedora, Amazon Linux), enforce seccomp / AppArmor profiles that restrict unprivileged user namespaces (`kernel.unprivileged_userns_clone=0`); deploy Falco/Tetragon rules to flag unexpected container-namespace transitions and uid-0 escalations from non-root pods.

### 3.4 TrickMo Android banker pivots C2 onto the TON blockchain

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/trickmo-android-banker-adopts-ton-blockchain-for-covert-comms/), [AlienVault / ThreatFabric](https://otx.alienvault.com/pulse/6a019c5f0a3344d92c4302a3)

ThreatFabric ('Trickmo.C') reports a substantive redesign of the TrickMo Android banking trojan: command-and-control has been moved off public DNS onto **The Open Network (TON)** using 256-bit `.adnl` identifiers routed through an embedded local TON proxy on the infected device. Active campaigns target banking and crypto-wallet users in France, Italy and Austria via TikTok and streaming-app lookalikes. Existing capabilities — phishing overlays, keylogging, screen recording, SMS/OTP interception, clipboard takeover, notification filtering — are now extended with `curl`, `dnsLookup`, `ping`, `telnet`, `traceroute`, **SSH tunnelling**, local/remote port-forwarding and authenticated SOCKS5 proxy support, turning compromised handsets into programmable network pivots and proxy exit nodes that defeat IP-based fraud telemetry. Traditional DNS-based takedowns are ineffective. MITRE: **T1566, T1090, T1021, T1078.004**.

**Affected:** Android banking/fintech/wallet users in EU (France, Italy, Austria); fraud teams reliant on IP/ASN reputation; corporate networks accessed by users' BYOD Android devices.

#### Indicators of Compromise

```
SHA-256:
  01889a9ec2abecb73e5e8792be68a4e3bc7dcbe1c3f19ac06763682d63aa8c21
  143c0e12d2aa1bdecde59f273139dd5605d00f61cda7f626224e07390119c026
  177ef86c57c31b29850227dbc8288b735bea977587f2f0a49cfc4089a644a2c4
  4cd8635062ff6b0885216a0b1658ebcb2938b670f7ac08ecb0b5fb85d8973ea0
  749bbcbc3e5d2d524344d52b6471dfa7b8d3ecdeb0b11ab82c843d497a056c8f
  e2e218ddf698b4c0099fd2a9619d6912a71f75beb51669a4e3ae4fc71f745d03
C2 transport: TON .adnl overlay (no observable public domains/IPs)
```

> **SOC Action:** Update mobile-threat-defence signatures to detect Trickmo.C hashes; for managed Android estates, alert on installations of TikTok / streaming-app sideloads outside Google Play and on any user-granted Accessibility-service permission to a freshly installed app; review fraud rules to deprioritise IP/ASN reputation as a sole trust signal for high-value EU banking sessions and add device-binding / hardware-attestation checks; block outbound TON traffic from corporate Wi-Fi where business need is absent.

### 3.5 Google GTIG: first observed AI-developed zero-day exploit; AI-assisted operations expand across nation-state actors

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/google-hackers-used-ai-to-develop-zero-day-exploit-for-web-admin-tool/)

Google Threat Intelligence Group disclosed that a 2FA-bypassing zero-day against an unnamed open-source web-administration tool was, with high confidence, generated by a large language model — the Python exploit shipped with educational docstrings, a hallucinated CVSS score and "textbook" structure characteristic of LLM training data, and exploited a high-level semantic logic bug of the type AI excels at finding. GTIG rules out Gemini and notes that **APT27, APT45, UNC2814, UNC5673 and UNC6201** (Chinese and North Korean clusters) are using AI for vulnerability discovery, that Russia-linked actors are obfuscating **CANFAIL** and **LONGSTREAM** with AI-generated decoy code, and that the **PromptSpy** Android backdoor now integrates a Gemini-API "GeminiAutomationAgent" module with a hard-coded jailbreak prompt to drive UI automation and replay screen-lock authentication. Threat actors are also industrialising premium-LLM access via account-pooling and proxy infrastructure. MITRE: **T1566**.

**Affected:** Operators of open-source web-administration tooling (specific product not disclosed by Google); Android handsets infected by PromptSpy; defenders' assumption sets about LLM safety controls.

> **SOC Action:** Treat any newly disclosed semantic-logic-bug CVE as having materially shorter window-to-weaponisation; prioritise patching on web admin consoles even without observed in-the-wild exploitation; for managed Android, alert on apps requesting both Accessibility-service and Gemini API access; verify that DLP and CASB policies cover paid LLM endpoints (account-pooling abuse surfaces as inbound API authentications from unfamiliar regions); review egress logs for high-volume API traffic to public LLM providers from non-development hosts.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Rising ransomware and malware activity targeting critical infrastructure (government, technology) | Mr_Rot13 cPanel exploitation of SE-Asian government servers; CVE-2024-26914 (AMD/DRM kernel batch) |
| 🔴 **CRITICAL** | Multiple critical CVEs in Devs Palace ERP Online ≤4.0.0 indicate a systemic product issue | Series of single-source TLP:AMBER+STRICT advisories (CVE-2026-8253/8254/8262 and earlier 8220/8221) (Telegram-sourced; channel redacted) |
| 🟠 **HIGH** | Increased targeting of educational institutions via phishing and stored-XSS exploitation | Instructure Canvas defacement; correlated Push Security technical advisory on the same breach |
| 🟠 **HIGH** | Abuse of cloud-native infrastructure for sophisticated phishing campaigns | "Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns" correlated with Mr_Rot13 obfuscation TTPs (shared T1027) |
| 🟠 **HIGH** | Same TTP cluster (T1071.001, T1078, T1190) spans LMS XSS, cPanel exploitation and AI-assisted lure factories | Correlation entries 750, 752 (confidence 0.70) |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **Qilin** (98 reports) — RaaS group, dominant pipeline-wide volume over the past 30 days.
- **The Gentlemen** (52 reports) — Active ransomware-style operator.
- **Akira** (50 reports) — RaaS with sustained intake throughout late April–early May.
- **ShinyHunters** (30 reports) — Re-engaged this period via the Instructure Canvas extortion campaign (most-recent last_seen).
- **DragonForce** (30 reports) — Continuing leak-site activity.
- **Coinbase Cartel** (26 reports) — Mid-April surge; activity quiet since 23 April.
- **Inc Ransom** (22 reports) — Multi-sector targeting (legal, technology, healthcare).
- **Lamashtu** (22 reports) — Persistent extortion-site presence.
- **Everest** (22 reports) — Ongoing data-leak operations.
- **TeamPCP** (18 reports) — Sustained low-volume activity.

### Malware Families

- **RansomLook** (90 reports) — Tracker-level signal (group/site enumeration).
- **RansomLock** (36 reports) — RaaS double-extortion brand; AiLock variant observed this period using ChaCha20 + NTRUEncrypt and `.AiLock` extension.
- **Tox1 / Tox** (33 / 16 reports) — Multi-platform tooling thread.
- **Akira ransomware / Akira / Akira Ransomware** (26 / 14 / 11 reports) — Dominant non-RansomLook family by volume.
- **RaaS** (18 reports) — Generic affiliate-model tagging.
- **Qilin** (13 reports) — Linked to the dominant threat actor of the same name.

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| Microsoft | 55 | [link](https://msrc.microsoft.com/update-guide) | MSRC Linux/kernel CVE batch (kfunc, bpf, drm/amdgpu, btrfs, ksmbd, .NET DoS CVE-2026-32226). |
| Unknown / OSINT | 9 | — | Telegram-sourced advisories (channel redacted) — multiple Devs Palace ERP CVEs and breach claims. |
| BleepingComputer | 5 | [link](https://www.bleepingcomputer.com/news/security/instructure-confirms-hackers-used-canvas-flaw-to-deface-portals/) | Lead coverage of Instructure/ShinyHunters, TrickMo, Google AI-exploit story. |
| AlienVault | 5 | [link](https://blog.xlab.qianxin.com/mr_rot13-the-elusive-6-year-hacker-group-weaponizing-critical-cpanel-flaws-for-backdoor-deployment_cn/) | XLab Mr_Rot13 attribution; ThreatFabric TrickMo; Needle crypto-stealer; Jenkins-DDoS botnet. |
| SANS | 3 | [link](https://isc.sans.edu) | Background ISC diary content. |
| RecordedFutures | 3 | [link](https://therecord.media/dirty-frag-linux-kernel-hit-by-second-major-bug) | Dirty Frag kernel chain; South Staffordshire Water Cl0p ICO fine. |
| Wiz | 1 | [link](https://www.wiz.io) | Internal service-ownership/risk-reduction guidance. |
| Schneier | 1 | [link](https://www.schneier.com) | Commentary item. |
| BellingCat | 1 | [link](https://www.bellingcat.com) | OSINT-focused reporting. |
| RansomLock | 1 | [link](https://www.ransomlook.io//group/ailock) | AiLock RaaS profile (Accretech America Inc. claim). |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Patch cPanel & WHM against CVE-2026-41940 on every internet-facing instance today, hunt for the Mr_Rot13 IOCs above (planted `cpanel-updater` SSH key, `cpanel.py` webshell, traffic to `cp.dene.de[.]com` / `wpsock[.]com` / `wrned[.]com`) and rotate all cPanel/WHM and root SSH credentials. (Ref §3.1)
- 🔴 **IMMEDIATE:** Roll the available distro patches for Dirty Frag (CVE-2026-43284 / CVE-2026-43500) across the Linux estate, prioritising shared-tenancy and Kubernetes worker nodes; pre-stage namespace-restriction sysctls where patches are still pending. (Ref §3.3)
- 🟠 **SHORT-TERM:** Canvas / Free-for-Teacher tenants must force-rotate admin sessions and tokens, review LMS audit logs for injected JavaScript, and sinkhole the ShinyHunters bait-domain set; reinforce vishing-resistant helpdesk procedures and enforce FIDO2 passkeys on identity-provider admins. (Ref §3.2)
- 🟠 **SHORT-TERM:** Update mobile-threat-defence signatures for Trickmo.C, deprioritise IP/ASN reputation as a sole trust signal for EU retail-banking sessions, and add device-binding / hardware-attestation checks to fraud rules. (Ref §3.4)
- 🟡 **AWARENESS:** Brief vulnerability-management and detection-engineering teams on AI-developed exploits (per Google GTIG), and shorten patch-SLO assumptions on semantic-logic-bug CVEs in web admin tooling; verify CASB/DLP coverage of paid-LLM endpoints to detect account-pooling abuse. (Ref §3.5)
- 🟢 **STRATEGIC:** Use the South Staffordshire Water ICO finding as a board-level case study for proactive monitoring: enforce least-privilege on domain admin accounts, integrate endpoint telemetry into the SOC monitoring platform, decommission Windows Server 2003 and any other unsupported OS, and ensure ZeroLogon (CVE-2020-1472) patching is complete and verified.

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 84 reports processed across 4 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
