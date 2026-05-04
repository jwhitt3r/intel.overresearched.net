---
layout: post
title:  "CTI Weekly Brief: 27 April to 3 May 2026 - Mass cPanel exploitation, GitHub RCE, APT28 zero-day, ShinyHunters extortion wave"
date:   2026-05-04 09:00:00 +0000
description: "346 reports across 15 sources. Mass-exploited cPanel zero-day driving 'Sorry' ransomware; GitHub RCE in core git infrastructure; CISA KEV addition for APT28-exploited Windows NTLM leak; Linux 'Copy Fail' kernel LPE affects every distro since 2017; ShinyHunters claims Instructure (275M records) and Marcus & Millichap breaches."
category: weekly
tags: [cti, weekly-brief, shinyhunters, apt28, qilin, cve-2026-41940, cve-2026-3854, cve-2026-32202, cve-2026-31431, sorry-ransomware]
classification: TLP:CLEAR
reporting_period_start: "2026-04-27"
reporting_period_end: "2026-05-03"
generated: "2026-05-04"
draft: false
report_count: 346
severity: critical
sources:
  - Microsoft
  - BleepingComputer
  - RansomLock
  - Wiz
  - Unit42
  - AlienVault
  - HaveIBeenPwned
  - SANS
  - Schneier
  - CISA
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 27 April to 3 May 2026 (7d) | TLP:CLEAR | 2026-05-04 |

## 1. Executive Summary

The pipeline ingested 346 reports across 15 sources during the week of 27 April to 3 May 2026, with 20 rated critical and 209 high. The week was dominated by confirmed in-the-wild exploitation of three flagship vulnerabilities: a cPanel/WHM authentication bypass (CVE-2026-41940) being mass-exploited to deploy the new Linux-only "Sorry" ransomware on at least 44,000 IP addresses; a remote code execution flaw in GitHub's internal git infrastructure (CVE-2026-3854) that briefly exposed millions of private repositories on GitHub.com and still leaves an estimated 88% of GitHub Enterprise Server instances unpatched; and CISA's KEV addition of CVE-2026-32202, a zero-click NTLM hash leak in Windows that the Russian APT28 group is actively exploiting against Ukraine and EU targets. Wiz disclosed a universal Linux kernel local privilege escalation ("Copy Fail", CVE-2026-31431) affecting every distribution since 2017. The ShinyHunters extortion gang claimed two major data breaches — Instructure (Canvas LMS, allegedly 275 million records across ~9,000 schools) and Marcus & Millichap (1.8 million accounts) — with the AI-correlation pipeline tying both to T1190 (exploit public-facing application) and T1071.001 (web protocol C2). Ransomware operations from Qilin, Everest, m3rx, and safepay continued to drive the high-severity volume, and supply-chain pressure on the npm ecosystem intensified with two fresh Shai-Hulud-derived campaigns identified by Unit 42.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 20 | cPanel CVE-2026-41940 mass exploitation; GitHub RCE CVE-2026-3854; APT28 zero-day CVE-2026-32202; Copy Fail Linux LPE CVE-2026-31431; Chromium Skia/ANGLE batch; LiteLLM SQLi CVE-2026-42208; Apache MINA RCE CVE-2026-42779; VECT 2.0 ransomware/wiper |
| 🟠 **HIGH** | 209 | ShinyHunters / Qilin / Everest / m3rx / safepay leak-site posts; ConsentFix v3 OAuth phishing; npm Shai-Hulud follow-on campaigns; Microsoft binutils/libpng/SMB CVEs; Telegram Mini App fraud |
| 🟡 **MEDIUM** | 58 | Inc Ransom and worldleaks extortion postings; phishing kits and stealer ecosystem reporting |
| 🟢 **LOW** | 8 | Lower-confidence telemetry; minor product updates |
| 🔵 **INFO** | 51 | Source feed enrichment, advisory metadata, RansomLook infrastructure summaries |

## 3. Priority Intelligence Items

### 3.1 cPanel CVE-2026-41940 mass-exploited to deploy "Sorry" ransomware

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/critrical-cpanel-flaw-mass-exploited-in-sorry-ransomware-attacks/), [BleepingComputer (emergency advisory)](https://www.bleepingcomputer.com/news/security/cpanel-whm-emergency-update-fixes-critical-auth-bypass-bug/)

cPanel and WHM released an emergency update for an authentication-bypass zero-day (CVE-2026-41940) that has been exploited in the wild since late February. Shadowserver reports at least 44,000 cPanel-running IPs have been compromised. Operators are deploying a new Go-based Linux encryptor branded "Sorry" that appends `.sorry` to encrypted files and uses raw ChaCha20 with an embedded RSA-2048 public key — Rivitna confirms decryption is impossible without the matching RSA-2026 private key. Each victim folder receives a `README.md` ransom note pointing to a single Tox ID for negotiation. Hundreds of impacted sites are already indexed in Google. CISA added the vulnerability to its KEV catalogue with a federal patch deadline.

Affected products: cPanel and WHM (Linux web hosting control panels). Sectors: web hosting providers, SMB websites, e-commerce.

#### Indicators of Compromise

```
File extension: .sorry
Ransom note:    README.md (per-folder)
Tox ID:         3D7889AEC00F2325E1A3FBC0ACA4E521670497F11E47FDE13EADE8FED3144B5EB56D6B198724
Cipher:         ChaCha20 (stream) + RSA-2048 (key wrap)
ATT&CK:         T1203, T1486, T1566
```

> **SOC Action:** Immediately apply the cPanel/WHM emergency update on all hosted instances. Hunt for newly created admin accounts in `/var/cpanel/users/` modified after 25 February 2026, unexpected outbound traffic to Tor entry nodes, and the literal string `.sorry` in filenames across web roots. Scan exposed cPanel banners against the Shadowserver compromise feed to confirm or rule out exposure.

### 3.2 GitHub critical RCE in internal git infrastructure (CVE-2026-3854)

**Source:** [Wiz Research](https://www.wiz.io/blog/github-rce-vulnerability-cve-2026-3854), [BleepingComputer](https://www.bleepingcomputer.com/news/security/github-fixes-rce-flaw-that-gave-access-to-millions-of-private-repos/)

Wiz Research disclosed an injection flaw in GitHub's internal git protocol that allowed any authenticated user to execute arbitrary commands on backend servers via a single `git push` command. On GitHub.com, the bug exposed shared storage nodes containing millions of public and private repositories belonging to other users; Wiz confirmed cross-tenant access was possible. On GitHub Enterprise Server (GHES), the same flaw grants full server compromise including all hosted repositories and internal secrets. GitHub.com was mitigated within six hours. Wiz reports that 88% of GHES instances were still vulnerable at publication. Fixed versions: 3.14.24, 3.15.19, 3.16.15, 3.17.12, 3.18.6, 3.19.3.

Affected products: GitHub Enterprise Server ≤ 3.19.1. Sectors: software engineering, regulated enterprises with self-hosted GHES.

#### Indicators of Compromise

```
CVE:            CVE-2026-3854
Vector:         git push -o (option injection)
Fixed GHES:     3.14.24, 3.15.19, 3.16.15, 3.17.12, 3.18.6, 3.19.3
ATT&CK:         T1064 (Scripting), T1190 (Exploit Public-Facing App)
```

> **SOC Action:** Inventory all GHES instances and upgrade to a fixed release this week. For instances that cannot be patched immediately, restrict authenticated push access at the network edge and rotate any tokens or SSH keys used by automation accounts. Review GHES audit logs for `git-receive-pack` calls containing `-o` push options from accounts that do not normally use them.

### 3.3 CISA KEV: APT28 exploiting Windows NTLM hash leak (CVE-2026-32202)

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/cisa-orders-feds-to-patch-windows-flaw-exploited-in-zero-day-attacks/)

CISA added CVE-2026-32202 to the KEV catalogue with a 12 May 2026 federal patch deadline. The flaw is a zero-click NTLM hash leak left behind by Microsoft's incomplete February patch for CVE-2026-21510. Akamai reports that exploitation requires only that a victim open a malicious file; the leaked hash is then used in pass-the-hash attacks for lateral movement. CERT-UA attributes the original CVE-2026-21510 exploitation to the Russian APT28 (Fancy Bear / UAC-0001) group, which used it against Ukrainian and EU targets in December 2025 alongside an LNK flaw (CVE-2026-21513). Microsoft has not confirmed whether APT28 is also exploiting the new CVE-2026-32202.

Affected products: Windows endpoints and servers. Sectors: government (esp. Ukraine and EU), defence, critical infrastructure.

```
CVE:            CVE-2026-32202 (incomplete patch of CVE-2026-21510)
Threat actor:   APT28 / Fancy Bear / UAC-0001 (attribution to original CVE)
ATT&CK:         T1003 (OS Credential Dumping), T1078 (Valid Accounts)
KEV deadline:   2026-05-12
```

> **SOC Action:** Apply the May Patch Tuesday update on all Windows endpoints/servers ahead of the 12 May KEV deadline. In the meantime, enable SMB signing, block outbound SMB (TCP 445) and WebDAV from user workstations to the internet, and monitor authentication logs for NTLM responses from unexpected service accounts. Hunt for inbound emails delivering attachments that trigger automatic UNC path resolution.

### 3.4 "Copy Fail" — universal Linux kernel LPE (CVE-2026-31431)

**Source:** [Wiz Research](https://www.wiz.io/blog/copyfail-cve-2026-31431-linux-privilege-escalation-vulnerability)

Xint disclosed a logic flaw in the Linux kernel's AEAD crypto subsystem (`algif_aead`) that lets an unprivileged local user write four controlled bytes into the page cache of any readable file — including setuid binaries — via AF_ALG sockets and `splice()`. Because the page cache backs in-memory executables, an attacker can transparently inject code into privileged binaries such as `/usr/bin/su` without touching disk, achieving root. The bug also enables container escape when an unprivileged container shares a base image with a privileged container on the same host. Every Linux kernel built between 2017 and the upstream patch (mainline commit `a664bf3d603d`) is affected. As of 1 May, Ubuntu LTS, Debian stable, and CloudLinux had not shipped fixes; Debian sid/forky and upstream are patched.

Affected products: virtually every Linux distribution since 2017. Sectors: cloud workloads, multi-tenant CI/CD, container orchestration platforms.

```
CVE:            CVE-2026-31431 ("Copy Fail")
Module:         algif_aead (AEAD AF_ALG socket family)
Mitigation:     echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf && rmmod algif_aead
ATT&CK:         T1059, T1064, T1070 (host indicator removal)
```

> **SOC Action:** Where vendor patches are not yet available, apply the upstream `algif_aead` blackhole modprobe mitigation on multi-tenant hosts, CI runners, and Kubernetes worker nodes — prioritise hosts that execute untrusted code. Add a seccomp deny for `socket(AF_ALG, ...)` to container baseline profiles. Alert on `rmmod`/`insmod` activity from non-root namespaces.

### 3.5 ShinyHunters extortion campaign: Instructure and Marcus & Millichap

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/instructure-confirms-data-breach-shinyhunters-claims-attack/), [HaveIBeenPwned](https://haveibeenpwned.com/Breach/MarcusMillichap)

The ShinyHunters extortion gang claimed two major intrusions confirmed during the reporting week. Instructure (developer of the Canvas LMS) confirmed an exploited vulnerability — since patched — exposed names, email addresses, student IDs, and inter-user messages. The threat actor's leak site claims approximately 275 million records across ~9,000 schools and additionally claims that Instructure's Salesforce instance was compromised. Marcus & Millichap (commercial real estate brokerage) also acknowledged a breach impacting 1.8 million accounts including names, employer, job title, email, and phone. The CognitiveCTI correlation engine grouped the two events with 0.90 actor confidence and flagged shared TTPs T1190 (exploit public-facing application) and T1071.001 (web protocol C2). RansomLock leak-site activity also tied Cushman & Wakefield to the same actor on 3 May, confirming a sustained multi-sector push.

Affected sectors: education, commercial real estate, professional services. Cross-vector: Salesforce instances tied to the LMS were also reportedly accessed.

```
Threat actor:   ShinyHunters (extortion-as-a-service)
Victims (wk):   Instructure / Canvas LMS, Marcus & Millichap, Cushman & Wakefield, Follett Software (carry-over)
ATT&CK:         T1190, T1071.001
Records:        ~275M (Instructure claim) + 1.8M (M&M confirmed) + 5.1M (ZenBusiness, prior wk)
```

> **SOC Action:** Customers of Instructure/Canvas should rotate all API keys and re-authorise integrations as instructed by the vendor; assume that previously cached student PII and inter-user messages are exposed and review your downstream data-handling obligations (FERPA, GDPR). Hunt your Salesforce environment for unusual API-token use, large bulk exports, and Connected App grants made during the breach window. Mandate hardware-backed MFA on Salesforce admin accounts.

### 3.6 ConsentFix v3 — automated OAuth phishing against Microsoft Azure

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/consentfix-v3-attacks-target-azure-with-automated-oauth-abuse/)

A third-generation ConsentFix kit is circulating on hacker forums that automates OAuth-code-flow phishing against first-party Microsoft Azure apps. The attack chains a Cloudflare Pages-hosted phishing page that mimics Microsoft sign-in, a localhost-redirect drag-and-drop trick to capture the authorization code, a Pipedream serverless workflow that immediately exchanges the code for a refresh token via Microsoft's API, and finally Specter Portal for post-exploitation. Because the abused apps are pre-trusted FOCI clients, MFA does not block the attack. Push Security warns that the architectural trust placed in first-party apps makes mitigation difficult.

Affected products: Microsoft Azure / Entra ID OAuth-protected resources. Sectors: any Azure tenant.

```
Toolkit:        ConsentFix v3
Hosting:        Cloudflare Pages (phishing), Pipedream (token exchange), Specter Portal (post-ex)
ATT&CK:         T1566 (Phishing), T1078.004 (Cloud Infrastructure Token), T1204 (User Execution)
```

> **SOC Action:** Disable the Azure CLI delegated permission (`04b07795-8ddb-461a-bbee-02f9e1bf7b46`) for users who do not need it, and block end-user consent grants by default in Entra ID. Configure Conditional Access to require compliant device and managed-network sign-in for first-party apps. Monitor Entra sign-in logs for refresh-token exchanges originating from Pipedream IP space (ASN 14618 / `34.196.0.0/14` is a coarse starting filter) and flag tokens issued to localhost redirect URIs.

### 3.7 LiteLLM CVE-2026-42208: pre-auth SQL injection actively exploited

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/hackers-are-exploiting-a-critical-litellm-pre-auth-sqli-flaw/)

A pre-authentication SQL injection in the LiteLLM proxy/SDK gateway (CVE-2026-42208) is being actively exploited only ~36 hours after public disclosure. The flaw lives in the API-key verification path; an attacker submits a crafted `Authorization: Bearer` header to any LLM API route and reads/writes the proxy database, where API keys, virtual keys, master keys, and provider credentials (OpenAI, Anthropic, AWS Bedrock) are stored. Sysdig observed targeted exploitation that went straight to the credential tables — operators clearly knew the schema — followed by IP rotation and refined payloads. Fix: LiteLLM 1.83.7 (replaces string concatenation with parameterised queries). LiteLLM has 45k GitHub stars and is widely deployed by AI/ML platform teams. The same project was hit earlier this year by a TeamPCP supply-chain attack against its PyPI packages.

Affected products: LiteLLM ≤ 1.83.6. Sectors: AI/ML platform engineering, any tenant exposing LiteLLM to the internet.

```
CVE:            CVE-2026-42208
Path exploited: /chat/completions  (Authorization header)
Fix version:    1.83.7
Workaround:     general_settings.disable_error_logs: true
ATT&CK:         T1190, T1078, T1204
```

> **SOC Action:** Treat any internet-exposed LiteLLM ≤ 1.83.6 instance as compromised — rotate all virtual API keys, master keys, and downstream provider (OpenAI, Anthropic, Bedrock, etc.) credentials. Review proxy database connection logs for queries originating from the application user but reading metadata tables outside the normal request flow.

### 3.8 VECT 2.0 ransomware acts as a wiper for any file >128 KB

**Source:** [Check Point Research (via AlienVault)](https://research.checkpoint.com/2026/vect-ransomware-by-design-wiper-by-accident/)

Check Point Research found that VECT 2.0, a Russian-language RaaS that recently partnered with TeamPCP and BreachForums to scale affiliates, has a fatal flaw in its encryption implementation. For every file above 131,072 bytes (128 KB) the encryptor discards three of four ChaCha20 nonces, making decryption impossible — even by the operator. The cipher is misidentified in earlier reporting as ChaCha20-Poly1305 AEAD; it is actually raw ChaCha20-IETF with no integrity protection. The flaw is identical across Windows, Linux, and ESXi variants. Victims who pay will not get usable VM disks, databases, documents, or backups back.

Affected platforms: Windows, Linux, ESXi.

```
Malware:        VECT 2.0 (RaaS)
Affiliate:      TeamPCP, BreachForums users
C2 onion:       vectordntlcrlmfkcm4alni734tbcrnd5lk44v6sp4lqal6noqrgnbyd[.]onion
SHA-256:        58e17dd61d4d55fa77c7f2dd28dd51875b0ce900c1e43b368b349e65f27d6fdd
SHA-256:        8ee4ec425bc0d8db050d13bbff98f483fff020050d49f40c5055ca2b9f6b1c4d
SHA-256:        9c745f95a09b37bc0486bf0f92aad4a3d5548a939c086b93d6235d34648e683f
SHA-256:        a7eadcf81dd6fda0dd6affefaffcb33b1d8f64ddec6e5a1772d028ef2a7da0f2
SHA-256:        e1fc59c7ece6e9a7fb262fc8529e3c4905503a1ca44630f9724b2ccc518d0c06
SHA-256:        e512d22d2bd989f35ebaccb63615434870dc0642b0f60e6d4bda0bb89adee27a
ATT&CK:         T1486, T1490, T1489, T1561.001
```

> **SOC Action:** Block the listed SHA-256 hashes in EDR. Update incident-response playbooks to advise victims of VECT 2.0 that paying will not recover files >128 KB — focus exclusively on offline backup restoration. Hunt ESXi management interfaces for unexpected outbound .onion traffic and for the VECT binary signatures via YARA.

### 3.9 npm supply chain — Shai-Hulud "Third Coming" and Mini Shai-Hulud

**Source:** [Unit 42](https://unit42.paloaltonetworks.com/monitoring-npm-supply-chain-attacks/)

Unit 42 published a consolidated update on the post-Shai-Hulud npm threat landscape, identifying two fresh April campaigns. The first, started 22 April and tagged "Shai-Hulud: The Third Coming", republished a malicious `@bitwarden/cli` v2026.4.0 attributed to TeamPCP; the package impersonates the real Bitwarden CLI and self-propagates by backdooring every npm package the victim can publish. The second, "Mini Shai-Hulud", started 29 April. Both campaigns continue the wormable propagation pattern — stealing npm tokens and GitHub Personal Access Tokens to republish legitimate packages — and embed persistence in CI/CD pipelines.

Affected ecosystems: npm registry, GitHub Actions, Docker Hub images, VS Code extensions.

```
Campaigns:      Shai-Hulud: The Third Coming (since 2026-04-22), Mini Shai-Hulud (since 2026-04-29)
Malicious pkg:  @bitwarden/cli@2026.4.0 (impersonates real Bitwarden CLI)
Threat actor:   TeamPCP
ATT&CK:         T1195.002 (Compromise Software Supply Chain), T1071, T1568, T1574.001
```

> **SOC Action:** Pin and verify SHA digests for all critical npm dependencies; do not auto-update. Block `@bitwarden/cli@2026.4.0` in your private registry. Audit GitHub Actions for workflows that read `NPM_TOKEN` or `GITHUB_TOKEN` and write back to the registry; rotate any PATs that may have been leaked. Use `npm audit signatures` and require scoped, expiring PATs.

### 3.10 Telegram Mini Apps abused for crypto scams and Android malware (FEMITBOT)

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/telegram-mini-apps-abused-for-crypto-scams-android-malware-delivery/)

CTM360 documented FEMITBOT, a shared backend powering hundreds of Telegram bot/Mini App scams that impersonate Apple, Coca-Cola, Disney, eBay, IBM, MoonPay, NVIDIA, and others. The bots launch phishing pages inside Telegram's WebView showing fake balances and countdown timers; victims are pushed to deposit funds, complete referral tasks, or sideload Android APKs that mimic legitimate apps (BBC, NVIDIA, CineTV, Coreweave, Claro). Tracking pixels (Meta, TikTok) are embedded for conversion optimisation. The same domain hosts both the scam API and the APK payloads to keep TLS chains valid and avoid mixed-content warnings.

Affected platforms: Telegram, Android.

```
Operation:      FEMITBOT (shared backend)
Indicator:      API response string "Welcome to join the FEMITBOT platform"
Brands abused:  Apple, Coca-Cola, Disney, eBay, IBM, MoonPay, NVIDIA, BBC, Claro
ATT&CK:         T1566, T1189 (Drive-by Compromise)
```

> **SOC Action:** Block sideload installation on managed Android devices via MDM (`UNKNOWN_SOURCES = false`). Educate finance and exec staff that any Telegram message asking them to deposit crypto, complete referrals, or "withdraw earnings" is fraud. Hunt outbound proxy logs for the FEMITBOT API string in JSON responses.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 CRITICAL | Exploitation of critical vulnerabilities in widely used software (libssh2, cPanel) | CVE-2026-7598 libssh2 integer overflow; cPanel CVE-2026-41940 mass-exploited "Sorry" ransomware (batch 102) |
| 🔴 CRITICAL | Exploitation of vulnerabilities across diverse software components (auth bypass, deserialization, OAuth abuse) | Apache MINA CVE-2026-42779 RCE; ConsentFix v3 Azure OAuth; CVE-2026-41940 auth bypass (batch 101) |
| 🔴 CRITICAL | Ransomware groups expanding targets across diverse sectors (Safepay) | energyaction.com.au, hpk.hamburg (batch 100) |
| 🔴 CRITICAL | Privilege-escalation chain via Chromium memory-corruption batch | CVE-2026-7339 WebRTC, CVE-2026-7347 Chromoting, CVE-2026-7350 WebMIDI, CVE-2026-7351 MHTML, CVE-2026-7353 Skia, CVE-2026-7334 Views, CVE-2026-7359 ANGLE (batch 98) |
| 🔴 CRITICAL | Software supply-chain compromise of public-facing applications | SAP npm package compromise; WordPress redirect plugin backdoor (batch 97) |
| 🔴 CRITICAL | Credential-stealing malware exploiting software vulnerabilities | TeamPCP SAP npm credential theft; Vercel breach Shadow AI / OAuth sprawl (batch 96) |
| 🔴 CRITICAL | Ransomware groups exploiting critical vulns for initial access and exfiltration | CVE-2026-42167 ProFTPD PoC; LiteLLM SQLi exploitation (batch 95) |
| 🔴 CRITICAL | Critical vulnerabilities in widely-used software platforms actively exploited | CVE-2026-3854 GitHub RCE Wiz disclosure (batch 94) |
| 🟠 HIGH | ShinyHunters targeting multiple sectors with consistent TTPs (T1190, T1071.001) | Marcus & Millichap; Instructure / Canvas LMS (batch 104) |
| 🟠 HIGH | Multiple ransomware groups using similar tactics across sectors | Cushman & Wakefield (ShinyHunters); emtco.com, manateeair.com (m3rx); Fiserv (Everest) (batch 102) |
| 🟠 HIGH | Software-vulnerability exploitation across sectors | CVE-2026-6845 binutils DoS; CVE-2026-32148 Hex lockfile bypass (batch 103) |
| 🟠 HIGH | Phishing remains the dominant initial-access TTP | Everest victims TSYS, Epiq Global, Symcor; LAPSUS BreachedForums activity; Homebrew malvertising → MacSync stealer (batch 100) |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **Qilin** (82 reports) — RaaS dominating leak-site volume; multi-channel onion infrastructure with Jabber/Tox negotiation
- **The Gentlemen** (63 reports) — Persistent extortion crew, broad sector targeting
- **Coinbase Cartel** (31 reports) — Continued financial-services-themed extortion activity
- **DragonForce** (27 reports) — Ongoing RaaS operations across manufacturing and retail
- **shadowbyt3$** (25 reports) — Commodity stealer / data-leak persona
- **ShinyHunters** (21 + 18 alias reports) — Headline extortion campaign this week (Instructure, M&M, Cushman & Wakefield, Follett)
- **Inc Ransom** (17 reports) — Fresh leak-site posts targeting legal, medical, manufacturing
- **Lamashtu** (16 reports) — Continued posting cadence
- **Everest** (15 reports) — Double-extortion against TSYS, Epiq Global, Symcor, Fiserv
- **FulcrumSec** (15 reports) — New high-cadence leak-site actor (first seen 29 April)
- **TeamPCP** (14 reports) — Behind LiteLLM PyPI compromise, VECT 2.0 partnership, npm Shai-Hulud variants
- **Lockbit5** (14 reports) — Lockbit successor still active
- **APT28 / Fancy Bear** — CVE-2026-32202 / CVE-2026-21510 zero-day exploitation against Ukraine and EU
- **FEMITBOT** — Telegram-based crypto-scam and Android-malware platform

### Malware Families

- **RansomLook** (53 reports) and **RansomLock** (44 reports) — Leak-site infrastructure / RaaS branding cluster
- **RaaS** (23 reports) — Generic ransomware-as-a-service tagging
- **Tox / Tox1** (21 + 13 reports) — Negotiation channel preferred by Qilin, "Sorry", and several other operators
- **Qilin** (11 reports as malware family)
- **Gentlemen ransomware** (9), **DragonForce ransomware** (7+8 alias) — Recurring high-volume strains
- **Everest ransomware** (6 reports) — Active across financial services and government
- **Mirai** (6 reports) — IoT botnet still in circulation
- **VECT** — RaaS that doubles as a wiper for files > 128 KB
- **Sorry** — New Linux Go-based ransomware paired with cPanel CVE-2026-41940
- **Shai-Hulud (3rd Coming, Mini)** — npm wormable supply-chain payloads from TeamPCP
- **ConsentFix v3** — OAuth phishing toolkit targeting Azure/Entra ID

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| RansomLook | 122 | [link](https://www.ransomlook.io/) | Primary leak-site monitoring across Qilin, Everest, m3rx, safepay, ShinyHunters, Inc Ransom |
| Microsoft (MSRC) | 87 | [link](https://msrc.microsoft.com/update-guide/) | Linux/OSS CVE pipeline (binutils, libpng, FRRouting, Apache Thrift, libssh2, firewalld) plus Chromium batch |
| BleepingComputer | 37 | [link](https://www.bleepingcomputer.com/news/security/critrical-cpanel-flaw-mass-exploited-in-sorry-ransomware-attacks/) | Primary coverage of cPanel mass-exploitation, GitHub RCE, CISA KEV, Telegram fraud |
| Unknown / Telegram | 22 | — | Telegram (channel name redacted) — POCs and translated technical detail for CVE-2026-41940, CVE-2026-3854, CVE-2026-31431, CVE-2026-42167, CVE-2026-42779 |
| RecordedFutures | 18 | [link](https://www.recordedfuture.com/research) | Threat actor / malware enrichment |
| AlienVault OTX | 11 | [link](https://research.checkpoint.com/2026/vect-ransomware-by-design-wiper-by-accident/) | Re-shared the Check Point VECT 2.0 wiper analysis |
| SANS ISC | 10 | [link](https://isc.sans.edu/) | Daily diaries (Homebrew malvertising → MacSync stealer, npm telemetry) |
| Wiz | 6 | [link](https://www.wiz.io/blog/github-rce-vulnerability-cve-2026-3854) | GitHub RCE CVE-2026-3854 and Copy Fail CVE-2026-31431 disclosures |
| Wired Security | 5 | [link](https://www.wired.com/category/security/) | Long-form coverage |
| HaveIBeenPwned | 5 | [link](https://haveibeenpwned.com/Breach/MarcusMillichap) | Marcus & Millichap (1.8M), ZenBusiness (5.1M) breach loads |
| Upwind | 4 | [link](https://www.upwind.io/feed) | Cloud-native security telemetry |
| Schneier | 3 | [link](https://www.schneier.com/) | Claude Mythos / Firefox 271 zero-day disclosure commentary |
| Crowdstrike | 3 | [link](https://www.crowdstrike.com/blog/) | Adversary intel |
| Unit 42 | 3 | [link](https://unit42.paloaltonetworks.com/monitoring-npm-supply-chain-attacks/) | npm Threat Landscape update; detection-beyond-the-endpoint |
| CISA | 3 | [link](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | KEV additions for cPanel CVE-2026-41940 and Windows CVE-2026-32202 |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Apply the cPanel/WHM emergency update everywhere; treat any internet-facing cPanel host without the patch as compromised and triage for the `.sorry` extension and the Tox-ID ransom note (§3.1). CISA KEV deadline applies to federal agencies but the threat is opportunistic worldwide.
- 🔴 **IMMEDIATE:** Patch GitHub Enterprise Server to 3.14.24 / 3.15.19 / 3.16.15 / 3.17.12 / 3.18.6 / 3.19.3 — Wiz reports 88% of instances are still vulnerable to CVE-2026-3854 (§3.2). Rotate runner and automation tokens after patching.
- 🔴 **IMMEDIATE:** Deploy May Patch Tuesday updates to Windows endpoints/servers ahead of CISA's 12 May KEV deadline for CVE-2026-32202; APT28 is actively exploiting the related CVE-2026-21510 against EU and Ukrainian targets (§3.3). Block outbound SMB and WebDAV from user workstations as a stop-gap.
- 🔴 **IMMEDIATE:** Treat all internet-exposed LiteLLM ≤ 1.83.6 instances as breached — rotate every virtual key, master key, and downstream LLM-provider credential and upgrade to 1.83.7 (§3.7).
- 🟠 **SHORT-TERM:** Roll out vendor patches for "Copy Fail" CVE-2026-31431 across the Linux estate; for distros without fixes (Ubuntu LTS, Debian stable, CloudLinux as of 1 May), apply the `algif_aead` blackhole and add seccomp filters on multi-tenant nodes (§3.4).
- 🟠 **SHORT-TERM:** Force Salesforce admin MFA, audit Connected Apps, and re-issue Instructure/Canvas API keys; assume student PII and inter-user messages exposed by the ShinyHunters incident are in adversary hands (§3.5). Notify regulators where required.
- 🟠 **SHORT-TERM:** Block end-user OAuth consent grants in Entra ID by default and require admin approval for first-party FOCI apps to break the ConsentFix v3 attack chain (§3.6).
- 🟡 **AWARENESS:** Pin and digest-verify npm dependencies, restrict publishing PAT scopes, and watch for `@bitwarden/cli@2026.4.0` and other Shai-Hulud-derivative packages (§3.9). Brief developer teams on Mini Shai-Hulud activity from 29 April onward.
- 🟡 **AWARENESS:** Update IR playbooks for VECT 2.0 victims — files >128 KB cannot be decrypted even if ransom is paid; restoration must come from offline backups (§3.8).
- 🟢 **STRATEGIC:** Move detection telemetry beyond the endpoint as recommended by Unit 42 — instrument cloud control planes, identity providers, and DNS to catch cloud-to-endpoint pivots, identity-based covert C2, and shadow IT before they bypass EDR.

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 346 reports processed across 13 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
