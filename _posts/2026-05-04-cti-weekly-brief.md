---
layout: post
title:  "CTI Weekly Brief: 4 May to 10 May 2026 - PAN-OS Zero-Day Exploited In-the-Wild, Linux Kernel Page-Cache Bugs Chain to Root, npm Supply Chain Worm Hits Intercom SDK"
date:   2026-05-11 08:30:00 +0000
description: "Weekly intelligence covering 559 reports across the pipeline: state-sponsored exploitation of PAN-OS CVE-2026-0300, two unpatched Linux LPE chains (Copy Fail and Dirty Frag), Ivanti EPMM zero-day under CISA emergency directive, Mini Shai-Hulud npm worm, and sustained ransomware pressure from Qilin, The Gentlemen, Akira and DragonForce."
category: weekly
tags: [cti, weekly-brief, qilin, the-gentlemen, akira, dirty-frag, copy-fail, cve-2026-0300, cve-2026-6973, cve-2026-31431]
classification: TLP:CLEAR
reporting_period_start: "2026-05-04"
reporting_period_end: "2026-05-10"
generated: "2026-05-11"
draft: false
severity: critical
report_count: 559
sources:
  - BleepingComputer
  - Microsoft
  - Wiz
  - Sysdig
  - Unit42
  - Elastic Security Labs
  - SANS
  - Schneier
  - CISA
  - CertEU
  - Upwind
  - RansomLock
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 4 May to 10 May 2026 (7d) | TLP:CLEAR | 2026-05-11 |

## 1. Executive Summary

This week the pipeline processed 559 reports across more than fifteen sources, dominated by 44 critical-severity items and 339 high-severity items. Three storylines defined the week. First, a confirmed-in-the-wild PAN-OS firewall zero-day (CVE-2026-0300) was exploited by suspected state-sponsored actors tracked by Unit 42 as CL-STA-1132 from 9 April onward; CISA added it to the KEV catalogue with a 9 May remediation deadline. Second, two separate Linux kernel local privilege escalation chains landed in the same week — Copy Fail (CVE-2026-31431), now under active exploitation and CISA-mandated for federal remediation by 15 May, and Dirty Frag (CVE-2026-43284 / CVE-2026-43500), disclosed after an embargo break on 7 May with a public PoC and no patches available across Ubuntu, RHEL, Fedora, openSUSE, AlmaLinux and CentOS Stream. Third, Ivanti disclosed a sixth EPMM zero-day in eighteen months (CVE-2026-6973) with limited exploitation observed; CISA gave federal agencies four days to patch.

Additional headline items include the Mini Shai-Hulud npm worm compromising the official intercom-client SDK (version 7.0.4) with Bun-runtime EDR evasion and four self-propagation vectors; Progress Software's MOVEit Automation pre-auth bypass (CVE-2026-4670) with ~1,400 instances exposed; sustained ransomware throughput from Qilin (98 pipeline-wide reports), The Gentlemen (56), Akira (50), DragonForce (30) and ShinyHunters (27); and the public disclosure of Google's DarkSword iOS exploit chain attributed to commercial surveillance vendors operating against targets in Saudi Arabia, Turkey, Malaysia and Ukraine since November 2025.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 44 | PAN-OS CVE-2026-0300 zero-day; Dirty Frag (CVE-2026-43284/43500) and Copy Fail (CVE-2026-31431) Linux LPEs; Ivanti EPMM CVE-2026-6973; MOVEit Automation CVE-2026-4670; Mini Shai-Hulud npm worm; Apache HTTP Server triple-fix; Redis-family RCEs; DarkSword iOS spyware |
| 🟠 **HIGH** | 339 | Qilin, The Gentlemen, Akira, DragonForce, ShinyHunters, Genesis, Inc Ransom and Lamashtu ransomware victim postings; PCPJack cloud worm; ScarCruft and DAEMON Tools supply-chain backdoors; Mac malware abusing Google Ads and Claude.ai shared chats |
| 🟡 **MEDIUM** | 97 | Microsoft MSRC bulletins; Kubernetes / xmldom / pip secondary CVEs; phishing toolkit advisories |
| 🟢 **LOW** | 16 | Lower-confidence ransomware victim claims; minor configuration issues |
| 🔵 **INFO** | 63 | Microsoft Defender / RansomLook telemetry; vendor blog posts; historical context items |

## 3. Priority Intelligence Items

### 3.1 PAN-OS CVE-2026-0300 — Unauthenticated RCE on Captive Portal Exploited Since 9 April

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/pan-os-firewall-rce-zero-day-exploited-in-attacks-since-april-9/), [Wiz](https://www.wiz.io/blog/critical-vulnerability-in-pan-os-exploited-in-the-wild-cve-2026-0300), [CERT-EU](https://cert.europa.eu/publications/security-advisories/2026-006/)

Palo Alto Networks confirmed limited but active exploitation of a buffer-overflow vulnerability in the PAN-OS User-ID Authentication Portal (Captive Portal) by suspected state-sponsored attackers tracked by Unit 42 as cluster CL-STA-1132. The flaw allows unauthenticated remote code execution as root on Internet-exposed PA-Series and VM-Series firewalls with no user interaction. Successful intrusions began 16 April after a week of failed probes starting 9 April. Post-exploitation, the actors deployed open-source Earthworm and ReverseSocks5 tunneling tools — Earthworm has prior associations with the Chinese-speaking clusters Volt Typhoon, UAT-8337 and APT41 — and cleaned nginx crash artefacts to evade detection. Shadowserver tracks more than 5,400 PAN-OS VM-Series firewalls exposed online (2,466 in Asia, 1,998 in North America). CISA added CVE-2026-0300 to the KEV catalogue with a 9 May FCEB deadline; Cloud NGFW and Panorama are unaffected. Patches were targeted for 13 May; until then, restrict the Authentication Portal to trusted zones or disable it.

**Affected products:** PAN-OS on PA-Series and VM-Series firewalls (Captive Portal feature enabled).

**MITRE ATT&CK:** T1190 (Exploit Public-Facing Application), T1572 (Protocol Tunneling), T1070 (Indicator Removal on Host).

> **SOC Action:** Audit `Device > User Identification > Authentication Portal Settings` on every Internet-facing PAN-OS device; disable or scope to internal zones until patches are applied. Hunt nginx access/error logs for crash-clearing activity and unexpected outbound SOCKS5 connections. Detect Earthworm/ReverseSocks5 process trees and outbound TCP sessions to non-corporate IPs on high ports.

### 3.2 Dirty Frag — Unpatched Universal Linux LPE (CVE-2026-43284 + CVE-2026-43500)

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/new-linux-dirty-frag-zero-day-with-poc-exploit-gives-root-privileges/), [Sysdig](https://webflow.sysdig.com/blog/dirty-frag-cve-2026-43284-and-cve-2026-43500-detecting-unpatched-local-privilege-escalation-via-linux-kernel-esp-and-rxrpc), [Upwind](https://www.upwind.io/feed/dirty-frag-linux-root-exploit-esp-rxrpc)

Researcher Hyunwoo Kim published a PoC for Dirty Frag on 8 May after a third party broke the coordinated disclosure embargo. The exploit chains two page-cache-write bugs — xfrm-ESP (CVE-2026-43284, introduced January 2017) and RxRPC (CVE-2026-43500, introduced June 2023) — to deterministically overwrite `/usr/bin/su` or `/etc/passwd` in the page cache without altering on-disk integrity. Because the logic is deterministic, there is no race window, the kernel does not panic on failure, and success rates approach 100% across Ubuntu, Red Hat Enterprise Linux, CentOS Stream, AlmaLinux, openSUSE Tumbleweed and Fedora. No CVE-coordinated patches existed at the time of disclosure. Interim mitigation is to block the affected kernel modules: `printf 'install esp4 /bin/false\ninstall esp6 /bin/false\ninstall rxrpc /bin/false\n' > /etc/modprobe.d/dirtyfrag.conf; rmmod esp4 esp6 rxrpc` — note this breaks IPsec VPNs and AFS file systems.

**Affected products:** Mainline Linux kernels carrying the xfrm-ESP optimisation (post-Jan 2017) and the RxRPC pcbc(fcrypt) handler (post-Jun 2023).

**MITRE ATT&CK:** T1068 (Exploitation for Privilege Escalation), T1070 (Indicator Removal on Host).

> **SOC Action:** Inventory Linux hosts loading `esp4`, `esp6` or `rxrpc` kernel modules (`lsmod | egrep 'esp[46]|rxrpc'`). Where IPsec/AFS is not required, deploy the modprobe blocklist immediately. On hosts where the modules must remain loaded, increase auditd coverage on `/usr/bin/su`, `/usr/bin/sudo` and `/etc/passwd` for unexpected memory-based modifications. Hunt for unprivileged users invoking AF_ALG/AF_RXRPC sockets with pcbc(fcrypt).

### 3.3 Copy Fail (CVE-2026-31431) — Actively Exploited Linux Kernel LPE

**Source:** [Unit 42](https://unit42.paloaltonetworks.com/cve-2026-31431-copy-fail/), [Elastic Security Labs](https://www.elastic.co/security-labs/copy-fail-dirtyfrag-linux-page-bugs-in-the-wild)

Disclosed 29 April and now under active exploitation per CISA's KEV addition, Copy Fail is a deterministic LPE in the Linux kernel cryptographic subsystem (`algif_aead` in the AF_ALG user-space crypto API). A combination of three innocuous-looking commits — authencesn (2011), AEAD support in AF_ALG (2015), and a 2017 in-place optimisation — causes `req->src` and `req->dst` to share a scatterlist, writing four attacker-controlled bytes past the legitimate region into the file page cache of executables like `su`. The flaw affects kernels 4.14 through 6.19.12 and impacts essentially every mainstream distribution since 2017 (Ubuntu, Amazon Linux, RHEL, Debian, SUSE, AlmaLinux). A 732-byte Python script exploits it portably. The implications are severe: container escape from Kubernetes pods, multi-tenant host compromise, and CI/CD pipeline takeover via shared kernel page cache. CISA has ordered FCEB agencies to remediate by 15 May.

**Affected products:** Linux kernels 4.14–6.19.12 on virtually all major distributions; containerised and CI/CD environments at elevated risk.

**MITRE ATT&CK:** T1068 (Exploitation for Privilege Escalation), T1611 (Escape to Host).

> **SOC Action:** Apply vendor kernel updates immediately. Where patching is delayed, follow the Linux Foundation interim mitigation to disable the vulnerable `algif_aead` module. In container environments, audit Kubernetes node kernels and enforce seccomp profiles that deny AF_ALG socket creation for workload containers. Hunt for unexpected splice() activity against the AF_ALG socket family in container runtime telemetry.

### 3.4 Ivanti EPMM CVE-2026-6973 — Authenticated RCE Zero-Day Under Limited Exploitation

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/ivanti-warns-of-new-epmm-flaw-exploited-in-zero-day-attacks/), [BleepingComputer](https://www.bleepingcomputer.com/news/security/cisa-gives-feds-four-days-to-patch-ivanti-flaw-exploited-as-zero-day/)

Ivanti disclosed an improper-input-validation flaw in Endpoint Manager Mobile (EPMM) 12.8.0.0 and earlier that allows admin-authenticated remote code execution. Limited exploitation has been observed in the wild. Ivanti released patches 12.6.1.1, 12.7.0.1 and 12.8.0.1 alongside four other high-severity bulletins (CVE-2026-5786 / 5787 / 5788 / 7821) which show no current exploitation. CISA issued an emergency directive giving federal agencies four days to patch. Shadowserver tracks more than 850 Internet-exposed EPMM instances, predominantly in Europe (508) and North America (182). EPMM has now had 33 distinct CVEs flagged in KEV, 12 of which have been abused by ransomware operators. Customers who rotated admin credentials following the January CVE-2026-1281/1340 disclosures inherit partial protection.

**Affected products:** Ivanti Endpoint Manager Mobile (on-prem) ≤ 12.8.0.0. Ivanti Neurons for MDM, EPM, Sentry and other Ivanti products are unaffected.

**MITRE ATT&CK:** T1078 (Valid Accounts), T1190 (Exploit Public-Facing Application), T1059 (Command and Scripting Interpreter).

> **SOC Action:** Patch EPMM to 12.6.1.1 / 12.7.0.1 / 12.8.0.1 immediately. Rotate admin credentials and audit admin login history for the past 60 days. Restrict EPMM admin console access to a management VPN/jump-host network — Internet exposure of an EPMM admin panel is no longer defensible given the threat group cadence.

### 3.5 MOVEit Automation CVE-2026-4670 — Unauthenticated Auth Bypass

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/moveit-automation-customers-warned-to-patch-critical-auth-bypass-flaw/)

Progress Software disclosed a critical authentication bypass in MOVEit Automation (versions before 2025.1.5, 2025.0.9 and 2024.1.8) that requires no privileges or user interaction. A companion privilege-escalation bug (CVE-2026-5174) was patched in the same release. No in-the-wild exploitation has been confirmed at disclosure, but the MFT-software threat history is unfavourable: Clop's 2023 MOVEit Transfer campaign affected 2,100 organisations and 62 million individuals, and Clop has repeatedly chosen MFT platforms as initial-access vectors. Shodan shows ~1,400 MOVEit Automation instances exposed online, with at least a dozen tied to US local/state government. Progress's only remediation is a full upgrade using the full installer, which entails downtime.

**Affected products:** MOVEit Automation before 2025.1.5, 2025.0.9, 2024.1.8.

**MITRE ATT&CK:** T1190 (Exploit Public-Facing Application), T1078 (Valid Accounts).

> **SOC Action:** Identify all MOVEit Automation hosts (file-transfer orchestrators are often missing from CMDB) and prioritise upgrade. While patching, place MOVEit web tier behind a WAF or network ACL restricted to operator IPs. Hunt MOVEit IIS logs for unauthenticated endpoint access and out-of-band scheduled-task creation.

### 3.6 Mini Shai-Hulud — npm Supply Chain Worm in intercom-client 7.0.4

**Source:** [Upwind](https://www.upwind.io/feed/mini-shai-hulud-npm-supply-chain-worm)

The official Node.js SDK for Intercom (`intercom-client@7.0.4`, published 30 April) was found to be malicious. Three files differed from 7.0.3: a preinstall hook in `package.json`, a `setup.mjs` dropper (222 lines), and `router_runtime.js` (11.7 MB, obfuscated). The dropper downloads the official Bun JavaScript runtime from GitHub and executes the payload under Bun to evade EDR rules that hook `node`/`node.exe`, NODE_OPTIONS shims and npm lifecycle instrumentation. The payload scrapes GitHub Actions runner memory for secrets, harvests credentials from AWS, GCP, Azure, Vault and other secret stores, exfiltrates via RSA-4096 encryption (preventing IR teams from determining what was stolen), injects a "Dependabot"-disguised GitHub Actions workflow that dumps secrets, and self-propagates via four mechanisms including poisoning every branch of compromised repositories with files disguised as Claude AI configuration and trojanizing other npm packages via stolen tokens. The package has been yanked but downstream effects persist independently. A correlated trend in the same week also flagged five malicious NuGet packages impersonating Chinese UI libraries to distribute crypto wallet and credential stealers.

**Affected products:** `intercom-client@7.0.4` (npm); any repo or workstation that ran `npm/pnpm/yarn install` against a manifest pinning that version; any cloned repository whose `.github/workflows/` was modified by the worm.

**MITRE ATT&CK:** T1195.002 (Compromise Software Supply Chain), T1059.007 (JavaScript), T1078.004 (Cloud Accounts), T1552.001 (Credentials in Files), T1071.001 (Web Protocols).

#### Indicators of Compromise

```
Malicious package: intercom-client@7.0.4 (npm) — yanked
Dropped runtime:   bun-v1.3.13 (downloaded from github.com/oven-sh/bun/releases)
Dropper artifact:  setup.mjs (preinstall hook)
Payload artifact:  router_runtime.js (~11.7 MB, obfuscated)
Persistence:       .github/workflows/*.yml disguised as Dependabot
Exfil channel:     RSA-4096 encrypted outbound payloads
```

> **SOC Action:** Query SBOMs, lockfiles and npm audit logs for any reference to `intercom-client@7.0.4`. On any host that ran `npm install` against that version, rotate every credential available to that runner (cloud, registry tokens, GitHub PATs, npm publish tokens, signing keys). Block unsigned downloads of `bun` from `github.com/oven-sh/bun/releases` from CI runners that should not need it. Audit recently modified `.github/workflows/` files in all owned repositories for unexplained Dependabot-style additions.

### 3.7 Weaver E-cology CVE-2026-22679 — Pre-Auth RCE Exploited Since Mid-March

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/weaver-e-cology-critical-bug-exploited-in-attacks-since-march/)

Vega researchers reported that attackers have been exploiting a debug-API endpoint flaw in Weaver E-cology 10.0 (a Chinese-market office automation platform) since mid-March, five days after Weaver shipped a fix and two weeks before public disclosure. The endpoint passed unvalidated parameters to backend RPC, enabling unauthenticated remote command execution under the Tomcat-bundled Java process. Observed attacker behaviour included Goby-style ping callbacks, PowerShell payload downloads, an MSI installer (`fanwei0324.msi`) and reconnaissance commands (`whoami`, `ipconfig`, `tasklist`). Endpoint defences blocked most stages and no persistent foothold was established in the documented intrusions. The vendor fix (build 20260312) removes the debug endpoint entirely; no workaround is offered.

**Affected products:** Weaver E-cology 10.0 builds prior to 20260312.

**MITRE ATT&CK:** T1190 (Exploit Public-Facing Application), T1059.001 (PowerShell), T1071.001 (Web Protocols), T1204 (User Execution).

> **SOC Action:** Inventory Weaver E-cology exposure (predominantly East Asia / China-market organisations). Update to build 20260312 or later. Hunt parent-child telemetry for `java.exe` (Tomcat) spawning `powershell.exe`, `cmd.exe`, `msiexec.exe`, or any reconnaissance binary (`whoami`, `ipconfig`, `tasklist`) in the past 90 days.

### 3.8 DarkSword — iOS Full-Chain Zero-Day Spyware

**Source:** Schneier on Security (Google Threat Intelligence Group attribution)

Google Threat Intelligence Group disclosed DarkSword, an iOS full-chain exploit observed since November 2025 leveraging multiple zero-day vulnerabilities to fully compromise targeted devices. GTIG attributes use of the chain to commercial surveillance vendors and suspected state-sponsored operators. Observed targeting includes Saudi Arabia, Turkey, Malaysia and Ukraine. Toolmarks in recovered payloads gave the chain its name.

**Affected products:** iOS (specific version range not published).

**MITRE ATT&CK:** T1078 (Valid Accounts), T1204 (User Execution), T1190 (Exploit Public-Facing Application).

> **SOC Action:** Ensure mobile fleet is on the latest iOS release and that Lockdown Mode is available to high-risk users (legal, executive, government-facing roles). Where MDM is in place, enforce minimum-iOS policies and review device-attestation events. Cross-reference any executive travel to Saudi Arabia, Turkey, Malaysia or Ukraine against device anomaly telemetry.

### 3.9 Apache HTTP Server Triple-Fix — mod_rewrite Privilege Escalation, HTTP/2 Double-Free RCE, Response-Splitting

**Source:** [Microsoft MSRC — CVE-2026-24072](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-24072), [Microsoft MSRC — CVE-2026-23918](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-23918), [Microsoft MSRC — CVE-2026-33523](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-33523)

Three critical Apache HTTP Server bulletins shipped on 7 May. CVE-2026-24072 is a `mod_rewrite` privilege elevation via `ap_expr` (improper user-input validation leading to root code execution). CVE-2026-23918 is a double-free in the `http2` module on early connection reset that allows remote code execution. CVE-2026-33523 is multi-module HTTP response splitting allowing forwarded malicious status lines, enabling cache poisoning and downstream XSS. The pipeline correlation engine identified these as a single "exploitation of web-server vulnerabilities leading to remote code execution" trend.

**Affected products:** Apache HTTP Server (specific affected branches per MSRC bulletins).

**MITRE ATT&CK:** T1190 (Exploit Public-Facing Application), T1068 (Exploitation for Privilege Escalation).

> **SOC Action:** Patch Apache HTTPD to the fixed minor versions across all `httpd`-fronted services including reverse-proxy tiers and shared hosting. Audit `mod_rewrite` rule files for use of `ap_expr` with untrusted input. If `mod_http2` is loaded but not required, unload it pending patch.

### 3.10 Redis Family CVE Cluster — Five Critical RCE Bulletins

**Source:** [Microsoft MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-23479) (plus CVE-2026-23631, CVE-2026-25243, CVE-2026-25588, CVE-2026-25589)

Five critical CVEs were published on 7–8 May covering use-after-free and invalid-memory-access conditions across `redis-server` (CVE-2026-23479 — unblock-client flow; CVE-2026-23631 — Lua), RedisTimeSeries (CVE-2026-25588) and RedisBloom (CVE-2026-25589), as well as RESTORE-path memory corruption (CVE-2026-25243). All permit remote code execution by attackers able to reach a Redis instance. The pattern across the cluster is unsafe handling of serialized RDB data during RESTORE and untrusted Lua script execution. Redis instances are frequently deployed without authentication on internal networks, often within reachable blast radius of compromised application tiers.

**Affected products:** redis-server (specific affected versions per MSRC), RedisTimeSeries, RedisBloom.

**MITRE ATT&CK:** T1190 (Exploit Public-Facing Application), T1210 (Exploitation of Remote Services).

> **SOC Action:** Inventory all Redis instances (including those bundled with application stacks). Patch to fixed versions. Enforce `requirepass` / ACL authentication and bind Redis to non-public interfaces. Audit application-tier access patterns for unexpected `EVAL`, `RESTORE` or module-load commands.

### 3.11 Hackers Abuse Google Ads and Claude.ai Shared Chats to Push Mac Malware

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/hackers-abuse-google-ads-claudeai-chats-to-push-mac-malware/)

A social-engineering campaign targeting macOS users abuses Google Ads placements and Claude.ai shared-chat links to trick users into executing a polymorphic shell-script downloader. The script profiles victims by geolocation and harvests browser credentials and macOS Keychain contents. The Claude.ai-shared-chat angle is novel — attackers seed a Claude conversation with copy-paste-able install instructions and share its public URL, exploiting the implicit trust users place in chats that originate from a legitimate AI vendor.

**MITRE ATT&CK:** T1566.002 (Phishing: Spearphishing Link), T1204.001 (Malicious Link), T1059.004 (Unix Shell), T1555 (Credentials from Password Stores).

> **SOC Action:** Block Google Ads click-through tracking redirects in DNS where feasible. Educate macOS users on the new pattern: copy-paste-from-shared-chat installer commands are an attacker channel. Hunt EDR telemetry on macOS hosts for `curl`/`wget` to Pastebin / shared-link domains piping directly into `sh`, and for unexpected Keychain access events.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Linux kernel page-cache LPEs exploited in the wild | Copy Fail (CVE-2026-31431) Elastic / Unit 42 / CISA KEV; Dirty Frag (CVE-2026-43284 + CVE-2026-43500) BleepingComputer / Sysdig / Upwind |
| 🔴 **CRITICAL** | Zero-day exploitation of edge network security products | PAN-OS CVE-2026-0300 (Wiz, BleepingComputer, CERT-EU); FortiClient EMS CVE-2026-35616 pre-auth bypass; Ivanti EPMM CVE-2026-6973 |
| 🔴 **CRITICAL** | Web-server RCE chains | Apache HTTP Server CVE-2026-23918 / 24072 / 33523 (correlation batch 111) |
| 🔴 **CRITICAL** | Supply-chain attacks on package ecosystems | Mini Shai-Hulud npm worm (intercom-client); Intercom's npm Package Compromised in Ongoing Mini Shai-Hulud Worm Attack; five malicious NuGet packages impersonating Chinese UI libraries |
| 🔴 **CRITICAL** | Critical vulnerabilities in industrial control systems | ABB B&R PVI; Johnson Controls CEM AC2000; Hitachi Energy PCM600 (correlation batch 108) |
| 🟠 **HIGH** | Sustained ransomware throughput across Qilin / The Gentlemen / Akira / DragonForce / Genesis | Multi-batch correlations across batches 105–114; Qilin alone correlated across ten victim postings in batch 112 |
| 🟠 **HIGH** | Phishing and credential-theft campaigns as cross-actor primary access | TeamPCP / PCPJack cloud worm; Google Ads / GoDaddy ManageWP phishing; Mac malware via Google Ads & Claude.ai shared chats |
| 🟠 **HIGH** | Supply-chain backdoors via trojanized software releases | ScarCruft compromises a gaming platform; DAEMON Tools trojanized to deploy backdoor (batch 108) |
| 🟠 **HIGH** | Geopolitical/hacktivist convergence | Pro-Ukraine BO Team and Head Mare teaming up against Russian targets; MuddyWater using Chaos ransomware as a decoy (batch 109) |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **Qilin** (98 reports) — Most active ransomware operator in the pipeline; ten correlated victim postings in batch 112 alone; sectors include real estate, architecture, construction, financial services and logistics.
- **The Gentlemen** (56 reports) — Active across manufacturing, chemical manufacturing and telecommunications; uses Tox1 / The Gentlemen ransomware variants.
- **Akira** (50 reports) — Healthcare-heavy targeting (Greenwoods Dental Centre, Réseau Radiologique Romand, Zojirushi).
- **DragonForce** (30 reports) — Multi-sector ransomware activity including construction and accountancy.
- **ShinyHunters** (27 reports) — Tied to the Canvas / Houghton Mifflin Harcourt education-sector incidents.
- **Coinbase Cartel** (26 reports) — Crypto-finance-themed leak postings.
- **Inc Ransom** (22 reports) — Legal-services, technology, healthcare targeting.
- **Lamashtu** (22 reports) — Mid-tier multi-sector activity.
- **Everest** (22 reports) — Linked to the Citizens Bank breach (April 2026 incident date) reported via Telegram.
- **TeamPCP** (18 reports) — Now being displaced by the PCPJack cloud worm.
- **FulcrumSec** (17 reports) — Active across healthcare, manufacturing and the Arup Group incident.
- **Lockbit5** (14 reports) — Steady cadence following last month's resurgence.
- **Safepay** (13 reports) — Targeted IT services and construction firms in Japan, Portugal, Italy, Germany, Australia, the UK, Cambodia, Argentina and Canada (batch 106).

### Malware Families

- **RansomLook / RansomLock** (90 + 36 reports) — Pipeline-wide RaaS-tracking telemetry; not an individual family but the unifying source of victim-disclosure scraping.
- **Tox1** (35 reports) — Associated with The Gentlemen.
- **Akira ransomware** (26 reports) — Primary payload of the Akira affiliate program.
- **RaaS** (18 reports) — Generic ransomware-as-a-service tagging.
- **Qilin ransomware** (13 reports) — Aligned with the Qilin threat-actor cadence above.
- **DragonForce ransomware** (8 reports).
- **Safepay** (8 reports) — Both the actor and the named payload.
- **The Gentlemen ransomware** (7 reports).
- **Everest ransomware** (7 reports) — Used in the Citizens Bank incident.
- **DarkSword** (1 report this week, newly tracked) — Government-grade iOS exploit chain.
- **Mini Shai-Hulud** (1 report this week, newly tracked) — Worming npm payload.
- **EarthWorm / ReverseSocks5** — Tunneling tools used in CL-STA-1132's PAN-OS post-exploitation.

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| RansomLook | 220 | [link](https://www.ransomlook.io/) | RaaS leak-site telemetry; Lynx, Qilin, The Gentlemen, Akira, DragonForce victim postings |
| Microsoft | 149 | [link](https://msrc.microsoft.com/update-guide/) | MSRC bulletins including Apache HTTP Server, Redis-family, libssh2, GnuTLS, Vim CVEs |
| BleepingComputer | 47 | [link](https://www.bleepingcomputer.com/news/security/pan-os-firewall-rce-zero-day-exploited-in-attacks-since-april-9/) | Primary coverage of PAN-OS, Dirty Frag, Ivanti EPMM, MOVEit and Weaver E-cology |
| Unknown | 25 | — | Telegram-origin posts (channels redacted) and TLP:AMBER+STRICT submissions |
| AlienVault | 24 | [link](https://otx.alienvault.com/) | OSINT pulses |
| RecordedFutures | 14 | [link](https://www.recordedfuture.com/) | Threat-intel platform exports |
| SANS | 13 | [link](https://isc.sans.edu/) | Internet Storm Center diaries including MS Edge cleartext-password issue |
| Wiz | 11 | [link](https://www.wiz.io/blog/critical-vulnerability-in-pan-os-exploited-in-the-wild-cve-2026-0300) | PAN-OS in-the-wild analysis |
| CISA | 8 | [link](https://www.cisa.gov/news-events/cybersecurity-advisories) | Emergency directives for Ivanti EPMM, Copy Fail, PAN-OS |
| Schneier | 6 | [link](https://www.schneier.com/blog/) | DarkSword iOS exploit chain commentary |
| Wired Security | 6 | [link](https://www.wired.com/category/security/) | Long-form context including the Canvas ransomware story |
| Sysdig | 4 | [link](https://webflow.sysdig.com/blog/dirty-frag-cve-2026-43284-and-cve-2026-43500-detecting-unpatched-local-privilege-escalation-via-linux-kernel-esp-and-rxrpc) | Dirty Frag detection logic |
| HaveIBeenPwned | 4 | [link](https://haveibeenpwned.com/) | Zara (197k accounts) and Marcus & Millichap breach feeds |
| Cisco Talos | 4 | [link](https://blog.talosintelligence.com/) | Threat-research blog posts |
| Elastic Security Labs | 4 | [link](https://www.elastic.co/security-labs/copy-fail-dirtyfrag-linux-page-bugs-in-the-wild) | Detection logic for Copy Fail and Dirty Frag |
| Unit42 | — | [link](https://unit42.paloaltonetworks.com/cve-2026-31431-copy-fail/) | Copy Fail deep-dive |
| Upwind | — | [link](https://www.upwind.io/feed/mini-shai-hulud-npm-supply-chain-worm) | Mini Shai-Hulud and Dirty Frag analyses |
| CERT-EU | — | [link](https://cert.europa.eu/publications/security-advisories/2026-006/) | Advisory 2026-006 (PAN-OS) |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Patch or mitigate PAN-OS CVE-2026-0300 on every Internet-exposed PA-Series and VM-Series firewall. If patches are not yet deployed, disable the User-ID Authentication Portal or restrict it to trusted zones; hunt the last 30 days for nginx crash-cleanup activity and outbound Earthworm/ReverseSocks5 tunneling.
- 🔴 **IMMEDIATE:** Patch Ivanti EPMM to 12.6.1.1 / 12.7.0.1 / 12.8.0.1 within four days per the CISA emergency directive; rotate admin credentials and review the past 60 days of admin authentication logs.
- 🔴 **IMMEDIATE:** Apply the Linux kernel updates that fix Copy Fail (CVE-2026-31431) before the 15 May CISA deadline; in environments where patching lags, follow Linux Foundation interim guidance to disable the vulnerable `algif_aead` module.
- 🔴 **IMMEDIATE:** Deploy the Dirty Frag modprobe blocklist (`esp4`, `esp6`, `rxrpc`) on every Linux host that does not require IPsec or AFS; subscribe to distro advisories for upstream patches.
- 🟠 **SHORT-TERM:** Patch MOVEit Automation to 2025.1.5 / 2025.0.9 / 2024.1.8; treat MFT platforms as the most attractive targets for data-theft extortion based on the 2023 Clop precedent.
- 🟠 **SHORT-TERM:** Sweep SBOMs, lockfiles and CI build caches for `intercom-client@7.0.4`; on every affected runner rotate cloud credentials, registry tokens and signing keys; audit `.github/workflows/` across all repositories for unexplained Dependabot-disguised changes.
- 🟠 **SHORT-TERM:** Patch the Apache HTTP Server triple (CVE-2026-23918 / 24072 / 33523) and the Redis-family bulletins (CVE-2026-23479 / 23631 / 25243 / 25588 / 25589); enforce `requirepass`/ACL authentication and non-public binding on every Redis instance.
- 🟡 **AWARENESS:** Brief macOS user populations on the new Google Ads + Claude.ai-shared-chat malware delivery vector; train staff that copy-pasting installer commands from any shared chat link is high-risk.
- 🟡 **AWARENESS:** Sustain ransomware-monitoring posture against Qilin, The Gentlemen, Akira, DragonForce, ShinyHunters, Genesis, Inc Ransom and Lamashtu — pipeline correlation places all in steady multi-sector campaigns.
- 🟢 **STRATEGIC:** Reduce edge-device exposure following the cumulative PAN-OS / Ivanti / FortiClient EMS / MOVEit pattern; align with CISA Binding Operational Directive 26-02 and remove EoL network appliances from public-facing footprint.
- 🟢 **STRATEGIC:** Treat Bun, Deno and other Node.js-alternate runtimes downloaded mid-build as suspicious by default in CI environments; constrain CI runners to a vetted toolchain allow-list.

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 559 reports processed across 13 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
