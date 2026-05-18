---
layout: post
title:  "CTI Weekly Brief: 11 to 17 May 2026 - Actively exploited Cisco SD-WAN zero-day, npm supply-chain worm hits TanStack/UiPath, Windows BitLocker and MiniPlasma zero-days, and a Qilin/Chaos/Stormous RaaS surge"
date:   2026-05-18 20:48:50 +0000
description: "CISA-mandated emergency patching of Cisco SD-WAN CVE-2026-20182; coordinated npm/PyPI supply-chain compromises (TanStack, UiPath, Mistral, node-ipc) by TeamPCP and a separate maintainer-account hijack; unpatched Windows MiniPlasma SYSTEM and BitLocker bypass PoCs from Chaotic Eclipse; mass-exploited WordPress flaws (Funnel Builder, Burst Statistics); 18-year-old NGINX heap overflow; Exim, SAP, Fortinet and PostgreSQL criticals; Secret Blizzard's Kazuar evolves into a modular P2P botnet; and a >170-victim RaaS surge dominated by Qilin, DragonForce, Stormous and Chaos."
category: weekly
tags: [cti, weekly-brief, qilin, dragonforce, stormous, teampcp, secret-blizzard, cve-2026-20182, cve-2026-42945, cve-2026-45185, cve-2026-8181]
classification: TLP:CLEAR
reporting_period_start: "2026-05-11"
reporting_period_end: "2026-05-17"
generated: "2026-05-18"
draft: false
severity: critical
report_count: 403
sources:
  - RansomLook
  - Microsoft
  - BleepingComputer
  - CISA
  - RecordedFutures
  - AlienVault
  - SANS
  - Upwind
  - Schneier
  - Wired Security
  - Cisco Talos
  - Wiz
  - Crowdstrike
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 11 May 2026 to 17 May 2026 (7d) | TLP:CLEAR | 2026-05-18 |

## 1. Executive Summary

The pipeline ingested 403 reports across 15 distinct sources over the week of 11–17 May 2026, with 29 rated critical and 256 rated high. The week was dominated by three converging story lines: (1) confirmed in-the-wild exploitation of a maximum-severity authentication bypass in Cisco Catalyst SD-WAN (CVE-2026-20182, CVSS 10.0), which CISA added to the KEV catalogue with a Sunday 17 May patching deadline for federal agencies; (2) a second wave of the "Mini Shai-Hulud" npm/PyPI supply-chain campaign by TeamPCP, which compromised @tanstack, @uipath, @mistralai and guardrails-ai packages on 11–12 May, followed two days later by a separate credential-stealing payload smuggled into three malicious node-ipc releases through a legitimate maintainer account; and (3) a public string of unpatched Windows zero-days from researcher "Chaotic Eclipse" — MiniPlasma (SYSTEM privilege escalation via cldflt.sys), YellowKey (BitLocker bypass via WinRE) and GreenPlasma — all shipped with working PoCs.

The product backdrop was just as heavy. May 2026 Patch Tuesday delivered 130 CVEs of which 30 are critical, SAP fixed unauthenticated RCE in Commerce Cloud and SQL injection in S/4HANA, Fortinet patched critical RCE in FortiSandbox and FortiAuthenticator, an 18-year-old heap overflow surfaced in NGINX's rewrite module (CVE-2026-42945), and Exim shipped an emergency fix for an unauthenticated user-after-free RCE in GnuTLS builds (CVE-2026-45185). Two WordPress plugins — Funnel Builder (40k sites, active credit-card skimmer injection) and Burst Statistics (200k sites, CVE-2026-8181 with 7,400 attacks blocked in 24h) — were under active mass exploitation. A Theori-disclosed Linux kernel LPE ("Copy.Fail") works across every major distribution without per-distro tuning. On the espionage front, AlienVault and partners detailed Secret Blizzard's evolution of the Kazuar backdoor into a modular peer-to-peer botnet targeting European and Central Asian government and defence. Ransomware leak-site volume was extreme: RansomLook accounted for 173 of 403 reports, with Qilin (32 mentions), Stormous (15), The Gentlemen (11), Akira (9), DragonForce (9), Inc Ransom (7) and a fast-moving newcomer "Chaos" all running concurrent intrusions, and Tycoon2FA returning to full operations with new device-code phishing tradecraft against Microsoft 365.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 29 | Cisco SD-WAN CVE-2026-20182 (KEV); npm/node-ipc supply chain; Windows MiniPlasma/BitLocker zero-days; NGINX CVE-2026-42945; Exim CVE-2026-45185; Fortinet RCE; SAP Commerce Cloud + S/4HANA; Copy.Fail Linux kernel; PostgreSQL/libyang/.NET criticals; Patch Tuesday |
| 🟠 **HIGH** | 256 | Sustained RaaS leak-site activity (Qilin, DragonForce, Stormous, Chaos, M3rx, The Gentlemen, Akira, Inc Ransom, Everest); Tycoon2FA device-code phishing; healthcare and government sector intrusions |
| 🟡 **MEDIUM** | 46 | Geopolitical scam lures; vendor advisories; secondary CVE batches |
| 🟢 **LOW** | 14 | Routine vendor notices and low-impact disclosures |
| 🔵 **INFO** | 58 | Threat actor profile updates, pipeline housekeeping, vendor blogs |

## 3. Priority Intelligence Items

### 3.1 Cisco Catalyst SD-WAN authentication bypass (CVE-2026-20182) actively exploited; CISA emergency directive

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/cisco-warns-of-new-critical-sd-wan-flaw-exploited-in-zero-day-attacks/), [The Record / Recorded Future](https://therecord.media/cisa-orders-all-federal-agencies-to-patch-cisco-sd-wan-bug)

Cisco disclosed CVE-2026-20182 in Catalyst SD-WAN Controller and SD-WAN Manager on 14 May with a CVSS score of 10.0. The flaw is in the peering authentication mechanism: an unauthenticated remote attacker can present themselves to the controller as a trusted router, obtain a high-privileged internal account, and pivot via NETCONF to alter SD-WAN fabric configuration. Cisco confirmed exploitation in May 2026 and Rapid7 (which discovered the bug while researching the February 2026 CVE-2026-20127 campaign by UAT-8616) likened the controller's behaviour to a "master key". CISA added the CVE to KEV the same day and required federal agencies to patch by Sunday 17 May, citing the prior emergency directive co-issued with Five Eyes partners. No workaround fully mitigates the issue. Affected sectors: telecom, finance, government, MSPs running Catalyst SD-WAN on-prem or cloud.

#### Indicators of Compromise

```
Log file: /var/log/auth.log
Pattern: Accepted publickey for vmanage-admin from <unknown IP>
Example: 2026-02-10T22:51:36+00:00 vm sshd[804]: Accepted publickey for vmanage-admin from <REDACTED> ssh2: RSA SHA256:<REDACTED>
Verification: Compare source IPs against System IPs configured in Cisco Catalyst SD-WAN Manager (WebUI > Devices > System IP).
```

MITRE: T1071 (Application Layer Protocol), T1548.002 (Abuse Elevation Control Mechanism), T1098 (Account Manipulation).

> **SOC Action:** Patch every Catalyst SD-WAN Controller and Manager instance to the fixed train immediately. Restrict management/control-plane interfaces to explicit IP allowlists. Pull /var/log/auth.log from every controller, extract all `Accepted publickey for vmanage-admin` entries from the past 60 days, and reconcile each source IP against the System IP list — treat any unrecognised peer as a compromised device and open a Cisco TAC case. Alert on `NETCONF` config changes that do not correlate to a known change ticket.

### 3.2 Coordinated npm/PyPI supply-chain attacks: "Mini Shai-Hulud" (TanStack/UiPath/Mistral) and node-ipc credential theft

**Source:** [Wiz](https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised), [Upwind](https://www.upwind.io/feed/malicious-node-ipc-npm-package-credential-theft)

Two distinct supply-chain campaigns landed in the same 72-hour window. On 11–12 May, threat actor **TeamPCP** compromised packages in the @tanstack namespace (including @tanstack/react-router, ~12M weekly downloads), @uipath (apollo-core, CLI, agent SDKs), @mistralai/mistralai (npm and PyPI), and the guardrails-ai Python package. The TanStack vector chained three GitHub Actions weaknesses: an attacker fork (zblgg/configuration) triggered a `pull_request_target` workflow that poisoned the pnpm cache, which a later maintainer merge restored, allowing attacker binaries to read OIDC tokens directly from `/proc/<pid>/mem` on the runner and publish without ever stealing npm credentials. The published packages carry two infection vectors: an `optionalDependencies` entry pointing to an orphan commit that runs a `prepare` script, plus an embedded ~2.3MB obfuscated `router_init.js`. The payload steals CI/CD tokens (GitHub Actions OIDC, GitLab, CircleCI), cloud credentials (AWS IMDSv2, GCP, Azure), Kubernetes service accounts, HashiCorp Vault and registry tokens, then self-propagates by republishing poisoned versions of any package the victim has write access to. Exfiltration runs over a typosquat domain (`git-tanstack[.]com`), the Session messenger network, and GitHub API dead drops. A persistent `gh-token-monitor` daemon (macOS LaunchAgent / Linux systemd) polls GitHub every 60s and, on a 40x response, attempts `rm -rf ~/`. The malware checks for a Russian-language locale and exits cleanly if detected.

On 14 May, three malicious versions (9.2.2, 9.2.3, 12.0.1) of the unrelated `node-ipc` package (~3.35M monthly downloads) were published through the legitimate maintainer account `atiertant` after ~20 months of inactivity, with byte-identical obfuscated payloads appended to `node-ipc.cjs`. The package's `main`/`exports` was rewritten so that every `require('node-ipc')` silently runs the malicious bundle while ESM imports look clean. The payload harvests developer, CI/CD, cloud, Kubernetes, SSH and AI-tooling credentials and exfiltrates via DNS TXT queries to attacker infrastructure (domain `azurestaticprovider[.]net` registered hours before publication).

#### Indicators of Compromise

```
TanStack / TeamPCP campaign
Exfil domain: git-tanstack[.]com
Embedded payload: router_init.js (~2.3MB, obfuscated)
Fork repo: zblgg/configuration
Orphan commit: github:tanstack/router#79ac49eedf774dd4b0cfa308722bc463cfe5885c
Channels: Session messenger; GitHub API dead-drops via stolen OIDC tokens
Persistence: gh-token-monitor LaunchAgent (macOS) / systemd unit (Linux)
Affected packages (partial): @tanstack/react-router, @uipath/apollo-core, @mistralai/mistralai (npm + PyPI), guardrails-ai

node-ipc credential stealer
Malicious versions: node-ipc 9.2.2, 9.2.3, 12.0.1
Maintainer account abused: atiertant
Exfil domain: azurestaticprovider[.]net
Exfil C2 IP: 37.16.75[.]69
Exfil method: DNS TXT queries
Detection time: 2026-05-14 17:45 UTC
```

MITRE: T1195.002 (Compromise Software Supply Chain), T1059.001 (PowerShell/scripting), T1071.004 (DNS C2), T1567.002 (Exfiltration over DNS), T1078 (Valid Accounts), T1098 (Account Manipulation).

> **SOC Action:** Block egress to `git-tanstack[.]com`, `azurestaticprovider[.]net` and `37.16.75[.]69` at the proxy/DNS layer. Pin npm and pip dependency versions; reject installs of @tanstack, @uipath, @mistralai and guardrails-ai versions from 11–12 May 2026 until vetted. Rotate all CI/CD tokens, npm/PyPI publish tokens, GitHub Actions OIDC trust relationships, AWS IMDS roles, GCP service-account keys and HashiCorp Vault tokens used by any build that ran during the window. Hunt for `gh-token-monitor` LaunchAgents/systemd units on developer endpoints, for `optionalDependencies` referencing orphan commits, and for DNS TXT egress to recently-registered domains. Disable `pull_request_target` workflows that check out untrusted PR code unless absolutely required.

### 3.3 Mass-exploited WordPress flaws — Funnel Builder credit-card skimming and Burst Statistics auth bypass (CVE-2026-8181)

**Source:** [BleepingComputer (Funnel Builder)](https://www.bleepingcomputer.com/news/security/funnel-builder-wordpress-plugin-bug-exploited-to-steal-credit-cards/), [BleepingComputer (Burst Statistics)](https://www.bleepingcomputer.com/news/security/hackers-exploit-auth-bypass-flaw-in-burst-statistics-wordpress-plugin/)

Sansec detected active exploitation of an unauthenticated vulnerability in FunnelKit's **Funnel Builder** WooCommerce plugin (all versions <3.15.0.3, ~40,000 installs). An exposed checkout endpoint accepts unauthenticated modifications to the plugin's global "External Scripts" setting, allowing attackers to inject a JavaScript payment-card skimmer that runs on every checkout page and steals card numbers, CVVs, billing addresses and other PII. The injected payload is disguised as a Google Tag Manager/Google Analytics loader and opens a WebSocket back-channel to attacker infrastructure. Patched in 3.15.0.3 on 14 May.

Separately, **Burst Statistics** (200,000 active installs) shipped CVE-2026-8181 in 3.4.0 (released 23 April) and patched in 3.4.2 on 12 May. Wordfence discovered the bug on 8 May and recorded 7,400+ blocked attacks in 24 hours after publication. The plugin misinterprets `wp_authenticate_application_password()` results: a `WP_Error` (or a `null` return) is treated as a successful authentication, so any unauthenticated REST API request supplying a known admin username and arbitrary password causes WordPress to call `wp_set_current_user()` with that username. Worst case: creation of new administrator accounts via `/wp-json/wp/v2/users` with no prior authentication. Roughly 115,000 sites likely remain unpatched.

#### Indicators of Compromise

```
Funnel Builder skimmer
Skimmer loader URL: hxxps[:]//analytics-reports[.]com/wss/jquery-lib.js
C2 WebSocket: wss[:]//protect-wss[.]com/ws
Disguised as: Google Tag Manager / Google Analytics
Audit: WordPress > Settings > Checkout > External Scripts

Burst Statistics (CVE-2026-8181)
Affected: Burst Statistics 3.4.0, 3.4.1
Fixed: 3.4.2 (2026-05-12)
Hunt: Recent unexpected administrator accounts; REST API hits to /wp-json/wp/v2/users with Basic auth and invalid passwords
```

MITRE: T1190 (Exploit Public-Facing Application), T1078.004 (Valid Accounts: Application Service), T1059.007 (JavaScript), T1056.003 (Web Portal Capture), T1071.001 (Web Protocols).

> **SOC Action:** Inventory WooCommerce sites for Funnel Builder <3.15.0.3 and force-update. Block egress to `analytics-reports[.]com` and `protect-wss[.]com`. Diff the Funnel Builder External Scripts setting against a known-good baseline and remove any unrecognised entries. For Burst Statistics, push 3.4.2 immediately or disable the plugin; review WordPress users for unexpected administrator accounts created since 23 April; alert on `/wp-json/wp/v2/users` POSTs from unauthenticated sources and on Basic-Auth REST API requests that supply a known admin username with an invalid password.

### 3.4 Public Windows zero-days from "Chaotic Eclipse" — MiniPlasma SYSTEM exploit and BitLocker bypass (YellowKey/GreenPlasma)

**Source:** [BleepingComputer (MiniPlasma)](https://www.bleepingcomputer.com/news/microsoft/new-windows-miniplasma-zero-day-exploit-gives-system-access-poc-released/), [BleepingComputer (BitLocker)](https://www.bleepingcomputer.com/news/security/windows-bitlocker-zero-day-gives-access-to-protected-drives-poc-released/)

Researcher **Chaotic Eclipse** (a.k.a. Nightmare Eclipse) released three unpatched Windows exploits this week, continuing a disclosure campaign that already produced BlueHammer (CVE-2026-33825) and RedSun in April. **MiniPlasma** (17 May) is a local privilege escalation in the `cldflt.sys` Cloud Filter driver: the undocumented `CfAbortHydration` API allows arbitrary registry keys to be created in the `.DEFAULT` hive without access checks (originally reported by Google Project Zero's James Forshaw as CVE-2020-17103 in 2020 and reportedly fixed in December 2020). BleepingComputer and Tharros Labs both confirmed the PoC succeeds on a fully patched Windows 11 Pro with May 2026 Patch Tuesday applied; the latest Insider Canary build is not vulnerable. **YellowKey** (13 May) is a BitLocker bypass affecting Windows 11 and Server 2022/2025: planting crafted `FsTx` files on a USB drive or EFI partition, then forcing a reboot into WinRE while holding CTRL, replays NTFS logs that delete `X:\Windows\System32\winpeshl.ini` and spawn `cmd.exe` with the BitLocker volume still unlocked. Independent researchers (Kevin Beaumont, Will Dormann) verified the exploit; Chaotic Eclipse claims the underlying issue is exploitable even with TPM+PIN but is withholding that PoC. **GreenPlasma** is a separate, unpatched LPE released alongside YellowKey. Source PoCs and compiled binaries for all three are publicly available on GitHub.

#### Indicators of Compromise

```
MiniPlasma LPE
Driver: cldflt.sys (Windows Cloud Filter)
API abused: CfAbortHydration
Target hive: HKEY_USERS\.DEFAULT

YellowKey BitLocker bypass
Artefact path: \System Volume Information\FsTx\* on USB / EFI partition
Trigger: Reboot into WinRE while holding CTRL
Side effect: X:\Windows\System32\winpeshl.ini deleted; cmd.exe spawned with disk unlocked
Affected: Windows 11; Windows Server 2022 / 2025; default TPM-only BitLocker
```

MITRE: T1068 (Exploitation for Privilege Escalation), T1542.003 (Bootkit), T1003.003 (NTDS), T1078.003 (Local Accounts), T1059.003 (cmd).

> **SOC Action:** Enforce **TPM+PIN** (and ideally a BIOS/UEFI password) on every BitLocker-protected endpoint; default TPM-only configurations are bypassable. Hunt for the creation of `\System Volume Information\FsTx` directories on removable media and EFI System Partitions, for missing `winpeshl.ini` on recovery partitions, and for unexpected boots into WinRE. On MiniPlasma, alert on registry-key creation under `HKEY_USERS\.DEFAULT` by non-SYSTEM processes and on unsigned binaries calling `CfAbortHydration` against `cldflt.sys`. Block unauthorised binary execution from user-writable directories with WDAC/AppLocker. Track Chaotic Eclipse's GitHub for further releases ahead of June Patch Tuesday — the researcher has signalled "a big surprise".

### 3.5 NGINX CVE-2026-42945, Exim CVE-2026-45185 and Copy.Fail Linux kernel LPE

**Source:** [BleepingComputer (NGINX)](https://www.bleepingcomputer.com/news/security/18-year-old-nginx-vulnerability-allows-dos-potential-rce/), [BleepingComputer (Exim)](https://www.bleepingcomputer.com/news/security/new-critical-exim-mailer-flaw-allows-remote-code-execution/), [Schneier on Security](https://jorijn.com/en/blog/copy-fail-cve-2026-31431-linux-kernel-bug-explained/)

Three high-impact Linux/open-source vulnerabilities landed within 36 hours. **CVE-2026-42945** is an 18-year-old heap buffer overflow in NGINX's `ngx_http_rewrite_module` (versions 0.6.27–1.30.0, CVSS 9.2), uncovered by AI-native vendor DepthFirst. NGINX configurations that combine `rewrite` and `set` directives — common in API gateways and reverse proxies — leave an `is_args` flag set after rewrites containing `?`, causing the engine to under-allocate then over-write the buffer with escaped data. DepthFirst demonstrated unauthenticated RCE on systems with ASLR disabled (still common in embedded/VM environments); NGINX's multi-process model lets attackers retry reliably because workers inherit identical layouts from the master. Three additional flaws were found in the same six-hour scan: CVE-2026-42946 (excessive SCGI/UWSGI allocation → worker crash, high), CVE-2026-40701 (OCSP DNS UAF, medium), CVE-2026-42934 (UTF-8 OOB read, medium). **CVE-2026-45185** is an unauthenticated user-after-free RCE in Exim ≤4.99.2 builds compiled with GnuTLS that advertise STARTTLS and CHUNKING (OpenSSL builds unaffected). Triggered during TLS shutdown while processing BDAT chunked SMTP, Exim frees a TLS buffer but later writes through stale callback references. Patched in 4.99.3; reported by XBOW's Federico Kirschbaum with an AI-assisted PoC race against XBOW Native. **Copy.Fail** (disclosed by Theori on 29 April, picked up by Schneier this week) is a Linux kernel LPE that abuses AF_ALG sockets and `splice()` to write four bytes at a time directly into the page cache of files the attacker does not own — no race condition, no per-distro tuning, and the file on disk is never modified, so AIDE/Tripwire and checksum-based monitoring see nothing. Confirmed working on Ubuntu, RHEL, Debian, SUSE, Amazon Linux and Fedora.

MITRE: T1190 (Exploit Public-Facing Application), T1068 (Exploitation for Privilege Escalation), T1027 (Obfuscated Files / Anti-Forensics), T1059 (Command and Scripting Interpreter).

> **SOC Action:** Upgrade NGINX to 1.30.1 (or the F5 NGINX Plus equivalent); ensure ASLR is enabled on every NGINX host; review configurations that combine `rewrite` with `set` and remove redundant patterns. Patch Exim to 4.99.3 on Debian/Ubuntu/RHEL and any third-party MTAs; if a build cannot be updated immediately, disable STARTTLS+CHUNKING on GnuTLS-linked builds or recompile against OpenSSL. For Copy.Fail, apply kernel updates from each distro the moment they are released and, in the interim, restrict `AF_ALG` socket access via SELinux/AppArmor policy or `modprobe.d` blacklists where the workload allows. Because Copy.Fail is invisible to file-integrity monitoring, prioritise behavioural EDR signatures over hash comparisons for system binaries.

### 3.6 Fortinet criticals (FortiSandbox CVE-2026-26083, FortiAuthenticator CVE-2026-44277) and SAP Commerce Cloud / S/4HANA

**Source:** [BleepingComputer (Fortinet)](https://www.bleepingcomputer.com/news/security/fortinet-warns-of-critical-rce-flaws-in-fortisandbox-and-fortiauthenticator/), [BleepingComputer (SAP)](https://www.bleepingcomputer.com/news/security/sap-fixes-critical-vulnerabilities-in-commerce-cloud-and-s-4hana/)

Fortinet patched two unauthenticated RCE flaws on 12 May. **CVE-2026-26083** is a missing-authorisation weakness (CWE-862) in FortiSandbox / FortiSandbox Cloud / FortiSandbox PaaS WEB UI that lets an unauthenticated attacker execute commands via crafted HTTP requests. **CVE-2026-44277** is an improper access-control flaw (CWE-284) in FortiAuthenticator (IAM appliance), patched in 6.5.7, 6.6.9 and 8.0.3 — FortiAuthenticator Cloud / FortiTrust Identity is not affected. Fortinet did not flag in-the-wild exploitation, but CISA has added 24 Fortinet bugs to KEV in recent years (13 used in ransomware) so the standing exploitation risk is high. SAP's May package shipped 15 fixes, including two criticals: **CVE-2026-34263** is an unauthenticated RCE in SAP Commerce Cloud caused by a Spring Security misconfiguration that allows malicious configuration upload and code injection on the server; **CVE-2026-34260** is a low-complexity SQL injection in S/4HANA exploitable by a basic-privileged user via unsanitised input concatenated into SQL queries.

MITRE: T1190 (Exploit Public-Facing Application), T1068 (Exploitation for Privilege Escalation), T1059 (Command and Scripting Interpreter), T1505.003 (Web Shell — potential post-exploitation).

> **SOC Action:** Patch FortiSandbox immediately; restrict the FortiSandbox and FortiAuthenticator management interfaces to dedicated administration networks; alert on unauthenticated HTTP POSTs to FortiSandbox WEB UI endpoints and on FortiAuthenticator API calls without a valid session cookie. Upgrade SAP Commerce Cloud to the patched release; review the Spring Security configuration for permissive endpoints; in S/4HANA, audit user activity for unexpected SELECT/INSERT patterns from low-privilege accounts and ensure WAF/SQLi rules are active in front of S/4HANA. Stage rollouts to validate no service regressions on authentication or commerce checkout flows.

### 3.7 Secret Blizzard's Kazuar backdoor evolves into a modular peer-to-peer botnet

**Source:** [AlienVault OTX](https://otx.alienvault.com/pulse/6a062c383bdae760fc221b6f)

Russian state actor Secret Blizzard (a.k.a. Turla / FSB Centre 16) has transformed the long-running Kazuar (MITRE S0265) backdoor into a fully modular peer-to-peer botnet. The ecosystem uses three module types — Kernel, Bridge and Worker — distributed across infected hosts, with a leadership-election mechanism that ensures only one Kernel module per network communicates externally to reduce detection. The architecture supports 150+ configuration options and multiple C2 channels (HTTP, WebSockets, Exchange Web Services). Targeting remains aligned to Russian foreign policy and military intelligence collection: government, diplomatic and defence organisations in Europe, Central Asia and Ukraine. Operational tradecraft includes anti-analysis checks, staged data exfiltration during local working hours, and sophisticated IPC for persistence. The pulse also names Pelmeni as an associated component and ties activity to the Turla intrusion set.

#### Indicators of Compromise

```
Malware family: Kazuar - S0265 (Secret Blizzard / Turla)
Associated tooling: Pelmeni
SHA-256:
  436cfce71290c2fc2f2c362541db68ced6847c66a73b55487e5e5c73b0636c85
  69908f05b436bd97baae56296bf9b9e734486516f9bb9938c2b8752e152315d4
  6eb31006ca318a21eb619d008226f08e287f753aec9042269203290462eaa00d
  c1f278f88275e07cc03bd390fe1cbeedd55933110c6fd16de4187f4c4aaf42b9
C2 channels: HTTP, WebSockets, Exchange Web Services (EWS)
Targeted regions: Europe, Central Asia, Ukraine
Targeted sectors: Government, Diplomatic, Defence
```

MITRE: T1027/T1027.002 (Obfuscated/Software Packing), T1041 (Exfil over C2), T1055 (Process Injection), T1071/T1071.001/T1071.003 (Application Layer Protocol — Web/Mail), T1090 (Proxy), T1102 (Web Service), T1113 (Screen Capture), T1114/T1114.002 (Email Collection — Remote Email), T1132 (Data Encoding), T1497 (Virtualisation/Sandbox Evasion), T1562.001 (Disable/Modify Tools), T1573 (Encrypted Channel).

> **SOC Action:** Add the four Kazuar SHA-256 hashes above to EDR/AV blocklists. Hunt egress logs for Exchange Web Services traffic from endpoints that are not Outlook/Teams (an unusual C2 channel that often evades web-proxy controls). Alert on anomalous WebSocket or HTTPS traffic patterns from government, diplomatic or defence-tier user populations, especially during local working hours. For Microsoft 365 tenants, hunt for unusual app registrations and OAuth grants against EWS. Inventory mailbox forwarding rules and EWS impersonation rights — both are favoured Turla persistence vectors.

### 3.8 Tycoon2FA returns with OAuth device-code phishing against Microsoft 365

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/tycoon2fa-hijacks-microsoft-365-accounts-via-device-code-phishing/)

Despite an international takedown of the Tycoon2FA phishing-as-a-service infrastructure in March 2026, the operation rebuilt on new infrastructure and, per Abnormal Security and eSentire, is now running a campaign that abuses the OAuth 2.0 device authorization grant flow to hijack Microsoft 365 accounts. Lure emails carry legitimate **Trustifi** click-tracking URLs that chain through Trustifi → Cloudflare Workers → multiple obfuscated JavaScript layers to a fake Microsoft CAPTCHA page. The page pulls a real Microsoft device code from the attacker's backend and prompts the victim to enter it at `microsoft.com/devicelogin` and complete MFA. Microsoft then issues OAuth access and refresh tokens to the attacker-controlled device, granting unrestricted mailbox, calendar, Teams and OneDrive access. Push Security and Proofpoint report a 37× year-over-year surge in device-code phishing supported by at least ten PhaaS kits. Tycoon2FA's anti-analysis blocklist contains 230 vendor names and routes analysis environments to a legitimate Microsoft page.

#### Indicators of Compromise

```
Lure vector: Trustifi click-tracking URLs in invoice-themed phishing emails
Redirect chain: Trustifi → Cloudflare Workers → obfuscated JS → fake Microsoft CAPTCHA
Target endpoint: hxxps[:]//microsoft[.]com/devicelogin (legitimate; abused as relay)
Result: OAuth access + refresh tokens issued to attacker device
Anti-analysis: 230-vendor blocklist (Selenium, Puppeteer, Playwright, Burp, sandboxes, AI crawlers, cloud providers)
```

MITRE: T1566 (Phishing), T1566.002 (Spearphishing Link), T1078.004 (Valid Accounts: Cloud), T1098.005 (Account Manipulation: Device Registration), T1550.001 (Use Alternate Authentication Material: Access Tokens).

> **SOC Action:** In Microsoft Entra ID / Conditional Access, **block OAuth device-code authorization for users that do not require it** (block by user/group or limit to managed Windows-Autopilot/IT-admin devices). Alert on `userCode` device-code sign-ins where the resulting device is not Entra-joined, on first-time sign-ins from unmanaged devices, and on the issuance of refresh tokens immediately after a device-code grant. Train users that **no legitimate workflow will email them a code to paste into `microsoft.com/devicelogin`**. Hunt mailbox audit logs for new forwarding rules, OAuth app grants and Outlook desktop registrations from unusual IP/ASN combinations following Trustifi-tracked click events.

### 3.9 RaaS surge: Qilin, DragonForce, Stormous, Chaos, M3rx, The Gentlemen and Akira dominate leak-site volume

**Source:** [RansomLook (Qilin)](https://www.ransomlook.io/group/qilin), [RansomLook (DragonForce)](https://www.ransomlook.io/group/dragonforce), [RansomLook (Stormous)](https://www.ransomlook.io/group/stormous), [RansomLook (Chaos)](https://www.ransomlook.io/group/chaos), [RansomLook (M3rx)](https://www.ransomlook.io/group/m3rx)

RansomLook contributed 173 of the week's 403 reports. The dominant pattern is concurrent multi-victim leak-site activity from RaaS programmes targeting healthcare, government, manufacturing, logistics, education, retail and the legal sector across the Americas, Europe, Asia-Pacific and the Middle East. **Qilin** (32 mentions this week, 123 across the trailing 30 days) listed Salter HealthCare, Majlis Perbandaran Alor Gajah, PNSB Insurance Brokers, Buckeye Paper, Musée du Bas-Saint-Laurent, The Taylor Provisions, Monir Precision Monitoring, Fruits Queralt and others — RansomLook correlated nine of those into a single 0.95-confidence actor cluster. **Stormous** (15 mentions, with strong correlation to GhostSec) ran a coordinated dump campaign against Cuban ministries (Foreign Trade, Culture, Energy and Mines) plus PT Kereta Api Indonesia, Nipun Consultancy and Moroccan bank-card data (50,000+ records). **DragonForce** continued its post-hacktivist RaaS evolution with AdvancedHEALTH (multiple postings), Ingelan and "Plan" — cluster includes Retail, Government, Logistics and Manufacturing sectors. **Chaos**, a newer RaaS, listed wtitransport.com, cstindustries.com, fallprotect.com and challenge-mfg.com in a single day with a 0.90-confidence cluster — the group operates Windows/ESXi/Linux/NAS payloads and reaches initial access via phishing, valid accounts and brokered credentials. **M3rx** posted Grupo 55, Dosocho, SOFT Inc., Società Produttori Sementi, Alge-Stop, Pemberton Valley Dyking District and Datasavior with 49.8–364 GB data leaks. **Inc Ransom**, **The Gentlemen**, **Akira**, **Coinbase Cartel**, **Lamashtu**, **ShinyHunters**, **Everest** and **Genesis** all logged multiple victims in the same period.

MITRE (composite): T1566 / T1566.001/002 (Phishing), T1078 (Valid Accounts), T1133 (External Remote Services), T1190 (Exploit Public-Facing Application), T1486 (Data Encrypted for Impact), T1485 (Data Destruction), T1496 (Resource Hijacking), T1059 (Command and Scripting Interpreter), T1071 (Application Layer Protocol).

> **SOC Action:** Treat any leak-site debut for an organisation in your portfolio as a confirmed compromise occurring 2–8 weeks earlier — pivot to incident response timelines accordingly. For Qilin specifically, hunt for `README-RECOVER-[rand]_2.txt` ransom notes and process trees that include the DtMXQFOCos encryptor; for Stormous, monitor for Tox2 protocol egress and bulk data movement to onion endpoints; for Chaos, scan ESXi hosts for new SSH keys and unsigned binaries dropped to `/tmp` and `/var/tmp`. Enforce phishing-resistant MFA (FIDO2 / Windows Hello / certificate-based) on every external-facing identity given how universally T1566 dominates this week's correlation evidence (128 mentions of T1566 Phishing across the pipeline). Validate that immutable backups are isolated from domain credentials and test full ESXi/NAS restoration paths.

### 3.10 May 2026 Patch Tuesday: 130 CVEs (30 critical) and ongoing Pwn2Own Berlin 2026 fallout

**Source:** [CrowdStrike](https://www.crowdstrike.com/en-us/blog/patch-tuesday-analysis-may-2026/), [BleepingComputer Pwn2Own coverage](https://www.bleepingcomputer.com/)

Microsoft's May 2026 Patch Tuesday on 13 May covered 130 CVEs, of which 30 were rated critical. Notable items appearing in correlation feeds include CVE-2026-32177 and CVE-2026-35433 (.NET elevation of privilege) and CVE-2026-42897 (Exchange Server spoofing). The same week, Pwn2Own Berlin 2026 paid out $1,298,250 for 47 zero-days against enterprise technologies; the pipeline flagged Microsoft Exchange, Windows 11 and Mozilla Firefox as among the targets compromised on day two. Critical PostgreSQL fixes also landed (CVE-2026-6477 libpq lo_*, CVE-2026-6638 REFRESH PUBLICATION SQLi, CVE-2026-6473 integer wraparound, CVE-2026-6478 MD5 password timing leak, CVE-2026-6472 multirange CREATE TYPE privilege check, CVE-2026-6637 refint stack buffer overflow/SQLi, CVE-2026-6667 PgBouncer missing auth on KILL_CLIENT), libyang CVE-2026-44673 (lyb_read_string integer overflow → heap buffer overflow), CVE-2026-44283 etcd PrevKv RBAC bypass and CVE-2026-44662 rust-openssl heap buffer overflow.

> **SOC Action:** Stage the May 2026 Microsoft update across pilot → broad rings within seven days; prioritise .NET, Exchange and any internet-facing Windows services. For database fleets, patch PostgreSQL minor versions on all replicas first, then primaries; rotate any MD5-stored passwords as a defence-in-depth move against CVE-2026-6478 timing leakage; review PgBouncer ACLs to deny `KILL_CLIENT` from non-admin networks until upgraded. Re-baseline Exchange spoofing detections (T1036 Masquerading / T1078 Valid Accounts) after applying CVE-2026-42897. Track Pwn2Own outcomes through vendor PSIRT advisories — assume exploit code becomes public within 90 days for any chain that has been publicly demonstrated.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Exploitation of vulnerabilities in widely-used software components | CVE-2026-44662 rust-openssl heap overflow; CVE-2026-6477 PostgreSQL libpq lo_* memory overwrite (batch 127) |
| 🔴 **CRITICAL** | Exploitation of widely-used software for financial gain | Funnel Builder WordPress credit-card skimmer; >$10M theft from THORChain (batch 126) |
| 🔴 **CRITICAL** | Exploitation of zero-days in Microsoft Exchange and Cisco SD-WAN | Microsoft Exchange + Windows 11 hacked on Pwn2Own day 2; ongoing Cisco Catalyst SD-WAN exploitation (batch 125) |
| 🔴 **CRITICAL** | Mass exploitation of authentication bypasses in WordPress plugins and Cisco SD-WAN | Burst Statistics CVE-2026-8181; Cisco SD-WAN CVE-2026-20182 (batch 124) |
| 🔴 **CRITICAL** | Actively exploited .NET elevation-of-privilege chain | CVE-2026-32177; CVE-2026-35433 (batch 123) |
| 🔴 **CRITICAL** | Rapid weaponisation of newly disclosed primitives (Windows BitLocker, Apache Thrift, Vim) | YellowKey/GreenPlasma BitLocker PoCs; CVE-2026-44656 Vim OS command injection; CVE-2026-45130 Vim heap overflow (batch 121) |
| 🔴 **CRITICAL** | Coordinated supply-chain compromises of npm and PyPI ecosystems | TanStack/UiPath/Mistral/guardrails-ai (TeamPCP); node-ipc credential stealer; Shai-Hulud worm (batches 118–119) |
| 🟠 **HIGH** | RaaS surge targeting diverse global sectors | Coinbase Cartel (Zywave, Grafana); Qilin (Turner Supply, Australian College of Business Intelligence, NR Engineering, Generation Life, Menzies Group); DragonForce (LeRoy Surveyors) — batch 126 |
| 🟠 **HIGH** | Healthcare-sector ransomware concentration | Qilin (CLINICA AVELLANEDA, Spirit Medical Transport, Salter HealthCare, B.Care Medical Center); Exitium (Gastroenterology & Hepatology of CNY) — batches 125–127 |
| 🟠 **HIGH** | Chaos RaaS double-extortion across construction, transport and manufacturing | wtitransport.com, cstindustries.com, fallprotect.com, challenge-mfg.com (batch 128 / 2026-05-18) |
| 🟠 **HIGH** | Phishing as a near-universal initial-access TTP | Tycoon2FA device-code phishing; multiple RaaS clusters (Qilin, DragonForce, Stormous) running T1566 — 128 pipeline-wide mentions |
| 🟠 **HIGH** | Supply-chain attacks expanding into software development and AI tooling | node-ipc credential theft; backdoored Cemu release linked to TanStack/Mistral campaign (batch 123) |
| 🟠 **HIGH** | State-sponsored actors operating inside trust boundaries with legitimate tools | "Vibe Hacking" against LatAm government/financial; ongoing state-sponsored access-broker reporting (batch 119) |
| 🟡 **MEDIUM** | Geopolitical instability leveraged for cybercrime lures | "Why geopolitical turmoil is a gift for scammers" (batch 127) |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **Qilin** (123 reports, 32 mentions this week) — Most active RaaS this period; healthcare and government concentration across Asia-Pacific, Europe and the Americas
- **The Gentlemen** (59 reports) — Aggressive multi-sector RaaS — telecommunications, retail, transportation, education, manufacturing, healthcare
- **Akira** (59 reports) — Sustained ransomware operations against architecture, manufacturing and broadcasting
- **ShinyHunters** (29 reports) — Education-platform extortion; Canvas portal defacement
- **Inc Ransom** (26 reports) — Aerospace, legal, agribusiness double-extortion
- **Everest** (24 reports) — Database leak claims (Citizens Bank, Studio Marchi)
- **TeamPCP** (23 reports) — npm/PyPI supply-chain operator behind Mini Shai-Hulud and TanStack/UiPath/Mistral compromises
- **Coinbase Cartel** (17 reports) — Cross-sector RaaS; Zywave, Grafana victim disclosures
- **FulcrumSec** (17 reports) — Active during weeks prior; no fresh activity 11–17 May
- **DragonForce** (16 reports, 9 this week) — Hacktivist origins, now financially motivated; cartel-like affiliate model
- **Stormous** (15 reports) — Cuban ministry data dumps; GhostSec collaboration
- **Lamashtu** (14 reports) — Food-sector intrusions (Parle Agro)
- **Lockbit5** (14 reports) — Activity tail-off in this window
- **M3rx** (13 reports) — European and North American targeting; 49.8–364 GB victim leaks
- **Chaos** (emerging cluster) — Construction, transport, manufacturing double-extortion
- **Secret Blizzard / Turla** — Kazuar modular P2P botnet, government and defence targeting
- **Chaotic Eclipse / Nightmare Eclipse** — Public Windows zero-day discloser (MiniPlasma, YellowKey, GreenPlasma, BlueHammer, RedSun)
- **UAT-8616** — Prior Cisco Catalyst SD-WAN exploitation (CVE-2026-20127), referenced in this week's CVE-2026-20182 reporting

### Malware Families

- **RansomLook (collector)** (127 reports) — Pipeline tag for leak-site ingestion (not a malware family per se)
- **Akira ransomware** (32 reports) — Active encryption and double-extortion
- **Tox1 / Tox / Tox2** (31 / 18 / 8 reports) — Communication/payload aliases used across ransomware clusters; Tox2 strongly correlated with Stormous this week
- **Qilin** (14 reports tagged as malware family) — Encryptor builds tied to the Qilin RaaS
- **The Gentlemen ransomware** (10 reports) — Coordinated multi-sector campaign
- **Everest ransomware** (10 reports) — Database extortion variant
- **Chaos Ransomware** (7 reports) — New double-extortion RaaS with Windows/ESXi/Linux/NAS variants
- **Kazuar — S0265** — Russian state P2P botnet; Pelmeni associated tooling
- **Mini Shai-Hulud** — Self-propagating npm credential-stealing worm (TeamPCP)
- **Credential-stealing malware (node-ipc payload)** — DNS-TXT exfiltration to azurestaticprovider[.]net
- **Tycoon2FA** — Phishing-as-a-service kit, now with OAuth device-code grant abuse
- **AdvancedHEALTH** — Malware/branding correlated with DragonForce activity this week

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| RansomLook | 173 | [link](https://www.ransomlook.io/) | Leak-site aggregation — Qilin, DragonForce, Stormous, Chaos, M3rx, Akira, Inc Ransom, The Gentlemen, Everest victim postings |
| Microsoft | 64 | [link](https://msrc.microsoft.com/update-guide) | MSRC advisories incl. PostgreSQL, libyang, etcd, .NET, Exchange CVEs |
| BleepingComputer | 51 | [link](https://www.bleepingcomputer.com/) | Primary coverage of Cisco SD-WAN, MiniPlasma, BitLocker, NGINX, Exim, Fortinet, SAP, WordPress plugin exploitation |
| CISA | 15 | [link](https://www.cisa.gov/news-events/cybersecurity-advisories) | Universal Robots, Siemens ROS#, Siemens SENTRON, Pwn2Own-linked ICS advisories; KEV catalogue updates |
| RecordedFutures | 13 | [link](https://therecord.media/) | CISA Cisco SD-WAN emergency directive coverage; THORChain $10M theft |
| AlienVault | 12 | [link](https://otx.alienvault.com/) | Kazuar / Secret Blizzard OTX pulse |
| Unknown | 12 | — | TLP:AMBER+STRICT and unattributed CVE PoCs (incl. CVE-2026-42945 RIFT) |
| SANS | 10 | [link](https://isc.sans.edu/) | Patch Tuesday Snort rules and CVE telemetry |
| Upwind | 8 | [link](https://www.upwind.io/feed/malicious-node-ipc-npm-package-credential-theft) | node-ipc credential-stealer analysis; Agentic Pack launches |
| Schneier | 6 | [link](https://www.schneier.com/) | Copy.Fail Linux kernel vulnerability commentary |
| Wired Security | 6 | [link](https://www.wired.com/category/security/) | iPhone theft + account takeover; geopolitical scam patterns |
| Cisco Talos | 5 | [link](https://blog.talosintelligence.com/) | Patch Tuesday analysis; KongTuke (Microsoft Teams abuse) reporting |
| Wiz | 4 | [link](https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised) | Mini Shai-Hulud TanStack/UiPath/Mistral deep dive |
| Sysdig | 3 | [link](https://sysdig.com/blog) | Cloud security telemetry |
| Crowdstrike | 3 | [link](https://www.crowdstrike.com/en-us/blog/patch-tuesday-analysis-may-2026/) | May 2026 Patch Tuesday CVE rollup |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Patch every Cisco Catalyst SD-WAN Controller and Manager against CVE-2026-20182 today; reconcile `vmanage-admin` SSH `Accepted publickey` events in `/var/log/auth.log` against your configured System IPs and treat any unknown peer as compromised. (See §3.1.)
- 🔴 **IMMEDIATE:** Quarantine and rotate every credential used by build pipelines that ran 11–14 May while @tanstack, @uipath, @mistralai, guardrails-ai or node-ipc were installable; block egress to `git-tanstack[.]com`, `azurestaticprovider[.]net` and `37.16.75[.]69`; pin dependency versions and disable `pull_request_target` GitHub Actions workflows that check out untrusted code. (See §3.2.)
- 🔴 **IMMEDIATE:** Force-update Funnel Builder to 3.15.0.3 and Burst Statistics to 3.4.2 across all WordPress estates; review External Scripts settings and recent administrator-account creations; alert on unauthenticated `/wp-json/wp/v2/users` POSTs. (See §3.3.)
- 🟠 **SHORT-TERM:** Enforce TPM+PIN BitLocker (plus BIOS password) on every Windows endpoint and hunt for `\System Volume Information\FsTx` artefacts on removable media and EFI partitions; alert on registry-key creation under `HKEY_USERS\.DEFAULT` by non-SYSTEM processes; track Chaotic Eclipse's GitHub for new releases ahead of June Patch Tuesday. (See §3.4.)
- 🟠 **SHORT-TERM:** Block OAuth 2.0 device-code authorization in Microsoft Entra Conditional Access for any user population that does not require it; alert on device-code sign-ins from unmanaged or non-Entra-joined devices; train users that no legitimate workflow emails a code to paste into `microsoft.com/devicelogin`. (See §3.8.)
- 🟠 **SHORT-TERM:** Apply NGINX, Exim 4.99.3, Fortinet (FortiSandbox / FortiAuthenticator), SAP Commerce Cloud and S/4HANA, and PostgreSQL minor-version updates within standard change windows; ensure ASLR is enabled on every NGINX host; stage Microsoft May 2026 Patch Tuesday across pilot → broad rings within seven days. (See §3.5, §3.6, §3.10.)
- 🟡 **AWARENESS:** Add the four Kazuar SHA-256 hashes to EDR/AV blocklists; hunt for Exchange Web Services egress from endpoints that do not run Outlook/Teams; audit Microsoft 365 EWS app registrations and mailbox forwarding rules. (See §3.7.)
- 🟡 **AWARENESS:** Re-validate phishing-resistant MFA enforcement (FIDO2 / Windows Hello for Business / certificate-based) on every external identity — T1566 dominates correlation evidence (128 pipeline mentions) and underpins the Qilin, DragonForce, Stormous, Chaos, M3rx, Tycoon2FA and TeamPCP intrusion chains observed this week. (See §3.9.)
- 🟢 **STRATEGIC:** Build a "Copy.Fail aware" detection programme that does not rely solely on file-integrity checksums; budget for behavioural EDR on every Linux fleet (page-cache modifications without on-disk change are invisible to AIDE/Tripwire). Inventory and isolate immutable backups from domain credentials; rehearse full ESXi/NAS restoration paths against modern multi-platform RaaS payloads. (See §3.5, §3.9.)

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 403 reports processed across 12 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
