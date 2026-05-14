---
layout: post
title:  "CTI Daily Brief: 2026-05-13 — Cisco SD-WAN ITW exploitation by UAT-8616, node-ipc supply chain compromise, 18-year NGINX RCE"
date:   2026-05-14 20:35:00 +0000
description: "65 reports across 18 sources: active exploitation of Cisco Catalyst SD-WAN (CVE-2026-20182) by UAT-8616, credential-stealing payload in node-ipc npm (3.35M monthly downloads), 18-year-old NGINX heap overflow CVE-2026-42945, Microsoft May Patch Tuesday including .NET EoP CVE-2026-32177, and CISA's 13-advisory Siemens/Universal Robots ICS batch."
category: daily
tags: [cti, daily-brief, qilin, uat-8616, kimsuky, muddywater, shinyhunters, kongtuke, cve-2026-42945, cve-2026-20182, cve-2026-32177, cve-2026-46300, node-ipc, ransomware]
classification: TLP:CLEAR
reporting_period: "2026-05-13"
generated: "2026-05-14"
severity: critical
draft: true
report_count: 65
sources:
  - BleepingComputer
  - CISA
  - Microsoft
  - Cisco Talos
  - Upwind
  - AlienVault
  - Datadog
  - Sysdig
  - HaveIBeenPwned
  - RansomLock
  - SANS
  - Lab52
  - Schneier
  - Wired Security
  - Permiso
  - Sentinel One
  - RecordedFuture
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-05-13 (24h) | TLP:CLEAR | 2026-05-14 |

## 1. Executive Summary

The pipeline processed 65 reports across 18 sources in the past 24 hours, with seven rated critical and 38 rated high. The dominant theme is **confirmed in-the-wild exploitation**: Cisco Talos disclosed active exploitation of CVE-2026-20182 in Catalyst SD-WAN by sophisticated actor UAT-8616, while separate clusters chain CVE-2026-20133/20128/20122 via ZeroZenX Labs' "XenShell" webshell. A coordinated supply chain campaign compromised the `node-ipc` npm package (3.35M monthly downloads), pushing credential-stealing malware that exfiltrates CI/CD, cloud, Kubernetes, SSH and AI tooling secrets via DNS TXT queries — the same campaign reaches into PyPI (`mistralai`), `@tanstack/react-router`, and a backdoored Cemu Linux build. Microsoft's May Patch Tuesday delivered .NET elevation-of-privilege CVEs (CVE-2026-32177 critical, CVE-2026-35433 high) and a Microsoft Exchange spoofing flaw (CVE-2026-42897). CISA published 13 ICS advisories covering Siemens (SENTRON, ROS#, SIMATIC, Teamcenter, Solid Edge) and Universal Robots Polyscope 5 (CVE-2026-8153, CVSS 9.8). On the ransomware side, Qilin dominates leak-site activity (110 reports last 30 days), West Pharmaceutical Services confirmed data theft and system encryption in an SEC filing, and ShinyHunters dumped 711,099 Abrigo records after a failed extortion attempt.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 7 | NGINX CVE-2026-42945, .NET EoP CVE-2026-32177, node-ipc npm compromise, Siemens SENTRON/ROS# ICS, Universal Robots Polyscope 5 |
| 🟠 **HIGH** | 38 | Cisco SD-WAN exploitation, Kimsuky PebbleDash, MuddyWater Korea, Fragnesia Linux LPE, supply chain campaign, Qilin/DragonForce/Inc Ransom/Morpheus leaks |
| 🟡 **MEDIUM** | 7 | Siemens SIPROTEC 5, Ruggedcom Rox, Dell SupportAssist BSOD, iPhone theft ecosystem, Dream Market arrest |
| 🟢 **LOW** | 1 | Outlook Junk folder link preview bypass |
| 🔵 **INFO** | 12 | ODNI election threat response, Permiso AI agent identity, LABScon25 replay |

## 3. Priority Intelligence Items

### 3.1 Active In-The-Wild Exploitation of Cisco Catalyst SD-WAN by UAT-8616

**Source:** [Cisco Talos](https://blog.talosintelligence.com/sd-wan-ongoing-exploitation/)

Cisco Talos has confirmed active, in-the-wild exploitation of **CVE-2026-20182**, an authentication-bypass flaw in Cisco Catalyst SD-WAN Controller (formerly vSmart) and SD-WAN Manager (formerly vManage). Talos attributes this activity to **UAT-8616** with high confidence — the same sophisticated actor that previously weaponised CVE-2026-20127 against SD-WAN systems. Post-compromise, UAT-8616 has been observed adding SSH keys, modifying NETCONF configurations, and escalating to root. Infrastructure overlaps with Operational Relay Box (ORB) networks Talos tracks.

Separately, multiple unrelated clusters are chaining **CVE-2026-20133, CVE-2026-20128 and CVE-2026-20122** (patched February 2026) against unpatched vManage. Most exploitation uses ZeroZenX Labs' public PoC and JSP webshell tracked as **XenShell**. Affected sectors include service providers and large enterprises operating SD-WAN fabrics.

> **SOC Action:** Verify all Catalyst SD-WAN Controller and Manager instances are patched to the version specified in Cisco's advisory for CVE-2026-20182. Hunt for unauthorized SSH key additions in `~/.ssh/authorized_keys` on SD-WAN appliances, anomalous NETCONF write operations, and outbound connections to ORB infrastructure. For CVE-2026-20133/20128/20122, hunt for `*.jsp` webshell artefacts on vManage hosts (XenShell signatures). MITRE ATT&CK: T1190, T1078, T1098.004.

---

### 3.2 Coordinated Supply-Chain Campaign: node-ipc, @tanstack/react-router, mistralai, Cemu

**Source:** [Upwind](https://www.upwind.io/feed/malicious-node-ipc-npm-package-credential-theft), [Datadog Security Labs](https://securitylabs.datadoghq.com/articles/backdoored-cemu-release-teampcp-supply-chain-campaign/)

On 14 May 2026 at approximately 14:25 UTC, three malicious versions of `node-ipc` (9.2.3, 12.0.1, and a third version, all byte-identical payloads) were published from a legitimate maintainer account (`atiertant`). The package — approximately 3.35M monthly downloads — had been dormant for ~20 months. The malicious payload was appended to `node-ipc.cjs` and ran silently whenever the package was loaded via `require('node-ipc')`, while ESM imports remained clean. The malware harvested developer, CI/CD, cloud (AWS/Azure/GCP), Kubernetes, SSH, and AI tooling credentials and exfiltrated them through DNS TXT queries to attacker infrastructure.

Datadog Security Labs links this incident to a broader campaign dubbed "TeamPCP" that poisoned approximately 170 packages across npm and PyPI in a five-hour window on 11 May, including `@tanstack/react-router` (3M+ weekly downloads) and `mistralai==2.4.6` (PyPI). A backdoored `Cemu-2.6-x86_64.AppImage` on the official GitHub release page bundled `startup.pyz` — byte-identical to the `transformers.pyz` payload from the TanStack campaign — confirming common operators.

#### Indicators of Compromise

```
Domain (node-ipc C2): azurestaticprovider[.]net
IP (live C2): 37.16.75[.]69
Malicious packages: node-ipc@9.2.3, node-ipc@12.0.1
SHA256 (startup.pyz / transformers.pyz): 0f35abda19fb69430c32228465396094b866d887427bf551e353ab31256a9dd6
GitHub release uploader: MangelSpec (Cemu v2.6)
PyPI: mistralai==2.4.6 (no upstream tag)
npm: @tanstack/react-router (compromised tokens; upstream commit 79ac49eed)
```

> **SOC Action:** Audit all `node-ipc`, `@tanstack/react-router`, and `mistralai` installs published on or after 11 May 2026; pin to known-good versions in `package-lock.json`/`uv.lock`/`requirements.txt` and rebuild. Query DNS logs for TXT queries to `azurestaticprovider[.]net` and any subdomain. Block `37.16.75[.]69` and the C2 domain at egress. Rotate any CI/CD secrets, cloud IAM keys, kube-config tokens, and SSH keys present on developer or build hosts that ran the malicious versions. MITRE ATT&CK: T1195.002, T1059, T1071.004 (DNS), T1552.001.

---

### 3.3 18-Year-Old NGINX Heap Overflow Allows RCE (CVE-2026-42945)

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/18-year-old-nginx-vulnerability-allows-dos-potential-rce/)

DepthFirst AI's autonomous scanning system discovered CVE-2026-42945, a CVSS 9.2 heap buffer overflow in `ngx_http_rewrite_module` affecting NGINX 0.6.27 through 1.30.0 — present in the codebase for roughly 18 years. The flaw stems from inconsistent state handling in NGINX's internal script engine: when `rewrite` and `set` directives are combined (a pattern common in API gateways and reverse proxies), an `is_args` flag remains set after a rewrite containing `?`, causing buffer-size miscalculation when escaped characters are later written.

DepthFirst demonstrated unauthenticated RCE via crafted HTTP requests that corrupt the NGINX memory pool, overwrite cleanup handler pointers and force execution of `system()`. RCE was achieved on a system with ASLR disabled (a common embedded/VM tuning). The multi-process architecture of NGINX makes exploitation reliable: workers crashed during exploitation are respawned with identical memory layouts. Three additional medium/high-severity flaws (CVE-2026-42946 SCGI/UWSGI memory allocation, CVE-2026-40701 OCSP UAF, CVE-2026-42934 UTF-8 OOB read) were disclosed in the same advisory. A TLP:AMBER+STRICT report tracked internally as "RIFT" describes PoC code for CVE-2026-42945.

> **SOC Action:** Inventory all NGINX deployments (including those embedded in Kubernetes ingress controllers, F5 NGINX Plus, and SaaS appliances) and upgrade beyond 1.30.0 as soon as F5 issues the patch. Until patched, audit configurations for combined `rewrite`/`set` directives and verify ASLR is enabled on all NGINX hosts (`cat /proc/sys/kernel/randomize_va_space` should be 2). Restrict reachability of internet-facing NGINX behind WAF rules that flag malformed rewrite-triggering URIs. MITRE ATT&CK: T1190, T1059.

---

### 3.4 Microsoft May Patch Tuesday — .NET EoP and Exchange Spoofing

**Source:** [Microsoft (CVE-2026-32177)](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-32177), [Microsoft (CVE-2026-35433)](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-35433), [Microsoft (CVE-2026-42897)](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-42897), [Microsoft (CVE-2026-41615)](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-41615)

Microsoft published five vulnerability advisories on 14 May. **CVE-2026-32177 (critical)** and **CVE-2026-35433 (high)** are elevation-of-privilege flaws in newly added .NET Framework packages exploitable by a local authenticated attacker. The AI-identified correlation engine flagged these as part of a broader trend — "Elevation of privilege vulnerabilities in .NET and other software frameworks are being actively exploited" — though Microsoft has not yet confirmed in-the-wild abuse. **CVE-2026-42897** is a cross-site scripting flaw in Microsoft Exchange Server enabling network-based spoofing. **CVE-2026-41615** is a network-reachable information-disclosure flaw in Microsoft Authenticator.

> **SOC Action:** Prioritise .NET Framework patches on developer endpoints, build agents, and any host running .NET applications under privileged service accounts. For Exchange, validate the May 2026 cumulative update is applied and review external-facing OWA for unusual JavaScript redirects. For Microsoft Authenticator, validate the latest mobile build is rolled out via MDM. MITRE ATT&CK: T1068, T1548, T1059.

---

### 3.5 Kimsuky (APT43) Expands PebbleDash Arsenal — New Rust Variants and VSCode Tunneling

**Source:** [Securelist / AlienVault](https://securelist.com/kimsuky-appleseed-pebbledash-campaigns/119785/)

Kaspersky's Securelist team disclosed multiple new Kimsuky (aka APT43, Ruby Sleet, Black Banshee, Sparkling Pisces, Velvet Chollima, Springtail) malware variants and post-exploitation tradecraft observed across South Korean public and private sector targets. The campaign features a first Rust-based PebbleDash variant called **HelloDoor**, a latest backdoor variant **httpMalice**, and a loader cluster `MemLoad`→`httpTroy`. Kimsuky continues to deliver droppers in JSE/PIF/SCR/EXE format via spear-phishing and uses **legitimate VSCode tunneling** plus **DWAgent** RMM for persistence and post-exploitation. C2 infrastructure relies primarily on free South Korean hosting (`*.o-r.kr`, `*.p-e.kr`, `*.n-e.kr`, `*.r-e.kr` domains), `trycloudflare.com` quick tunnels, and compromised legitimate Korean sites.

#### Indicators of Compromise

```
SHA256: 2d597c3a726970927b302bf015cec4e37cdc974959cb846dbcb23cdb46386a6c
SHA256: 4ac02dc231f2546ce64335729145db672b5ab01d8943df8a550cc77fc436df14
SHA256: 8779580d97d5a1d9c612cee745a7097483fc1643e38d7c1574670f56bc7abb48
SHA256: d0912a47413338a1a79eef767aa33135f1e3ac66dfb6f6d1c8dbec72c892b985
Domain: newjo-imd[.]com
Hostnames: attach.docucloud.o-r[.]kr, cms.spaceyou.o-r[.]kr, erp.spaceme.p-e[.]kr
Hostnames: file.bigcloud.n-e[.]kr, load.auraria[.]org, load.erasecloud.n-e[.]kr
Hostnames: load.ssangyongcne.o-r[.]kr, load.supershop.o-r[.]kr, load.yju.o-r[.]kr
Hostnames: morames.r-e[.]kr, opedromos1.r-e[.]kr
Hostnames: female-disorder-beta-metropolitan.trycloudflare[.]com
DWAgent C2: node484265.dwservice[.]net, node828765.dwservice[.]net, node896147.dwservice[.]net
URL: hxxp[:]//newjo-imd[.]com/common/include/library/default.php
URL: hxxps[:]//file.bigcloud.n-e[.]kr/index.php
URL: hxxps[:]//www.pyrotech.co[.]kr/common/include/tech/default.php
URL: hxxps[:]//www.yespp.co[.]kr/common/include/code/out.php
```

> **SOC Action:** Add the listed SHA256s to EDR blocklists and the hostnames to DNS sinkhole. Hunt for legitimate-but-misused VSCode `code tunnel` processes initiated by non-developer users, and `dwagent.exe`/`dwservice.exe` outside sanctioned RMM inventory. Alert on `trycloudflare.com` egress from corporate networks. South-Korea-aligned organisations should treat any of the `*.o-r.kr` / `*.p-e.kr` / `*.n-e.kr` / `*.r-e.kr` resolutions as high-priority indicators. MITRE ATT&CK: T1566.001, T1059.003, T1543.003, T1219, T1071.001, T1573.001.

---

### 3.6 MuddyWater (Seedworm) Targets South Korean Electronics Manufacturer

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/iranian-hackers-targeted-major-south-korean-electronics-maker/)

Symantec's Threat Hunter Team disclosed that Iran-linked **MuddyWater** (Seedworm, Static Kitten) spent a week inside the network of a major unnamed South Korean electronics manufacturer in late February 2026, as part of a broader campaign targeting at least nine high-profile organisations across critical-infrastructure sectors and an international airport in the Middle East. The campaign is intelligence-driven, focused on industrial and IP theft.

Tradecraft relies on **DLL sideloading** of legitimate signed binaries — `fmapp.exe` (Foremedia audio) loading `fmapp.dll`, and `sentinelmemoryscanner.exe` (a SentinelOne component) loading `sentinelagentcore.dll`. The malicious DLLs deliver **ChromElevator** to dump Chrome browser data. PowerShell is invoked via Node.js loaders for reconnaissance, screenshot capture, credential theft (SAM/SECURITY/SYSTEM hive theft, Kerberos abuse), and SOCKS5 tunnelling. Data exfiltration abuses the public file-sharing service `sendit.sh`. Attribution preserves Symantec's hedging — attribution is "Iran-linked" with no claim of state direction.

> **SOC Action:** Alert on `sentinelmemoryscanner.exe` and `fmapp.exe` executions where they were not previously baselined, particularly when followed by Node.js child processes. Hunt for outbound traffic to `sendit.sh` from corporate endpoints. Block or monitor unsigned/unsanctioned DLLs loaded by SentinelOne-signed binaries; check EDR vendors for an updated sentinel-self-protection bypass detection. MITRE ATT&CK: T1218.002 (DLL Side-Loading), T1003, T1071.001, T1090.

---

### 3.7 Fragnesia (CVE-2026-46300) — Universal Linux Local Privilege Escalation

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/new-fragnesia-linux-flaw-lets-attackers-gain-root-privileges/)

Zellic's William Bowling disclosed **CVE-2026-46300 ("Fragnasia")**, a high-severity logic bug in the Linux kernel XFRM ESP-in-TCP subsystem that allows an unprivileged local attacker to write arbitrary bytes into the kernel page cache of read-only files — including `/usr/bin/su` — yielding root. The flaw belongs to the "Dirty Frag" class (CVE-2026-43284, CVE-2026-43500) disclosed the prior week, but is a separate bug in the same surface and requires no race condition. A public PoC is available. All Linux kernels released before 13 May 2026 are affected.

Mitigation (until kernel updates ship): unload and blocklist the `esp4`, `esp6`, and `rxrpc` modules — but note this breaks AFS network filesystems and IPsec VPNs.

> **SOC Action:** Apply distribution kernel updates as they land. On hosts where patching is delayed, deploy the temporary mitigation only after confirming no production IPsec/AFS dependency: `rmmod esp4 esp6 rxrpc && printf 'install esp4 /bin/false\ninstall esp6 /bin/false\ninstall rxrpc /bin/false\n' > /etc/modprobe.d/dirtyfrag.conf`. Hunt EDR for unusual `setuid`/`su` invocations following local user logins; correlate with `/usr/bin/su` integrity changes. MITRE ATT&CK: T1068, T1547.006.

---

### 3.8 CISA ICS Advisory Batch — Universal Robots Polyscope 5 and Siemens Critical Manufacturing

**Source:** [CISA — Universal Robots Polyscope 5](https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-17), [CISA — Siemens ROS#](https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-08), [CISA — Siemens SENTRON 7KT PAC1261](https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-14)

CISA published 13 ICS advisories on 14 May 2026. Three are rated critical:

- **Universal Robots Polyscope 5 (CVE-2026-8153, CVSS 9.8)** — unauthenticated OS command injection in the Dashboard Server interface allows arbitrary code execution on the robot OS. Affects Polyscope 5 < 5.25.1. Critical Manufacturing sector, worldwide deployment.
- **Siemens ROS# (CVE-2026-41551, CVSS 9.1)** — path traversal in `file_server` before 2.2.2 enables unauthenticated arbitrary file read/write at service-user rights. Used in ROS-Sharp Unity / ROS bridge deployments.
- **Siemens SENTRON 7KT PAC1261 Data Manager (CVE-2025-22871, CVSS 9.1)** — HTTP request smuggling in the Go `net/http` package allows authorization-token theft and administrative takeover. Energy sector. Update to V2.1.0.

Additional Siemens high-severity advisories cover Opcenter RDnL (CVE-2026-27446 / Apache Artemis), gWAP (Axios prototype pollution), Industrial Devices (CVE-2025-40833 DoS), SIMATIC S7 PLC Web Server (XSS), Solid Edge (PAR parser), Teamcenter (hard-coded credentials, CVE-2026-33893), and Simcenter Femap (heap overflow via IPT files).

> **SOC Action:** OT/ICS teams should validate that Polyscope 5, ROS# `file_server`, and SENTRON 7KT PAC1261 instances are isolated from corporate networks and the internet, then schedule maintenance windows for the Siemens and Universal Robots patches in line with CISA's defence-in-depth guidance. Confirm any robotic Dashboard Server is unreachable from production OT VLANs except via jump host. MITRE ATT&CK: T1190, T1078.001, T1083.

---

### 3.9 NATS-as-C2 — Langflow CVE-2026-33017 Exploited for Cloud and AI Credential Harvesting

**Source:** [Sysdig](https://webflow.sysdig.com/blog/nats-as-c2-inside-a-new-technique-attackers-are-using-to-harvest-cloud-credentials-and-ai-api-keys)

Sysdig Threat Research Team documented what they describe as the first published case of a threat actor using a **NATS messaging server as C2 infrastructure** ("NATS-as-C2"). The activity was uncovered during incident response on exploitation of **CVE-2026-33017** in Langflow (an LLM workflow builder). The operator used NATS pub/sub orchestration and durable task queues to coordinate a distributed worker pool that hunts AWS API keys and AI/LLM provider keys. The use of cloud-native message-bus infrastructure makes C2 traffic blend with legitimate microservice communications.

> **SOC Action:** Patch Langflow to a version that resolves CVE-2026-33017. Audit egress logs for outbound TCP/4222 (default NATS port) and TLS connections to unfamiliar NATS-hosting providers (Synadia, hosted NATS) from production workloads. Rotate AWS and AI provider keys (OpenAI, Anthropic, Mistral, Bedrock) on any host that ran an unpatched Langflow. MITRE ATT&CK: T1190, T1071, T1567.

---

### 3.10 Ransomware Ecosystem — West Pharmaceutical, ShinyHunters/Abrigo, and Qilin Tempo

**Source:** [BleepingComputer — West Pharmaceutical](https://www.bleepingcomputer.com/news/security/west-pharmaceutical-says-hackers-stole-data-encrypted-systems/), [HaveIBeenPwned — Abrigo](https://haveibeenpwned.com/Breach/Abrigo), [RansomLook — Qilin](https://www.ransomlook.io//group/qilin)

**West Pharmaceutical Services** (S&P 500 pharmaceutical components, >$3B revenue, 10,800 employees) filed an 8-K disclosing a cyberattack detected on 4 May 2026 resulting in data exfiltration and system encryption. The company has engaged Unit 42 and partially restarted manufacturing. No ransomware group has claimed responsibility at time of writing.

**ShinyHunters** dumped 711,099 records from fintech provider **Abrigo** after a "pay-or-leak" extortion attempt in April. Compromised fields include names, employers, job titles, emails, phone and physical addresses — consistent with data sourced from Abrigo's Salesforce instance (separate from last year's Drift connector compromise).

Qilin RaaS dominated leak-site postings in the 24-hour window with new victims **Schulte-Lindhorst GmbH**, **Fab-Masters**, **Domaine Des Tournels**, **Spirit Medical Transport**, **Mayer**, and **Bluize**. DragonForce posted **MicroMarketing**, **Pamil Modulsystem**, and **Tricon Infotech**. Inc Ransom posted **Silergy Corp**. Morpheus posted **BAYTECH A/S**. Abyss-Data posted **technic.com**.

> **SOC Action:** For healthcare/manufacturing/pharma entities: validate offline backups are <24h old and unreadable from production AD; verify EDR coverage on engineering workstations and OT jump hosts. For Salesforce-using organisations: audit connected apps for the Drift integration and any other inactive third-party connector with `api`, `refresh_token` scope; rotate session tokens. Add Qilin and DragonForce TTP detections (LSASS access via `comsvcs.dll MiniDump`, ransom-note write of `README-RECOVER-*.txt`). MITRE ATT&CK: T1486, T1567, T1078.004 (Cloud Accounts).

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Elevation-of-privilege vulnerabilities in .NET and other software frameworks are being actively exploited | CVE-2026-32177 .NET EoP, CVE-2026-35433 .NET EoP |
| 🟠 **HIGH** | Increased use of phishing and ransomware tactics by multiple actors across various sectors | CVE-2026-42897 Exchange Spoofing; Schulte-Lindhorst by Qilin; Cyber-Enabled Cargo Crime; KongTuke via Microsoft Teams; iPhone theft hacking ecosystem; AI Deepfake Python backdoor; "Thus Spoke…The Gentlemen" |
| 🟠 **HIGH** | Supply chain attacks targeting software development and technology sectors | node-ipc credential-stealing malware; Backdoored Cemu / TanStack / Mistral campaign |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **Qilin** (110 reports) — Dominant RaaS by volume; six new leak postings in the 24-hour window across architecture, hospitality, medical transport and manufacturing
- **The Gentlemen** (60 reports) — Continued postings on dedicated leak site; phishing-led intrusions
- **Akira** (59 reports) — Ongoing affiliate-driven leak activity; Akira-ransomware family resurfaced this week
- **ShinyHunters** (33 reports incl. variant casing) — Abrigo 711K-record leak today; Salesforce-pivot extortion model continues
- **Coinbase Cartel** (28 reports) — Crypto-focused extortion crew, sustained activity
- **Inc Ransom** (24 reports) — New Silergy Corp victim posted
- **Everest** (24 reports) — Database-leak focus
- **TeamPCP** (22 reports) — Likely operator behind the TanStack/node-ipc/Cemu/Mistral supply-chain campaign per Datadog
- **FulcrumSec** (17 reports) — Newer leak-site presence
- **UAT-8616** (Cisco Talos) — Sophisticated SD-WAN exploitation cluster, ORB infrastructure overlap

### Malware Families

- **RansomLook**-tracked families (111) and **RaaS** generic (19) — leak-site aggregator labels; not malware per se
- **Tox1 / Tox** (34 / 17) — Ransomware tooling family
- **Akira ransomware / Akira** (32 / 16 / 12 variant casings) — Continued affiliate activity
- **Qilin** (13) — Family signatures track to leak-site operations
- **ModeloRAT** — Python-based RAT delivered via KongTuke's Microsoft Teams social engineering
- **PebbleDash / HelloDoor / httpMalice / httpTroy / AppleSeed / HappyDoor** — Kimsuky toolset expansion
- **XenShell** — JSP webshell deployed against Cisco SD-WAN via ZeroZenX PoC
- **ChromElevator** — Commodity Chrome data-theft tool used by MuddyWater

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| RansomLock | 15 | [link](https://www.ransomlook.io/) | Aggregated leak-site postings (Qilin, DragonForce, Inc Ransom, Morpheus, Abyss-Data, Killsec3, CMD Organization, Everest) |
| CISA | 13 | [link](https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-17) | 13 Siemens + Universal Robots ICS advisories (incl. three critical) |
| BleepingComputer | 9 | [link](https://www.bleepingcomputer.com/news/security/18-year-old-nginx-vulnerability-allows-dos-potential-rce/) | NGINX CVE-2026-42945, MuddyWater Korea, KongTuke, Fragnesia, West Pharma |
| Microsoft | 5 | [link](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-32177) | May Patch Tuesday: .NET EoP, Exchange spoofing, Authenticator info disclosure |
| Cisco Talos | 2 | [link](https://blog.talosintelligence.com/sd-wan-ongoing-exploitation/) | UAT-8616 ITW exploitation of CVE-2026-20182 |
| SANS | 2 | [link](https://isc.sans.edu/diary/rss/32990) | Outlook Junk-folder preview bypass |
| AlienVault | 2 | [link](https://securelist.com/kimsuky-appleseed-pebbledash-campaigns/119785/) | Kimsuky PebbleDash deep-dive; device-code phishing |
| Upwind | 2 | [link](https://www.upwind.io/feed/malicious-node-ipc-npm-package-credential-theft) | node-ipc supply chain compromise; Agentic Pack |
| Schneier | 2 | [link](https://www.schneier.com/) | Commentary |
| Permiso | 2 | [link](https://permiso.io/blog/ai-agent-runtime-security) | AI agent identity runtime |
| Sysdig | 1 | [link](https://webflow.sysdig.com/blog/nats-as-c2-inside-a-new-technique-attackers-are-using-to-harvest-cloud-credentials-and-ai-api-keys) | NATS-as-C2 technique disclosure |
| Datadog | 1 | [link](https://securitylabs.datadoghq.com/articles/backdoored-cemu-release-teampcp-supply-chain-campaign/) | TanStack/Cemu/Mistral supply chain link analysis |
| HaveIBeenPwned | 1 | [link](https://haveibeenpwned.com/Breach/Abrigo) | Abrigo 711K-account ShinyHunters leak |
| Lab52 | 1 | [link](https://lab52.io/blog/trends-in-radio-frequency-spectrum-activity-and-its-impact-on-the-geopolitical-landscape/) | RF spectrum and nation-state activity |
| Sentinel One | 1 | [link](https://www.sentinelone.com/labs/labscon25-replay-breach-alpha-trading-on-cyber-fallout/) | LABScon25 replay — breach-trading research |
| Crowdstrike | 1 | — | Threat intelligence content |
| RecordedFuture | 1 | [link](https://therecord.media/odni-taps-officials-to-coordinate-response-to-election-threats) | ODNI election-threat coordination |
| Wired Security | 1 | [link](https://www.wired.com/story/your-iphone-gets-stolen-then-the-hacking-begins/) | Stolen iPhone phishing ecosystem |
| Unknown / Telegram | 2 | — | Telegram (channel name redacted); CVE-2026-42945 PoC and unrelated data leak |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Patch and hunt for Cisco Catalyst SD-WAN exploitation (CVE-2026-20182 by UAT-8616; CVE-2026-20133/20128/20122 by separate clusters). Confirm vManage/vSmart instances are on the fixed builds and search for unauthorised SSH keys, NETCONF writes, and `*.jsp` XenShell artefacts.
- 🔴 **IMMEDIATE:** Audit `node-ipc`, `@tanstack/react-router`, and `mistralai` installs from 11 May onward; rotate any CI/CD, cloud, Kubernetes, SSH, and AI provider credentials present on affected hosts; block `azurestaticprovider[.]net` and `37.16.75[.]69`.
- 🟠 **SHORT-TERM:** Inventory and schedule NGINX upgrades beyond 1.30.0 (CVE-2026-42945, CVSS 9.2) — covers F5 NGINX, Kubernetes ingress, embedded reverse proxies. Verify ASLR is enabled on all NGINX hosts as a compensating control.
- 🟠 **SHORT-TERM:** Roll the May 2026 Microsoft updates — .NET Framework (CVE-2026-32177/35433), Exchange Server (CVE-2026-42897), Microsoft Authenticator (CVE-2026-41615). Prioritise build agents and any host with .NET running under privileged service accounts.
- 🟠 **SHORT-TERM:** OT/ICS teams should action the 14 May Siemens + Universal Robots advisories — particularly Polyscope 5 (CVE-2026-8153, CVSS 9.8), Siemens ROS#, and SENTRON 7KT PAC1261. Ensure all three are isolated from corporate networks pending patching.
- 🟡 **AWARENESS:** Brief SOC analysts on Kimsuky's VSCode-tunnel and DWAgent abuse and on KongTuke's Microsoft Teams social engineering with ModeloRAT. Implement Microsoft Teams external-federation allowlisting and alert on `code tunnel` / `dwservice.exe` outside sanctioned baselines.
- 🟢 **STRATEGIC:** Treat supply-chain compromise of widely-used packages (npm, PyPI, GitHub releases) as a recurring class of incident: enforce lockfile pinning, internal package proxies with quarantine windows, and CI/CD secret scoping that minimises blast radius when a build host is compromised.

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 65 reports processed across 4 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
