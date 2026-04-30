---
layout: post
title:  "CTI Daily Brief: 2026-04-29 - Linux privilege escalation, TeamPCP SAP npm supply-chain attack, dormant WordPress backdoor"
date:   2026-04-30 20:15:00 +0000
description: "23 reports processed across 2 correlation batches. Critical Linux root-escalation CVE, TeamPCP supply-chain compromise of official SAP npm packages, a dormant WordPress backdoor in 70K sites, and active Qinglong RCE exploitation for cryptomining dominate the day."
category: daily
tags: [cti, daily-brief, teampcp, qilin, payoutsking, everest, cve-2026-31431, cve-2026-3965, cve-2026-4047]
classification: TLP:CLEAR
reporting_period: "2026-04-29"
generated: "2026-04-30"
draft: true
severity: critical
report_count: 23
sources:
  - RansomLook
  - BleepingComputer
  - SANS
  - RecordedFutures
  - Wiz
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-04-29 (24h) | TLP:CLEAR | 2026-04-30 |

## 1. Executive Summary

The pipeline processed 23 reports across two correlation batches in the last 24 hours, with one critical and 15 high-severity items. The day was defined by a fresh wave of software supply-chain abuse: TeamPCP compromised four official SAP npm packages (`@cap-js/sqlite`, `@cap-js/postgres`, `@cap-js/db-service`, `mbt`) with a credential-stealing `preinstall` script that scrapes CI/CD runner memory and exfiltrates secrets via attacker-controlled GitHub repos described as "A Mini Shai-Hulud has Appeared." Separately, the Quick Page/Post Redirect WordPress plugin (~70,000 installs) was found to harbour a dormant self-update backdoor that pulls code from `anadnet[.]com`. A critical local privilege-escalation flaw, CVE-2026-31431, was disclosed against major Linux distributions, and active in-the-wild exploitation of CVE-2026-3965 / CVE-2026-4047 in the Qinglong task scheduler is dropping cryptominers on developer hosts. Ransomware activity remained heavy, with Qilin, Everest, Inc Ransom, Payoutsking and FulcrumSec all posting fresh victims. No CISA KEV additions were observed in the data for this period.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 1 | CVE-2026-31431 Linux local privilege escalation |
| 🟠 **HIGH** | 15 | TeamPCP SAP npm compromise; WordPress plugin backdoor; Qinglong RCE; Qilin / Everest / Inc Ransom / Payoutsking ransomware victim postings |
| 🟡 **MEDIUM** | 3 | Inc Ransom secondary victim posting; Libredtail cryptomining variant analysis; Telegram-based breach forum activity |
| 🔵 **INFO** | 4 | ISC Stormcast 30 Apr; Section 702 surveillance reauthorisation; Wiz 2026 State of AI in the Cloud recap; US/China Dubai scam-centre takedown |

## 3. Priority Intelligence Items

### 3.1 CVE-2026-31431 — Local Root Privilege Escalation Across Major Linux Distributions

**Source:** Unknown (low-confidence brokered disclosure, TLP:AMBER+STRICT)

A vulnerability tracked as CVE-2026-31431 affects major Linux distributions and reportedly allows an unprivileged user to escalate to root via a 732-byte copy operation against the root directory. Public technical detail is currently sparse — only the title and a brief description were indexed, with no PoC, vendor advisory, or distro patch references in the source data. Mapped MITRE techniques include T1064 (Privilege Escalation), T1078 (Valid Accounts), and T1085 (Shift User Execution). Confidence in the underlying reporting is high (100), but attribution and exact technical mechanism are unverified, so treat the disclosure as unverified until distribution security teams (Red Hat, Debian, SUSE, Ubuntu, Canonical) confirm.

> **SOC Action:** Open a high-priority tracking ticket against `CVE-2026-31431` and poll vendor security feeds (RHSA, USN, DSA, openSUSE-SU) hourly until an advisory drops. Pre-position kernel/util-linux patch deployment via your config-management tool. In the interim, audit `auditd`/`execve` logs for SUID binary anomalies and hunt for unexpected user-to-root transitions on multi-tenant Linux hosts.

### 3.2 TeamPCP Supply-Chain Compromise of Official SAP npm Packages

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/official-sap-npm-packages-compromised-to-steal-credentials/)

Four official SAP-published npm packages — `@cap-js/sqlite@2.2.2`, `@cap-js/postgres@2.2.2`, `@cap-js/db-service@2.10.1`, and `mbt@1.2.48` — were trojanised with a malicious `preinstall` script that fetches the Bun runtime from GitHub and executes an obfuscated `execution.js` infostealer (`setup.mjs` → `execution.js`). The payload harvests npm/GitHub tokens, SSH keys, AWS/Azure/GCP credentials, Kubernetes config, and CI/CD pipeline secrets, then encrypts and uploads them to public GitHub repositories under the victim's account, tagged with the description **"A Mini Shai-Hulud has Appeared."** On CI runners, an embedded Python script reads `/proc/<pid>/maps` and `/proc/<pid>/mem` of the `Runner.Worker` process to scrape `isSecret:true` values directly from memory, bypassing GitHub Actions log masking. The malware also uses GitHub commit-message dead-drops (`OhNoWhatsGoingOnWithGitHub:<base64>`) to retrieve attacker tokens and self-propagates by republishing other packages the stolen credentials can access. Researchers attribute with medium confidence to **TeamPCP**, the same actor behind the Trivy, Checkmarx and Bitwarden supply-chain incidents. Initial compromise vector is unconfirmed but suspected to be an exposed npm token in a misconfigured CircleCI job. Affected packages have been deprecated on the registry. Mapped TTPs: T1195.002 (Compromise Software Supply Chain), T1003 (OS Credential Dumping), T1071 (Application Layer Protocol), T1204 (User Execution), T1027 (Obfuscated Files or Information).

#### Indicators of Compromise

```
Affected packages (deprecated):
  @cap-js/sqlite@2.2.2
  @cap-js/postgres@2.2.2
  @cap-js/db-service@2.10.1
  mbt@1.2.48

Malicious files:
  setup.mjs
  execution.js  (obfuscated; uses Bun runtime)

Dead-drop signature:
  GitHub repo description: "A Mini Shai-Hulud has Appeared"
  Commit-message pattern: OhNoWhatsGoingOnWithGitHub:<base64>

Memory-scrape pattern (CI runner):
  Reads /proc/<pid>/maps and /proc/<pid>/mem of Runner.Worker
  Regex target: "key":{"value":"...","isSecret":true}
```

> **SOC Action:** Block install of the four affected versions in Artifactory/Nexus/JFrog and any internal npm proxy. Run `npm ls @cap-js/sqlite @cap-js/postgres @cap-js/db-service mbt` recursively across developer laptops and build agents; quarantine any host that resolved the bad versions. Search GitHub org audit logs for repos created in the last 72h with the description "A Mini Shai-Hulud has Appeared" and for commits matching `OhNoWhatsGoingOnWithGitHub:`. Rotate all npm publish tokens, GitHub PATs, cloud keys, SSH keys, and Kubernetes service-account tokens that touched any affected build runner. Restrict CI runners from outbound traffic to `github.com/raw.githubusercontent.com` paths not on an allowlist, and enable GitHub secret-scanning push protection org-wide.

### 3.3 Quick Page/Post Redirect — Dormant WordPress Backdoor in ~70,000 Sites

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/popular-wordpress-redirect-plugin-hid-dormant-backdoor-for-years/)

Researcher Austin Ginder (Anchor) discovered that versions 5.2.1 and 5.2.2 of the **Quick Page/Post Redirect** WordPress plugin shipped a hidden self-update mechanism that pointed not to WordPress.org but to attacker-controlled `anadnet[.]com`. Sites running those versions silently received a tampered 5.2.3 build from `w.anadnet[.]com` in March 2021, which planted a passive backdoor that activates only for logged-out visitors and was used at the time to rent out parasite-SEO ranking on the affected fleet. The self-update primitive remains in roughly 70,000 active installs and is functionally an arbitrary remote code-execution channel — currently dormant only because the C2 subdomain does not resolve, though the parent domain is still active. WordPress.org has temporarily pulled the plugin pending review. Mapped TTPs: T1190 (Exploit Public-Facing Application), T1071.001 (Web Protocols), T1204 (User Execution), T1554 (Compromise Host Software Binary).

#### Indicators of Compromise

```
Plugin: Quick Page/Post Redirect (versions 5.2.1, 5.2.2, tampered 5.2.3)
C2 domain:    anadnet[.]top-level domain still active
C2 subdomain: w.anadnet[.]com (currently NXDOMAIN)
Trigger:     'the_content' filter hook, logged-out visitors only
Goal:         arbitrary code injection / parasite-SEO content
```

> **SOC Action:** Inventory WordPress estates and any tenant-managed sites for the **Quick Page/Post Redirect** plugin; uninstall and replace with a clean 5.2.4 build once republished by WordPress.org. Add `anadnet[.]com` and `w.anadnet[.]com` to web-proxy and DNS RPZ blocklists, and alert on any historical resolution. Hunt WordPress logs for outbound HTTP from the plugin directory and for unusual content served only to unauthenticated sessions. Treat any site that ran 5.2.x as backdoor-compromised: rotate admin credentials, reissue API/REST keys, and review uploaded media for injected payloads.

### 3.4 Active Exploitation of Qinglong RCE Chain (CVE-2026-3965, CVE-2026-4047) for Cryptomining

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/hackers-exploit-rce-flaws-in-qinglong-task-scheduler-for-cryptomining/)

Snyk reports active in-the-wild exploitation of two authentication-bypass flaws in the open-source Qinglong task scheduler (>19K GitHub stars, popular among Chinese developers) since **7 February 2026** — predating public disclosure. CVE-2026-3965 stems from a misconfigured rewrite rule mapping `/open/*` to `/api/*`, exposing protected admin endpoints unauthenticated. CVE-2026-4047 abuses a case-sensitivity mismatch between the auth middleware (case-sensitive) and Express.js routing (case-insensitive), letting requests like `/aPi/...` slip past authorisation. Chained, they yield unauthenticated RCE. Attackers modify Qinglong's `config.sh` to drop a cryptominer named `.fullgc` (mimicking JVM "Full GC" garbage-collection) into `/ql/data/db/.fullgc`, sourcing Linux x86_64, ARM64, and macOS variants from `file.551911[.]xyz`. The miner consumes 85–100% CPU. Affected versions are 2.20.1 and earlier; the maintainer's first patch (PR #2924) was insufficient — the effective fix landed in PR #2941. Mapped TTPs: T1190 (Exploit Public-Facing Application), T1496 (Resource Hijacking), T1068 (Exploitation for Privilege Escalation), T1204 (User Execution), T1036 (Masquerading).

#### Indicators of Compromise

```
CVEs:        CVE-2026-3965, CVE-2026-4047
Affected:    Qinglong <= 2.20.1
Miner path:  /ql/data/db/.fullgc
Process:     .fullgc  (mimics "Full GC")
CPU usage:   85–100%
Payload host: file.551911[.]xyz  (Linux x86_64, ARM64, macOS variants)
Modified:    /ql/config/config.sh  (injected shell commands)
Probe path:  /aPi/...  /Api/...  (case-bypass)
             /open/*    (rewrite-rule bypass)
```

> **SOC Action:** Identify all internet-exposed Qinglong panels (Shodan/Censys queries on default Qinglong banners, port 5700) and patch to the build containing PR #2941 immediately — restrict to VPN/internal networks if patching is delayed. Block egress to `file.551911[.]xyz` and add the domain to DNS blocklists. Hunt for `.fullgc` processes, modifications to `/ql/config/config.sh`, and outbound connections to known XMRig-style mining pools from any Qinglong host. On WAFs, alert on requests with mixed-case `/Api/` or `/aPi/` paths and any access to `/open/*` from non-trusted source IPs.

### 3.5 Sustained Ransomware Posting Activity — Qilin, Everest, Inc Ransom, Payoutsking, FulcrumSec

**Source:** [RansomLook](https://www.ransomlook.io/)

The ransomware leak-site monitor surfaced 12 fresh victim postings across at least five operations in 24 hours. **Qilin** (RaaS, Jabber/Tox C2) posted "Jgb." **Inc Ransom** posted **Arban & Carosi** and a follow-up **Iowa Spring Manufacturing & Sales** entry. **Everest** (active since December 2020, double-extortion via Tor leak site) posted **Umiles Group** with a database leak claim and **Morae**. **Payoutsking** — explicitly non-RaaS, Tox-only communication, custom `readme_locker.txt` ransom note — posted four U.S. and global victims: **Epcon Communities**, **Data Exchange Corporation**, **SCS Engineers**, and **SunSource**. **Krybit/0APT** posted **zsiclife.co.zm**, **Radar** posted **Bentley Capital Ventures**, and **Payload** posted **PROM (Peakside Ros Outlet Management)**. Pipeline correlation flagged the broader 24h window as showing high actor-confidence clustering for **Qilin**, **The Gentlemen**, **FulcrumSec**, **Aurora**, and **Lockbit5** as well, with shared TTPs centred on T1566 (Phishing) and T1486 (Data Encrypted for Impact). Initial-access vectors documented across these operations include phishing, credential theft for remote-access services, and exploitation of vulnerable public-facing applications.

> **SOC Action:** Cross-reference the named victim organisations against your supply-chain and customer registries; if any match, initiate third-party-breach IR procedures and pull associated VPN/SSO sessions for review. Review EDR for execution of `readme_locker.txt`-dropping binaries and `.locked` / `.encrypt` extension ransom note artifacts on file servers. Re-validate that internet-facing RDP/VPN/Citrix endpoints enforce phishing-resistant MFA and are not on the public exposure footprint without justification. Tune detections for T1486 high-rate file-modification patterns and T1059 PowerShell + T1078 valid-account anomalies on domain controllers.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Exploitation of vulnerabilities in software supply chains and public-facing applications | Official SAP npm packages compromised to steal credentials; Popular WordPress redirect plugin hid dormant backdoor for years (batch 97) |
| 🔴 **CRITICAL** | Credential-stealing malware exploiting software vulnerabilities | Supply Chain Campaign Targets SAP npm Packages with Credential-Stealing Malware; Learning from the Vercel breach: Shadow AI & OAuth sprawl (batch 96) |
| 🟠 **HIGH** | Increased ransomware activity targeting multiple sectors with varied TTPs | Jgb By qilin; Arban & Carosi By inc ransom; Umiles Group - Database Leaked By everest (batch 97) |
| 🟠 **HIGH** | Increased ransomware activity targeting multiple sectors with overlapping TTPs | PROM By payload; Probity Contracting Group / Edenshaw Developments By qilin; Magisterial Service / Diviso Grupo Financiero By the gentlemen (batch 96) |
| 🟠 **HIGH** | Phishing campaigns leveraging sophisticated techniques across diverse sectors | Hackers arrested for hijacking 610,000 Roblox accounts; ClickFix-style phishing → obfuscated PowerShell execution (batch 96) |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors
- **Qilin** (79 reports) — RaaS operator with sustained victim cadence; Jabber/Tox C2 channels
- **The Gentlemen** (63 reports, plus 24 in lowercase variant) — heavy poster across financial services, manufacturing, and SMBs; Tox-based comms
- **Coinbase Cartel** (31 reports) — active extortion brand
- **DragonForce** (28 reports, plus 21 lowercase) — multi-sector targeting
- **shadowbyt3$** (25 reports) — emerging poster on leak-site monitors
- **ShinyHunters** (21 reports) — credential-data brokerage / extortion
- **TeamPCP** (19 reports) — supply-chain specialist; today's SAP npm compromise

### Malware Families
- **RansomLook / RansomLock** (46 / 45 reports) — leak-site brand mentions; effectively an OSINT signal rather than a malware family proper
- **RaaS** (22 reports) — generic Ransomware-as-a-Service tagging
- **Tox1 / Tox** (21 / 13 reports) — secure-messaging C2 substrate favoured by Qilin, The Gentlemen, Payoutsking
- **DragonForce ransomware** (20 reports) — encryptor in active use
- **Qilin (malware)** (11 reports) — Qilin/Agenda encryptor
- **Gentlemen ransomware** (9 reports) — affiliate encryptor

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| RansomLook | 12 | [link](https://www.ransomlook.io/) | Leak-site aggregation; primary source for victim postings (Qilin, Inc Ransom, Everest, Payoutsking, Krybit, Radar, Payload) |
| BleepingComputer | 3 | [link](https://www.bleepingcomputer.com/news/security/official-sap-npm-packages-compromised-to-steal-credentials/) | Drove all three top-priority items: SAP npm, WordPress backdoor, Qinglong RCE |
| Unknown | 3 | — | Includes brokered Linux CVE disclosure (TLP:AMBER+STRICT) and two Telegram-origin posts |
| RecordedFutures | 2 | [link](https://therecord.media/us-china-partner-on-dubai-scam-compound-takedown) | Section 702 reauthorisation; US/China Dubai scam-centre takedown (276 arrests) |
| SANS | 2 | [link](https://isc.sans.edu/diary/rss/32936) | ISC Stormcast; Libredtail HTTP-cryptomining honeypot analysis |
| Wiz | 1 | [link](https://www.wiz.io/blog/state-of-ai-in-cloud-2026-recap) | 2026 State of AI in the Cloud recap |

> **Telegram-origin items** (Unknown source) — channel URLs intentionally redacted per editorial policy. Two posts: one alleging an imminent breach affecting "over 200 districts in a particular state" (unverified, low specificity); one referencing a DoxByte-affiliated chat invitation.

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Block the four trojanised SAP npm versions in registries today, rotate all secrets that touched any build runner that resolved them, and search GitHub for repos described "A Mini Shai-Hulud has Appeared" — exfiltrated credentials are already public-readable to anyone who finds them. Traceback: §3.2.
- 🔴 **IMMEDIATE:** Patch internet-exposed Qinglong instances to the build containing PR #2941; if patching is blocked, take panels off the public internet today. Hunt for `.fullgc` processes and outbound traffic to `file.551911[.]xyz`. Traceback: §3.4.
- 🟠 **SHORT-TERM:** Inventory WordPress fleets for **Quick Page/Post Redirect** versions 5.2.x, uninstall, and add `anadnet[.]com` to DNS RPZ. Treat any site that ran the affected versions as compromised even though the C2 currently NXDOMAINs. Traceback: §3.3.
- 🟠 **SHORT-TERM:** Open and track CVE-2026-31431 with vendor security feeds; prepare a kernel/util-linux emergency-patch path for Linux fleet. Audit for unexpected user-to-root transitions in the meantime. Traceback: §3.1.
- 🟡 **AWARENESS:** Cross-check victim names from RansomLook (Umiles Group, Morae, Epcon Communities, Data Exchange Corporation, SCS Engineers, SunSource, Bentley Capital Ventures, PROM, Iowa Spring) against your third-party register — supplier compromise can introduce material risk even without direct intrusion. Traceback: §3.5.
- 🟢 **STRATEGIC:** Harden the CI/CD trust boundary: enforce short-lived, scoped npm publish tokens; require workload-identity federation for cloud creds in pipelines; gate `preinstall`/`postinstall` script execution behind allow-listed packages; enable GitHub push-protection and Dependabot supply-chain alerts org-wide. The TeamPCP, Vercel, and Bitwarden incidents are converging on the same primitive. Traceback: §3.2, §4.

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 23 reports processed across 2 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
