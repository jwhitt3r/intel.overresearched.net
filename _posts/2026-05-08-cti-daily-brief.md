---
layout: post
title:  "CTI Daily Brief: 2026-05-08 - Linux page-cache 0-days exploited in the wild; Genesis ransomware burst hits US healthcare and legal sectors"
date:   2026-05-09 20:15:00 +0000
description: "Elastic confirms Copy Fail (CVE-2026-31431) added to CISA KEV; DirtyFrag widens the same bug class across the Linux network stack. Genesis ransomware posts five US victims in one day. Trending Hugging Face repo (244k downloads) ships Rust infostealer."
category: daily
tags: [cti, daily-brief, genesis, dragonforce, qilin, shinyhunters, copy-fail, dirtyfrag, cve-2026-31431, cve-2026-3832, cve-2026-4948]
classification: TLP:CLEAR
reporting_period: "2026-05-08"
generated: "2026-05-09"
draft: true
severity: critical
report_count: 27
sources:
  - Microsoft
  - Elastic Security Labs
  - BleepingComputer
  - Schneier
  - Wired Security
  - RansomLook
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-05-08 (24h) | TLP:CLEAR | 2026-05-09 |

## 1. Executive Summary

The pipeline ingested 27 reports across seven sources in the last 24 hours, dominated by ransomware leak-site activity (19 of 27 reports) and a pair of critical Linux kernel disclosures. Elastic Security Labs published detection logic for **Copy Fail** (CVE-2026-31431) and **DirtyFrag**, two page-cache corruption bugs that yield reliable local root on Ubuntu, Amazon Linux, RHEL, and SUSE — Copy Fail is reported exploited in the wild and has been added to CISA's Known Exploited Vulnerabilities catalog. The Genesis ransomware group posted five US victims in a single 24-hour window across healthcare, legal, and engineering sectors, and a typosquatted "Open-OSS/privacy-filter" repository on Hugging Face accumulated 244,000 downloads while delivering a Rust-based infostealer to a `recargapopular[.]com` C2. Microsoft also disclosed CVE-2026-3832, a GnuTLS OCSP bypass that accepts revoked certificates, and CVE-2026-4948, a firewalld D-Bus authorization flaw enabling local firewall tampering. AI correlation flagged Linux privilege escalation as the dominant critical trend; phishing (T1566) was the most-mentioned ATT&CK technique across the day's data (14 mentions).

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 2 | Linux page-cache 0-days (Copy Fail / DirtyFrag); GnuTLS OCSP bypass (CVE-2026-3832) |
| 🟠 **HIGH** | 20 | Genesis, Qilin, DragonForce, ShinyHunters, killsec3, Inc Ransom, PEAR, Sinobi leak-site activity; Hugging Face infostealer; firewalld CVE-2026-4948 |
| 🟡 **MEDIUM** | 2 | Yarbo robot lawn-mower remote takeover; leak bazaar low-confidence post |
| 🔵 **INFO** | 3 | CVE-2026-41526 (no detail); ransomware tracker telegram digest; Schneier squid blog |

## 3. Priority Intelligence Items

### 3.1 Copy Fail and DirtyFrag — Linux page-cache 0-days exploited in the wild (CISA KEV)

**Source:** [Elastic Security Labs](https://www.elastic.co/security-labs/copy-fail-dirtyfrag-linux-page-bugs-in-the-wild)

Elastic Security Labs published technical analysis and detection logic for two Linux kernel privilege-escalation vulnerabilities that exploit page-cache corruption to obtain reliable root. **Copy Fail (CVE-2026-31431)** is a logic bug in the kernel's `authencesn` cryptographic template that chains `AF_ALG` and `splice()` to perform a controlled 4-byte write into the page cache of any readable file — corrupting the in-memory view of a setuid binary like `/usr/bin/su` without modifying the file on disk. The public exploit is a 732-byte Python script that works across Ubuntu, Amazon Linux, RHEL, and SUSE. Copy Fail has been reported exploited in the wild and added to CISA's KEV catalog. **DirtyFrag** extends the same primitive into the networking stack: an ESP variant uses XFRM security associations via `AF_NETLINK` to overwrite `/usr/bin/su`, while an `AF_RXRPC` + `pcbc(fcrypt)` fallback corrupts `/etc/passwd` to clear root's password. DirtyFrag does **not** require the `algif_aead` module, so systems patched only against Copy Fail remain exposed. Public PoCs exist in Python, Go, Rust, C, and Metasploit. Exploits require `unshare(CLONE_NEWUSER | CLONE_NEWNET)` for namespace capability acquisition before triggering the page-cache write. Affected: all major Linux distributions running unpatched kernels.

#### Indicators of Compromise

```
Syscall pattern: socket(AF_ALG)  →  hex a0 = 26
Syscall pattern: socket(AF_RXRPC) →  hex a0 = 21
Behavior:        non-root splice() into setuid binary page cache
Behavior:        unshare(CLONE_NEWUSER|CLONE_NEWNET) followed by EUID 0
Targeted files:  /usr/bin/su, /etc/passwd
CVEs:            CVE-2026-31431 (Copy Fail), DirtyFrag (ESP + RxRPC variants)
Related:         CVE-2026-43284, CVE-2026-43500 (Dirty Frag earlier disclosure)
```

ATT&CK: T1068 (Exploitation for Privilege Escalation), T1078.004 (Valid Accounts: Local), T1098.002 (Account Manipulation: Clear Text Password)

> **SOC Action:** Patch Linux kernels across all distributions immediately and prioritise internet-exposed and multi-tenant systems. Deploy Elastic's published EQL detection: correlate `auditd` syscall events for `socket` with `a0` of `26`/`21` and `splice()` from non-root processes within 60 seconds of an `EUID=0` transition. Restrict `unprivileged_userns_clone` (`sysctl kernel.unprivileged_userns_clone=0`) on hosts that don't require user namespaces. Audit for unexpected modifications to `/etc/passwd` mtime or in-memory hash divergence on `/usr/bin/su`.

### 3.2 GnuTLS OCSP revocation bypass — CVE-2026-3832 (CRITICAL)

**Source:** [Microsoft Security Response Center](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-3832)

CVE-2026-3832 is a security-bypass vulnerability in the GnuTLS library's OCSP response handling. A crafted OCSP response can cause GnuTLS to accept a revoked server certificate as valid, defeating the certificate-validation safety net relied on by countless Linux applications, mail clients, package managers, and network daemons that link against GnuTLS. The flaw enables adversaries who already control or can MitM a TLS path to present revoked certificates without alarms. No in-the-wild exploitation reported as of publication.

ATT&CK: T1219 (Remote Access Software), T1566 (Phishing) — adversary in the middle.

> **SOC Action:** Inventory GnuTLS dependents (`apt rdepends libgnutls30`, `rpm -q --whatrequires gnutls`) and patch as upstream fixes ship from distributions. Until then, prefer applications that use OpenSSL where possible for sensitive paths. Hunt for repeated TLS connections to internal services from clients presenting certificates whose serial numbers appear on published CRLs.

### 3.3 Genesis ransomware — five US victims posted in 24 hours

**Sources:** [RansomLook — Genesis](https://www.ransomlook.io//group/genesis)

The Genesis data-extortion group posted five new victims on 2026-05-09: **CarePoint Health**, **The American Board of Preventive Medicine**, **Prescott & Holden** (legal), **Van Atta Engineering** (Dayton, OH), and **Rain Makers Solutions**. Genesis describes itself as financially motivated only — it states it does not run an affiliate programme, does not re-attack victims, and publishes a separate "parsed" folder of the most sensitive data on darkweb forums to maximise leverage. It claims it avoids medical and charitable institutions unless "reputation gaps" are present, but two of the five 24-hour victims are healthcare-adjacent (CarePoint Health, American Board of Preventive Medicine). The group's leak portal averaged 93% uptime over the last 30 days; AI correlation rated this campaign at 0.90 confidence under shared TTPs T1566 (Phishing) and T1485/T1486 (Data Encrypted for Impact) and US healthcare/engineering/legal sector targeting.

#### Indicators of Compromise

```
Contact:  genesis.info@onionmail[.]org
Onion:    genesis6ixpb5mcy4kudybtw5op2wqlrkocfogbnenz3c647ibqixiad[.]onion
Pattern:  "parsed" folder structure on darkweb leak posts
Sectors:  healthcare, legal services, engineering, professional services
```

ATT&CK: T1566 (Phishing), T1486 (Data Encrypted for Impact), T1071 (Application Layer Protocol)

> **SOC Action:** Healthcare and legal-services SOCs in the US should query EDR/email gateways for new phishing waves targeting clinical, billing, and legal-records staff. Block known Genesis OnionMail contact addresses at email gateways. Verify backups for the named victims' peer organisations (regional medical specialty boards, mid-size US engineering firms) are immutable and tested. Hunt for unusual outbound bulk-archive uploads (>1 GB) over Tor or commodity file-transfer services from domain controllers or file servers.

### 3.4 Fake OpenAI "Privacy Filter" repository on Hugging Face — Rust infostealer with 244k downloads

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/fake-openai-repository-on-hugging-face-pushes-infostealer-malware/)

A typosquatted Hugging Face repository named `Open-OSS/privacy-filter` reached the platform's #1 trending slot and recorded 244,000 downloads (likely partly inflated by 667 auto-generated likes) before HiddenLayer reported it and the platform took it down. The repository copied OpenAI's legitimate "Privacy Filter" model card almost verbatim and shipped a `loader.py` that disabled SSL verification, fetched a base64-decoded URL, and executed a JSON-delivered PowerShell command in an invisible window. That PowerShell stage downloaded `start.bat`, performed privilege escalation, added an exclusion to Microsoft Defender, and executed a Rust infostealer named `sefirah`. The stealer harvests Chromium/Gecko cookies, saved passwords, encryption keys, session tokens, Discord tokens and master keys, cryptocurrency wallets and seed phrases, SSH/FTP/VPN/FileZilla credentials, sensitive local files, system info, and multi-monitor screenshots; data is exfiltrated to `recargapopular[.]com`. HiddenLayer also identified an overlapping npm typosquatting campaign distributing the WinOS 4.0 implant. Compromised users should reimage, rotate all credentials, replace cryptocurrency wallets and seed phrases, and invalidate all browser sessions.

#### Indicators of Compromise

```
C2:           hxxps[:]//recargapopular[.]com
Repo (taken down): Open-OSS/privacy-filter (Hugging Face)
Loader:       loader.py (disables SSL verification, base64-decodes URL)
Stage 2:      start.bat (privilege escalation + Defender exclusion)
Final:        sefirah (Rust infostealer, anti-VM/sandbox/debugger checks)
Related:      WinOS 4.0 implant (npm typosquatting overlap)
```

ATT&CK: T1566 (Phishing — typosquatting), T1059.001 (PowerShell), T1218 (Signed Binary Proxy Execution), T1562.001 (Disable or Modify Tools — Defender exclusion)

> **SOC Action:** Block `recargapopular[.]com` at perimeter DNS and proxy. EDR-hunt for `python.exe` or developer-laptop processes spawning `powershell.exe -w hidden` and creating `start.bat` in user temp directories within the last 30 days. Audit `Add-MpPreference -ExclusionPath` events on developer endpoints. Block or alert on Hugging Face `Open-OSS/*` namespace pulls in CI/CD. Mandate package and model-source allow-listing for any AI/ML pipeline that consumes Hugging Face artefacts.

### 3.5 firewalld D-Bus authorization flaw — CVE-2026-4948 (HIGH)

**Source:** [Microsoft Security Response Center](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-4948)

CVE-2026-4948 is a D-Bus setter authorization flaw in `firewalld`. A local unprivileged user can modify the firewall state because the configuration-management interface fails to perform sufficient privilege checks on D-Bus property setters. Combined with a local-execution primitive (such as Copy Fail or DirtyFrag in the same disclosure window), an attacker could disable host firewall rules to enable lateral movement before further escalation. Affects RHEL/Fedora-family distributions and any system using `firewalld` as the active firewall manager.

ATT&CK: T1068 (Exploitation for Privilege Escalation), T1562.004 (Disable or Modify System Firewall)

> **SOC Action:** Apply distribution updates for `firewalld` as they ship. Until patched, audit `polkit` rules governing `org.fedoraproject.FirewallD1` and consider tightening D-Bus method access via `polkit` rules to restrict configuration changes to the `wheel` group. Alert on unexpected `firewall-cmd --reload`, `--add-service`, or `--remove-rich-rule` invocations from non-administrative users.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Linux kernel vulnerabilities being exploited for privilege escalation | Copy Fail and DirtyFrag (Elastic Security Labs); CVE-2026-4948 firewalld D-Bus mis-authorization |
| 🔴 **CRITICAL** | Earlier-cycle: Dirty Frag (CVE-2026-43284 / CVE-2026-43500) — universal Linux LPE via ESP and RxRPC; root on all major distros |
| 🟠 **HIGH** | Genesis ransomware group targeting multiple US sectors with high severity | Prescott & Holden, Van Atta Engineering, CarePoint Health, American Board of Preventive Medicine, Rain Makers Solutions |
| 🟠 **HIGH** | Increased ransomware activity targeting education and other sectors with persistent threats | Houghton Mifflin Harcourt (ShinyHunters); Canvas LMS incident across multiple universities |
| 🟠 **HIGH** | Phishing and credential-theft campaigns targeting a wide range of sectors | mrs holdings (killsec3); CF Evans Construction and CMC Expertise Comptable (DragonForce) |
| 🟡 **MEDIUM** | Phishing as a common TTP across diverse threat reports | Hugging Face fake OpenAI repo; Yarbo robot lawn mower; CVE-2026-3832 GnuTLS OCSP bypass |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **Qilin** (102 reports, last 30d) — RaaS group with 5 victim posts in this 24h window (Lindabury, Ruiz Barbarin Arquitectos Slp, DL Cohen Construction, Fogel Capital Management, Calidra)
- **The Gentlemen** (58 reports) — manufacturing, telecommunications, chemical-manufacturing focus
- **Akira** (50 reports) — sustained healthcare and education sector targeting
- **DragonForce** (30 reports) — RaaS cartel, 2 fresh victims this cycle (CF Evans Construction, CMC Expertise Comptable)
- **ShinyHunters** (29 reports) — education-sector emphasis; Houghton Mifflin Harcourt posted today
- **Coinbase Cartel** (26 reports) — last seen 2026-04-23, no fresh activity this cycle
- **Lamashtu** (22 reports) — diversified targeting
- **Everest** (22 reports) — last seen 2026-05-07
- **Inc Ransom** (21 reports) — Calsoft Inc posted in this cycle
- **Genesis** (5 fresh posts in 24h) — covered in §3.3

### Malware Families

- **RansomLook** (85 reports) — leak-site aggregation tag
- **RansomLock** (40 reports) — overlapping leak-site tagging
- **Tox1** (35 reports) — Tox-based C2 communication marker (The Gentlemen, others)
- **Akira ransomware** (26 reports) — active in healthcare
- **RaaS** (18 reports) — generic ransomware-as-a-service tag
- **Qilin** (13 reports as malware family) — encryptor distinct from group identity
- **infostealer** / **sefirah** (Rust) — new this cycle, see §3.4
- **WinOS 4.0 implant** — npm typosquatting overlap, see §3.4

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| RansomLook | 19 | [link](https://www.ransomlook.io/) | Primary leak-site coverage: Genesis (5), Qilin (5), DragonForce (2), ShinyHunters, killsec3, Inc Ransom, PEAR, Sinobi, leak bazaar |
| Microsoft | 3 | [MSRC](https://msrc.microsoft.com/update-guide/) | CVE disclosures: CVE-2026-3832 (critical), CVE-2026-4948 (high), CVE-2026-41526 (info) |
| Elastic Security Labs | 1 | [link](https://www.elastic.co/security-labs/copy-fail-dirtyfrag-linux-page-bugs-in-the-wild) | Critical Linux LPE detection guidance — see §3.1 |
| BleepingComputer | 1 | [link](https://www.bleepingcomputer.com/news/security/fake-openai-repository-on-hugging-face-pushes-infostealer-malware/) | Hugging Face infostealer campaign — see §3.4 |
| Wired Security | 1 | [link](https://www.wired.com/story/security-news-this-week-hackable-robot-lawnmower-unlocks-a-new-nightmare/) | Yarbo robot lawn-mower remote takeover; Meta drops Instagram DM E2EE |
| Schneier | 1 | [link](https://www.schneier.com/) | Friday squid post — informational |
| Telegram (channel name redacted) | 1 | — | Ransomware tracker digest — TLP:AMBER+STRICT |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Patch all Linux hosts against Copy Fail (CVE-2026-31431) and DirtyFrag — Copy Fail is on CISA KEV and exploited in the wild. Disable `kernel.unprivileged_userns_clone` where not needed. Deploy Elastic's EQL detection for the `socket(AF_ALG/AF_RXRPC) → splice → EUID=0` pattern (§3.1).
- 🔴 **IMMEDIATE:** Block `recargapopular[.]com` at perimeter and EDR. Audit developer and data-science endpoints for `Open-OSS/privacy-filter` Hugging Face pulls in the last 14 days; reimage and rotate all credentials for any user that did pull it (§3.4).
- 🟠 **SHORT-TERM:** Healthcare, legal, and engineering SOCs in the US: review email-gateway phishing detections, validate offline backups, and run table-top exercises against the Genesis extortion playbook (§3.3). Apply firewalld update for CVE-2026-4948 and harden `polkit` rules for `org.fedoraproject.FirewallD1` (§3.5).
- 🟠 **SHORT-TERM:** Inventory GnuTLS dependents and patch CVE-2026-3832 as distribution fixes ship; treat the OCSP-bypass as MitM-enabling for any GnuTLS-linked client until remediated (§3.2).
- 🟡 **AWARENESS:** Brief security and ML-platform teams on the rising rate of typosquatted AI/ML model repositories on Hugging Face and npm. Enforce a model-source allow-list in CI/CD pipelines.
- 🟢 **STRATEGIC:** Standardise on auditd + EDR detection for namespace-creation primitives (`unshare(CLONE_NEWUSER|CLONE_NEWNET)`) — multiple recent Linux LPE classes (Dirty Frag, DirtyFrag, Copy Fail) rely on user-namespace capability acquisition. Treat unprivileged user namespaces as a high-value detection surface across the Linux estate.

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 27 reports processed across 2 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
