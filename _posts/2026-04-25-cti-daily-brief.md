---
layout: post
title:  "CTI Daily Brief: 2026-04-25 — Critical Breeze Cache RCE PoC circulating; Qilin, Lockbit5, M3rx ransomware surge"
date:   2026-04-26 20:30:00 +0000
description: "Two critical vulnerabilities lead the day: a public PoC for CVE-2026-3844 (Breeze Cache unauthenticated RCE) circulating on Telegram, and a Linux BPF stack-out-of-bounds write (CVE-2026-23359). Ransomware activity dominates the picture with Qilin, Lockbit5, M3rx, PEAR and Medusa posting fresh victims across engineering, logistics, healthcare and manufacturing. US utility firm Itron disclosed an internal IT network breach to the SEC."
category: daily
tags: [cti, daily-brief, qilin, lockbit5, m3rx, cve-2026-3844, cve-2026-23359]
classification: TLP:CLEAR
reporting_period: "2026-04-25"
generated: "2026-04-26"
draft: true
severity: critical
report_count: 54
sources:
  - Microsoft
  - RansomLook
  - BleepingComputer
  - Wired Security
  - Telegram (channel name redacted)
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-04-25 (24h) | TLP:CLEAR | 2026-04-26 |

## 1. Executive Summary

The pipeline ingested 54 reports across five sources in the last 24 hours, with two items rated critical and 21 rated high. The dominant theme is **ransomware-as-a-service activity at scale**: Qilin, Lockbit5, M3rx, PEAR, Medusa and Krybit collectively published 16 fresh victim postings spanning engineering, logistics, healthcare, optical, and manufacturing sectors across Europe, North America, Australia and Latin America. The most urgent vulnerability item is **CVE-2026-3844**, an unauthenticated arbitrary file upload to RCE in the Breeze Cache WordPress plugin (≤2.4.4) — a working PoC is being shared on Telegram, increasing the likelihood of opportunistic mass exploitation. A second critical item, **CVE-2026-23359**, is a stack-out-of-bounds write in the Linux kernel BPF devmap component disclosed via Microsoft's MSRC feed alongside 30+ other Linux kernel CVEs published this cycle. Operationally, **US utility technology firm Itron** disclosed an unauthorised intrusion into its internal IT network in an 8-K filing — no ransomware group has claimed the attack and the activity has reportedly been blocked. No CISA KEV additions were observed in the data for this period.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 2 | CVE-2026-3844 Breeze Cache RCE PoC; CVE-2026-23359 Linux BPF devmap OOB write |
| 🟠 **HIGH** | 21 | Qilin/Lockbit5/M3rx/PEAR/Medusa/Krybit victim postings; Linux kernel network/Wi-Fi/Bluetooth CVEs |
| 🟡 **MEDIUM** | 22 | Itron utility breach disclosure; netfilter, NVMe, L2CAP, Squashfs CVEs; Telegram phishing bot |
| 🟢 **LOW** | 8 | Race-condition and memory-leak fixes in NFC, USB, blktrace, ice driver |
| 🔵 **INFO** | 1 | Wired report on White House Correspondents' Dinner shooting (non-cyber) |

## 3. Priority Intelligence Items

### 3.1 CVE-2026-3844 — Breeze Cache (≤2.4.4) Unauthenticated File Upload to RCE — Public PoC

**Source:** Telegram (channel name redacted)

A working proof-of-concept for CVE-2026-3844 is circulating on a Telegram channel known for proxying exploit content. The flaw is an unauthenticated arbitrary file upload in the Breeze Cache WordPress plugin (versions ≤2.4.4) that chains directly into remote code execution due to insufficient validation of uploaded files. Because Breeze Cache is widely deployed on Cloudways-hosted WordPress sites and the exploit requires no authentication, the disclosure window between PoC release and opportunistic mass scanning is typically measured in hours. BleepingComputer corroborated this, separately reporting that hackers are exploiting a file upload bug in Breeze Cache. MITRE techniques referenced in the report include `T1071 — Application Layer Protocol Abuse` and `T1204 — User Execution`.

**Affected products:** Breeze Cache WordPress plugin, all versions ≤ 2.4.4.

> **SOC Action:** Immediately inventory WordPress estates for the Breeze Cache plugin and force-update to a patched release. Block POST requests to `/wp-admin/admin-ajax.php` and the plugin's upload endpoints from non-trusted source IPs at the WAF, alert on web shells dropped under `wp-content/uploads/`, and hunt for new PHP files in upload directories created in the last 7 days. Where patching is delayed, disable the plugin.

### 3.2 CVE-2026-23359 — Linux Kernel BPF devmap Stack-Out-of-Bounds Write

**Source:** [Microsoft MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-23359)

Microsoft's MSRC feed disclosed a stack-out-of-bounds write in the Berkeley Packet Filter (BPF) devmap component of the Linux kernel. An attacker able to deliver crafted packets to a vulnerable host could potentially trigger arbitrary code execution or denial of service in kernel context. This is one of more than 30 Linux kernel CVEs (CVE-2026-23348 through CVE-2026-23399 range) published in the same cycle, several of which are independently rated high — including CVE-2026-23398 (NULL pointer dereference in `icmp_tag_validation()`), CVE-2026-23396 (NULL deref in mac80211 mesh), CVE-2026-23392 (netfilter `nf_tables` flowtable release), CVE-2026-23391 (xt_CT packet drop on template removal), and CVE-2026-31788 (Xen `privcmd` privilege restriction in unprivileged domU). No in-the-wild exploitation has been reported for any of these in the data set.

**Affected products:** Linux kernel (BPF devmap, ICMP, mac80211, netfilter, Xen privcmd, DRBD, ksmbd, NVMe, L2CAP, Squashfs subsystems).

> **SOC Action:** Subscribe to vendor advisories for your Linux distribution (Red Hat, SUSE, Ubuntu, Debian, Amazon Linux) and prioritise rolling out kernel updates for internet-facing hosts and Wi-Fi/Bluetooth-enabled endpoints first. Deprioritise CVE-2026-23359 patching on hosts where unprivileged BPF is disabled (`kernel.unprivileged_bpf_disabled=1`). For mac80211 and L2CAP CVEs, restrict Wi-Fi and Bluetooth on production servers and lab kit not requiring radio.

### 3.3 Ransomware Surge — Qilin, Lockbit5, M3rx, PEAR, Medusa, Krybit

**Sources:** [Qilin (RansomLook)](https://www.ransomlook.io//group/qilin), [Lockbit5 (RansomLook)](https://www.ransomlook.io//group/lockbit5), [M3rx (RansomLook)](https://www.ransomlook.io//group/m3rx), [PEAR (RansomLook)](https://www.ransomlook.io//group/pear), [Medusa (RansomLook)](https://www.ransomlook.io//group/medusa), [Krybit (RansomLook)](https://www.ransomlook.io//group/krybit)

The pipeline observed 16 fresh victim postings across six RaaS leak sites in the last 24 hours. **Qilin** posted five new victims (Longwood Engineering, Muller Technology, A & A Building Material, Istarpal, Exclusive Networks) — the group has now generated 1,725 posts all-time and 103 in the last 30 days, making it the most prolific actor in the pipeline (also the top trending threat actor with 68 reports, last seen 2026-04-26 19:56). **Lockbit5** added three victims (bladex.com, heinrichs-logistic.de, merlo.de) — affiliates `LockBitSupp` and `Wazawaka` are listed. **M3rx**, a comparatively newer group with only six all-time posts, claimed substantial data theft from five organisations (dmschweiz.ch — 120GB, anvilarts.org.uk — 480GB, primeproperties.com.au — 100GB, airdriephysio.com — 54GB, rainforestclean.com — 259GB). **PEAR**, **Medusa** (Walman Optical / EssilorLuxottica subsidiary) and **Krybit** (Narteks Tekstil) each posted one victim. The AI correlation engine grouped the Qilin postings with confidence 0.95 and the M3rx postings with confidence 0.92, anchored on shared `T1566 — Phishing`, `T1485 — Data Encrypted for Impact`, and `T1071.001 — Application Layer Protocol: Web Protocols`.

**Affected sectors:** Engineering, manufacturing, logistics, building materials, telecoms, optical/eye care, plumbing, physiotherapy, textiles, finance.

> **SOC Action:** Prioritise the Qilin, Lockbit5 and M3rx affiliate playbooks: hunt for unsigned PowerShell, AnyDesk/ScreenConnect installs, fresh service principal creation, and outbound connections to known Tox-bootstrap nodes from server VLANs. Validate that offline backups for high-value file shares were tested in the last 30 days. For the named Qilin onion `ijzn3sicrcy7guixkzjkib4ukbiilwc3xhnmby4mcbccnsd7j2rekvqd[.]onion` (90% uptime, 30d) and Lockbit5 admin onion `lockbitapt67g6rwzjbcxnww5efpg4qok6vpfeth7wx3okj52ks4wtad[.]onion` (100% uptime), block Tor egress at the proxy and alert on any allow-listed exception.

#### Indicators of Compromise

```
Qilin onion (active):    ijzn3sicrcy7guixkzjkib4ukbiilwc3xhnmby4mcbccnsd7j2rekvqd[.]onion
Qilin onion (active):    pandora42btuwlldza4uthk4bssbtsv47y4t5at5mo4ke3h4nqveobyd[.]onion
Qilin file server:       kg2pf5nokg5xg2ahzbhzf5kucr5bc4y4ojordiebakopioqkk4vgz6ad[.]onion
Qilin C2 IP:             31.41.244[.]100
Qilin Jabber:            qilin@exploit[.]im
Qilin Tox ID:            7C35408411AEEBD53CDBCEBAB167D7B22F1E66614E89DFCB62EE835416F60E1B
Lockbit5 admin onion:    lockbitapt67g6rwzjbcxnww5efpg4qok6vpfeth7wx3okj52ks4wtad[.]onion
Lockbit5 chat onion:     lockbitsuppyx2jegaoyiw44ica5vdho63m5ijjlmfb7omq3tfr3qhyd[.]onion
Lockbit5 file server:    lockbitfss2w7co3ij6am6wox4xcurtgwukunx3yubcoe5cbxiqakxqd[.]onion
Lockbit5 Tox ID:         3085B89A0C515D2FB124D645906F5D3DA5CB97CEBEA975959AE4F95302A04E1D
M3rx leak onion:         4k6plf4h2cm2nco6ae3inrsxnmqgl6lllmwefydhnlcq4tuhwbj4qpad[.]onion
M3rx Tox ID:             9A1217BEDA4AB77052A25D17CB6FFB34AFA2BE462E607F2FD8E1DF1DDD4CA16A
PEAR mail:               pear@onionmail[.]org
PEAR onion:              peargxn3oki34c4savcbcfqofjjwjnnyrlrbszfv6ujlx36mhrh57did[.]onion
Ransom note (Qilin):     README-RECOVER-[rand].txt
Ransom note (M3rx):      RECOVERY_NOTES.TXT
Ransom note (Medusa):    !!!READ_ME_MEDUSA!!!.txt
```

### 3.4 Itron, Inc. — US Utility Technology Firm Discloses Internal IT Network Breach

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/american-utility-firm-itron-discloses-breach-of-internal-it-network/)

Washington-based utility technology firm **Itron** (NASDAQ-listed; ~5,600 employees; $2.4B 2025 revenue; 7,700 customers across 100 countries; 112 million managed endpoints) disclosed in an SEC 8-K filing that an unauthorised third party gained access to certain internal systems on **2026-04-13**. The company activated its incident response plan, notified law enforcement, engaged external advisors, and reports the activity has now been blocked with no observed follow-on activity and no material business disruption. No ransomware group has claimed the attack, and Itron states the unauthorised access did not extend to customers — though the investigation remains ongoing. Itron's portfolio interlocks with electricity, water and gas critical infrastructure, making this a watch-item for downstream supply chain risk to utility operators that integrate Itron metering and grid management products.

**Affected sectors:** Critical infrastructure (energy, water, gas) — supply chain.

> **SOC Action:** Utility operators using Itron meters, head-end systems or grid management software should request from Itron account teams a written confirmation that customer-facing infrastructure was unaffected, and review outbound traffic from Itron-connected management hosts since 2026-03-13 (30-day lookback) for anomalous beaconing, large data transfers, or new SaaS administrative logins. File a 24-hour incident notification to NERC CIP / sector ISAC if any indicators are detected.

### 3.5 Telegram-Based Phishing Bot Campaign — "Breached" Lookup Bot

**Source:** Telegram (channel name redacted)

Two reports captured a Telegram-based phishing operation centred on a "Breached" lookup bot that promises free tokens via a `/breached` command and harvests user data through onion-redirect links. While individually low-impact, the campaign sits alongside the same Telegram channel ecosystem that is currently distributing the Breeze Cache PoC (Section 3.1) — analysts should treat the broader channel cluster as a single low-trust source. The activity maps to `T1566 — Phishing` and `T1566.001 — Phishing: Spearphishing Link`.

> **SOC Action:** Add Telegram bot URLs and `t.me/*` shortlinks to phishing awareness training examples. Detection engineers should hunt for outbound DNS to `t[.]me` from corporate endpoints not associated with sanctioned messaging use, and flag any user-clicked Telegram redirect that lands on an onion service.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Exploitation of software vulnerabilities leading to critical security risks. | CVE-2026-3844 Breeze Cache ≤2.4.4 unauthenticated arbitrary file upload to RCE (PoC published) |
| 🟠 **HIGH** | Increased ransomware activity targeting diverse sectors globally. | Qilin (Longwood, Muller, A & A Building, Istarpal, Exclusive Networks); Lockbit5 (bladex.com, heinrichs-logistic.de, merlo.de); M3rx; PEAR; Medusa; Krybit |
| 🟠 **HIGH** | Phishing remains the prevalent initial-access TTP across RaaS campaigns. | Qilin, M3rx, PEAR, Krybit reports — `T1566 — Phishing` recurs as the top correlation TTP (13 mentions) |
| 🟡 **MEDIUM** | Exploitation of vulnerabilities in network and communication protocols. | CVE-2026-23368 (PHY led_triggers AB-BA deadlock); CVE-2026-23361 (PCI dwc MSI-X); CVE-2026-23398 (ICMP NULL deref); CVE-2026-23396 (mac80211 mesh) |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors
- **Qilin** (68 reports) — Most active RaaS group in the pipeline; last seen 2026-04-26 19:56; targeting engineering, finance, healthcare globally.
- **The Gentlemen** (58 reports) — Sustained activity over the last 30 days; not active in the current 24h window.
- **Coinbase Cartel** (38 reports) — Active extortion brand; last seen 2026-04-23.
- **DragonForce** (28 reports) — Continued posting cadence, primarily late-March through mid-April.
- **nightspire** (27 reports) — Healthcare and public-sector targeting (e.g., Swansea Ambulance Corps).
- **shadowbyt3$** (25 reports) — Recent activity on ransom-leak forums.
- **Lockbit5** (active today) — Posted three victims; Affiliates `LockBitSupp`, `Wazawaka` listed.
- **M3rx** (active today, only 6 posts all-time) — Aggressive newcomer publishing large data-theft claims (54–480 GB per victim).

### Malware Families
- **RansomLook** (35 reports, last seen 2026-04-26) — Recurring leak-site parser tag; appears across Qilin, M3rx, Medusa entries.
- **RaaS** (25 reports) — Generic tag indicating Ransomware-as-a-Service operating model.
- **dragonforce ransomware** (21 reports).
- **Tox1 / Tox** (29 combined) — Threat actor messaging client recurring across Qilin, Lockbit5, M3rx, PEAR.
- **Qilin** (9 malware-tagged reports) — Beyond actor mentions.
- **Gentlemen ransomware** (9 reports).

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| Microsoft (MSRC) | 33 | [link](https://msrc.microsoft.com/update-guide) | Linux kernel CVE batch (CVE-2026-23348 → CVE-2026-23399, plus CVE-2026-31788); one critical (CVE-2026-23359 BPF devmap). |
| RansomLock | 16 | [link](https://www.ransomlook.io/) | Aggregated ransomware leak-site postings: Qilin (×5), M3rx (×5), Lockbit5 (×3), PEAR, Medusa, Krybit. |
| Unknown (Telegram) | 3 | — | Critical Breeze Cache PoC; "Breached" phishing bot pinned posts. Channels not linked per editorial policy. |
| BleepingComputer | 1 | [link](https://www.bleepingcomputer.com/news/security/american-utility-firm-itron-discloses-breach-of-internal-it-network/) | Itron utility firm SEC 8-K disclosure. |
| Wired Security | 1 | [link](https://www.wired.com/story/california-engineer-identified-in-suspected-shooting-at-white-house-correspondents-dinner/) | Non-cyber; informational only. |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Patch or disable the Breeze Cache WordPress plugin (≤2.4.4) across all managed WordPress estates today. A working PoC for CVE-2026-3844 is in active circulation; opportunistic exploitation should be assumed within 24 hours of PoC release. Hunt for new files in `wp-content/uploads/` and unexplained PHP processes spawned by the web server user.
- 🔴 **IMMEDIATE:** Block egress to and alert on hits against the Qilin, Lockbit5, M3rx, PEAR and Medusa onion infrastructure listed in §3.3 IOCs. Confirm offline-backup tested-restore status for high-value file shares within 7 days.
- 🟠 **SHORT-TERM:** Roll the Linux kernel CVE-2026-23348 → 23399 batch through change management with priority on internet-facing hosts, Wi-Fi/Bluetooth-enabled endpoints, and Xen-based virtualisation hosts (CVE-2026-31788). Set `kernel.unprivileged_bpf_disabled=1` on hosts that don't require unprivileged BPF as a quick-mitigation for CVE-2026-23359.
- 🟠 **SHORT-TERM:** Utility operators with Itron product dependencies should request written breach-impact confirmation from account teams and conduct a 30-day outbound traffic review on Itron-connected management hosts. File ISAC notification if anomalies surface.
- 🟡 **AWARENESS:** Brief end users on Telegram-bot phishing lures using free-token / "lookup" pretexts. Ensure security awareness libraries include current Telegram redirect examples.
- 🟢 **STRATEGIC:** Phishing (`T1566`) is the dominant initial-access TTP across today's RaaS reports (13 entity mentions). Reassess phishing simulation cadence, MFA enforcement on email and VPN, and conditional access for risky-sign-in events as a baseline posture improvement against the Qilin/Lockbit5/M3rx/PEAR threat cluster.

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 54 reports processed across 3 correlation batches in the last 24 hours (batches 89, 90, 91). A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
