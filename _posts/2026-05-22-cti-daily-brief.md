---
layout: post
title:  "CTI Daily Brief: 2026-05-22 - Apache.NMS.AMQP unauthenticated RCE; BIND 9 / Rsync / DNSCrypt critical drop; ShinyHunters and Inc Ransom continue extortion sprees"
date:   2026-05-23 20:30:00 +0000
description: "51 reports across 8 sources. Eight critical CVEs led by an unauthenticated RCE in Apache.NMS.AMQP and a large Microsoft / upstream BIND 9, Rsync, DNSCrypt, DNSSEC patch wave. ShinyHunters keep posting US telecoms and healthcare victims; Inc Ransom hits Spanish aerospace; SARS allegedly breached by nullsec."
category: daily
tags: [cti, daily-brief, shinyhunters, inc-ransom, nova, bind9, rsync, cve-2025-54539, cve-2026-3593]
classification: TLP:CLEAR
reporting_period: "2026-05-22"
generated: "2026-05-23"
draft: true
report_count: 51
severity: critical
sources:
  - Microsoft
  - RansomLock
  - BleepingComputer
  - Wired Security
  - SANS
  - Schneier
  - RecordedFutures
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-05-22 (24h) | TLP:CLEAR | 2026-05-23 |

## 1. Executive Summary

The pipeline processed 51 reports across 8 sources, with eight critical-severity items dominated by an unauthenticated remote code execution vulnerability in Apache.NMS.AMQP (CVE-2025-54539) and a large Microsoft / upstream patch wave covering BIND 9, Rsync < 3.4.3, DNSCrypt and DNSSEC validators, Qt Network's OpenSSL backend, haveged, libyang, and Pallets Click. Ransomware leak-site activity remained the dominant operational story: ShinyHunters posted three new US victims (Charter Communications, Baker Distributing, DentaQuest), Inc Ransom claimed Spanish aerospace supplier mymgroup.es, Nova (RALord rebrand) continued targeting construction firms, and Krybit listed the Bangkok Metropolitan Administration. A separate Telegram post by the group "nullsec" claims a breach of the South African Revenue Service (SARS). No confirmed in-the-wild exploitation or CISA KEV additions were observed in the 24-hour window, but CISA's new community-nomination form for the KEV catalogue went live.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 8 | Apache.NMS.AMQP unauth RCE; BIND 9 DoH UAF; DNSSEC/DNSCrypt RCE; Rsync TOCTOU & off-by-one; Qt OpenSSL rogue CA; haveged root EoP |
| 🟠 **HIGH** | 23 | ShinyHunters, Inc Ransom, Nova, Krybit, Genesis, Leaknet ransomware leaks; BIND 9 DoS / cache poisoning cluster; nullsec / SARS claim |
| 🟡 **MEDIUM** | 13 | Rsync xattr UAF; BIND 9 NSEC3 / EDNS performance bugs; NGINX JavaScript flaw; CINEMAGOAL piracy app takedown; FBI ALPR push |
| 🟢 **LOW** | 3 | BIND 9 EDNS option list; qs.stringify crash; BIND CLASS != IN handling |
| 🔵 **INFO** | 4 | CISA opens KEV nominations; SANS stack-string analysis; Schneier squid Friday; "Elite Squad" Telegram dump |

## 3. Priority Intelligence Items

### 3.1 CVE-2025-54539 — Apache.NMS.AMQP unauthenticated RCE via deserialization policy bypass

**Source:** Telegram (channel name redacted)

A critical deserialization-policy bypass in Apache.NMS.AMQP allows unauthenticated remote code execution. The flaw is in input validation during object deserialization; an attacker who can reach an AMQP endpoint can execute arbitrary code with no credentials. Affected products include any .NET application embedding the Apache.NMS.AMQP client to consume AMQP 1.0 messages — common in industrial messaging, integration brokers, and financial back-office systems. ATT&CK mappings noted in the source: T1204 (User Execution), T1070 (Indicator Removal on Host). The disclosure surfaced via a Telegram channel; vendor-level confirmation should be verified before mass remediation, but the unauthenticated nature warrants immediate triage.

> **SOC Action:** Inventory all .NET services that import `Apache.NMS.AMQP` (search NuGet manifests and deployed assemblies). Restrict ingress to AMQP brokers (TCP/5671, TCP/5672) to known producer subnets at the firewall. Hunt EDR for unexpected child processes spawned from `w3wp.exe`, `dotnet.exe`, or service-host processes that load `Apache.NMS.AMQP.dll`. Pin a detection on outbound C2 from these processes pending an upstream patch advisory.

### 3.2 BIND 9 critical & high cluster — DNS-over-HTTPS UAF plus DoS/cache-poisoning batch

**Source:** [Microsoft MSRC — CVE-2026-3593](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-3593), [CVE-2026-42944](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-42944), [CVE-2026-40622](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-40622), [CVE-2026-42960](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-42960), [CVE-2026-5950](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-5950), [CVE-2026-3592](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-3592), [CVE-2026-3039](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-3039)

A coordinated upstream BIND 9 disclosure produced one critical and six high-severity CVEs. CVE-2026-3593 is a heap use-after-free in the DNS-over-HTTPS implementation that may permit arbitrary code execution or service crash through crafted DoH requests. The six high-severity flaws cover a heap overflow when processing multiple NSID/COOKIE/PADDING EDNS options (CVE-2026-42944), a "ghost domain names" attack variant (CVE-2026-40622), authority-section cache poisoning (CVE-2026-42960), an unbounded resolver resend loop (CVE-2026-5950), self-pointed glue record amplification (CVE-2026-3592), and TKEY GSS-API negotiation memory exhaustion (CVE-2026-3039). Mapped ATT&CK behaviours: T1068.004 (Memory Corruption), T1190 (Exploit Public-Facing Application).

> **SOC Action:** Identify recursive resolvers, DoH endpoints, and authoritative BIND deployments. Prioritise upgrade of any internet-facing DoH resolver to the patched BIND 9 build (track ISC advisory rev). For internal resolvers that cannot patch immediately, disable DoH (`http` listeners) and rate-limit recursion. Add IDS coverage for malformed EDNS option ordering and oversized authority sections; correlate spikes in recursion-failure metrics that could indicate the resend-loop DoS being abused.

### 3.3 Rsync < 3.4.3 — multiple critical and high pre-auth issues

**Source:** [Microsoft MSRC — CVE-2026-29518](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-29518), [CVE-2026-45232](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45232), [CVE-2026-43619](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-43619), [CVE-2026-43617](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-43617), [CVE-2026-43620](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-43620), [CVE-2026-43618](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-43618), [CVE-2026-41035](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-41035)

Rsync versions below 3.4.3 are affected by a cluster of newly disclosed flaws. Two are critical: a TOCTOU race condition enabling symlink-based arbitrary file write (CVE-2026-29518) and an off-by-one stack write via the HTTP proxy code path (CVE-2026-45232). High-severity issues include a symlink race via path-based syscalls (CVE-2026-43619) and an authorisation bypass via hostname resolution (CVE-2026-43617). Medium-severity items cover an out-of-bounds read in `recv_files()`, an integer-overflow information disclosure, and a use-after-free in `receive_xattr` when invoked with `-X` on Linux. ATT&CK: T1190, T1210, T1071.001, T1048.

> **SOC Action:** Inventory rsync versions across backup servers, CI runners, container base images, and storage gateways (`rsync --version`). Schedule emergency upgrade to 3.4.3+ on any host that accepts inbound rsync over SSH or daemon mode. Disable the daemon's HTTP-proxy support where unused. For backup workflows that must retain the `-X` flag, monitor for SIGSEGV and unexpected file overwrites under shared directories.

### 3.4 DNSSEC and DNSCrypt critical RCE pair (CVE-2026-33278 / CVE-2026-32792)

**Source:** [Microsoft MSRC — CVE-2026-33278](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-33278), [Microsoft MSRC — CVE-2026-32792](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-32792)

CVE-2026-33278 enables arbitrary code execution during DNSSEC validation through improper input handling; CVE-2026-32792 is a "packet of death" in DNSCrypt that yields unauthenticated RCE through malformed packets. Both directly affect DNS resolvers and middleboxes in the validation path. ATT&CK: T1071.001 (Application Layer Protocol: DNS), T1059.001 (Command and Scripting Interpreters), T1204.

> **SOC Action:** Confirm resolver inventory includes DNSSEC validators (Unbound, BIND, Knot Resolver) and DNSCrypt-proxy deployments. Patch as advisories land. In the interim, restrict DNS recursion to known client subnets and pin egress DNS to enforced upstreams. Add NIDS signatures for malformed DNSCrypt opcodes and oversized DNSSEC RRSIG/NSEC chains; alert on resolver process restarts and segfaults.

### 3.5 ShinyHunters extortion cluster — Charter Communications, Baker Distributing, DentaQuest

**Source:** [RansomLook — shinyhunters](https://www.ransomlook.io//group/shinyhunters)

ShinyHunters posted three new victim entries to its leak site within the 24-hour window: Charter Communications (US telecom), Baker Distributing (HVAC/refrigeration distribution), and DentaQuest (dental benefits). Pipeline correlation linked the three at 0.90–0.95 confidence on shared actor and RansomLook tooling. Group infrastructure shows mixed health: the primary `.onion` (`shinypogk4...`) is up at ~67% uptime over 30 days, secondary mirrors are intermittent. Mailbox `shinygroup@onionmail.com` and the published PGP key remain consistent with prior campaigns. Reported TTPs: T1566 (Phishing) followed by data theft / encryption and dual-channel (Tor + clearnet) extortion.

#### Indicators of Compromise

```
Tor: hxxp[:]//shinypogk4jjniry5qi7247tznop6mxdrdte2k6pdu5cyo43vdzmrwid[.]onion/
Tor: hxxp[:]//shnyhntww34phqoa6dcgnvps2yu7dlwzmy5lkvejwjdo6z7bmgshzayd[.]onion/
Tor: hxxp[:]//toolatedhs5dtr2pv6h5kdraneak5gs3sxrecqhoufc5e45edior7mqd[.]onion/
Clearnet: hxxps[:]//shinyhunte[.]rs/
File server: 91.215.85[.]22
Contact: shinygroup[@]onionmail[.]com
```

> **SOC Action:** Block the listed `.onion` addresses at proxy / Tor-egress controls and the clearnet host at the web filter. For telco, distribution, and healthcare operators, hunt mail logs for inbound messages with reply-to / return-path matching `onionmail.com` and any references to the PGP key fingerprint. Validate that DentaQuest, Charter, and Baker have not appeared in upstream credential dumps in the last 30 days; rotate any third-party shared credentials if so.

### 3.6 Inc Ransom claim — Mecanizados y Montajes Aeronáuticos (mymgroup.es)

**Source:** [RansomLook — inc ransom](https://www.ransomlook.io//group/inc%20ransom)

Inc Ransom added Mecanizados y Montajes Aeronáuticos (mymgroup.es) — a Spanish aerospace machining and assembly supplier — to its leak listing among multiple other victims posted in the same cycle. The group continues to operate dual Tor/clearnet payment infrastructure with intermittent uptime. No new TTPs were disclosed in this listing, but aerospace supply chains remain a high-value target where IP and ITAR-equivalent data exposure can cascade to OEM customers.

> **SOC Action:** Aerospace and defence supply-chain SOCs: confirm whether mymgroup.es is in your tier-1/2 supplier inventory; if so, escalate to procurement for a contractual breach-notification trigger. Hunt for unusual outbound transfers from supplier-shared VPN tunnels or extranets in the last 30 days. Flag any received CAD files, engineering drawings, or NCR documents originating from `mymgroup.es` domains for elevated scrutiny pending confirmation.

### 3.7 Nova (RALord rebrand) — sustained construction-sector targeting

**Source:** [RansomLook — nova](https://www.ransomlook.io//group/nova)

Nova, identified as a rebrand of RALord, posted three new victims (University of Valencia, AMACCAO, Hoy Construction) and continues to operate a RaaS-style affiliate model behind captcha gates with PGP-encrypted ransom notes. Average infrastructure uptime is ~11% over 30 days, indicating limited operational discipline but active recruitment. The cluster correlated at 0.95 confidence on shared actor and RALord malware lineage. ATT&CK behaviours: T1071 (Application Layer Protocol), T1048 (Exfiltration Over Alternative Protocol).

> **SOC Action:** Construction, engineering, and higher-education SOCs: increase scrutiny on RDP / VPN ingress from non-corporate ASNs over the next 14 days. Hunt for PGP binaries (`gpg.exe`, `gpg2.exe`) executing from non-standard user contexts and for ransom-note artifacts referencing "RALord" or "Nova". Validate that public-facing portals on `*.uv.es` peers and major contractors have MFA on all administrative paths.

### 3.8 Krybit lists Bangkok Metropolitan Administration (bangkok.go.th)

**Source:** [RansomLook — krybit](https://www.ransomlook.io//group/krybit)

Krybit's tracker surfaced `bangkok.go.th` among multiple entries this cycle. Attribution within the listing is hedged — the underlying actor is unidentified and Krybit aggregates indicators across overlapping campaigns (a separate listing for `lasevillanita.com` is speculatively linked to "0APT"). Treat the Bangkok listing as an unverified claim pending corroboration from Thai CERT (ThaiCERT) or the BMA itself.

> **SOC Action:** Government-sector SOCs operating in APAC: monitor ThaiCERT advisories for confirmation. If your organisation peers with `*.go.th` domains (international cooperation, smart-city projects, healthcare exchange), validate trust relationships and rotate any shared API tokens. Do not treat the Krybit listing as confirmed compromise without secondary attribution.

### 3.9 South African Revenue Service (SARS) — unverified breach claim by "nullsec"

**Source:** Telegram (channel name redacted)

A Telegram post attributed to a group calling itself "nullsec" claims a breach of the South African Revenue Service (SARS), with a referenced thread on breached.su. The data, scope, and authenticity of the claim are not corroborated in the source material. Treat as unverified pending official confirmation. Even if false, the claim itself can prompt phishing pretexts targeting South African taxpayers and accountants.

> **SOC Action:** SA-focused SOCs and managed-service providers: monitor for phishing campaigns referencing SARS, tax refunds, or eFiling credentials in the next 7–14 days. Tighten DMARC enforcement on inbound mail purporting to originate from `*.sars.gov.za`. Where customer data is held on behalf of SARS-affiliated entities, prepare a breach-response playbook even if the claim is unverified.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Continued exploitation of vulnerabilities in widely used software and systems | CISA KEV additions earlier in the week; CVE-2026-33117 Azure SDK for Java bypass (carried forward in batch 139) |
| 🟠 **HIGH** | Ransomware activity targeting multiple sectors with financial motives | ShinyHunters cluster (Charter, Baker, DentaQuest); Genesis healthcare/legal targeting |
| 🟠 **HIGH** | Ransomware double extortion across education, healthcare, manufacturing | Akira leak posts (Karlin Foods, Gitis, Function Enterprises, Buffalo Niagara Convention Center) |
| 🟠 **HIGH** | Phishing + application-layer protocol exploitation as common TTPs among RaaS groups | Coinbase Cartel posts (Cognizant, Siveco, Openmind, Pragmatic Solutions) |
| 🟠 **HIGH** | RaaS expansion by Qilin across multiple sectors | ROTO Immobilien, Snyder Packaging, Vernon & Ginsburg (carried from batch 138) |
| 🟡 **MEDIUM** | Phishing as a recurring TTP across diverse campaigns | Fake FIFA World Cup ticket / merchandise sites; ShinyHunters telco phishing |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **Qilin** (116 reports) — dominant RaaS operator over the last 30 days
- **Akira** (68 reports) — sustained double-extortion across mid-market verticals
- **The Gentlemen** (59 reports) — established defence-evasion focus, RaaS-style ops
- **TeamPCP** (35 reports) — continuing leak-site activity
- **ShinyHunters** (31 reports) — three new victims this cycle (Charter, Baker, DentaQuest)
- **Inc Ransom** (26 reports) — Spanish aerospace and other targets added today
- **Safepay** (19 reports) — steady cadence
- **Lockbit5** (19 reports) — successor brand activity continues
- **Everest** (18 reports) — slowing relative to mid-month peak
- **FulcrumSec** (17 reports) — leak-site activity tapering

### Malware Families

- **RansomLook** (142 reports) — leak-tracker tooling reference, dominant in source mix
- **Akira ransomware** (37 reports)
- **Tox1** (33 reports)
- **Other1** (22 reports)
- **Akira** (21 reports)
- **Tox** (18 reports)
- **Qilin** (15 reports)
- **Akira Ransomware** (14 reports)
- **The Gentlemen** (13 reports)
- **RaaS** (12 reports) — generic tagging for ransomware-as-a-service tradecraft

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| Microsoft | 31 | [MSRC](https://msrc.microsoft.com/update-guide) | Large BIND 9 / Rsync / DNSSEC / DNSCrypt / Qt patch wave |
| RansomLook | 12 | [ransomlook.io](https://www.ransomlook.io/) | ShinyHunters, Inc Ransom, Nova, Krybit, Genesis, Leaknet listings |
| Unknown (Telegram) | 3 | — | Apache.NMS.AMQP CVE, SARS / nullsec claim, "Elite Squad" dump |
| RecordedFutures | 1 | [therecord.media](https://therecord.media/cisa-to-allow-researchers-to-report-vulnerabilities-kev) | CISA opens KEV nominations to external researchers |
| Wired Security | 1 | [wired.com](https://www.wired.com/story/security-news-this-week-fbi-license-plate-reader-real-time-access/) | FBI seeks near-real-time ALPR access; Chromium PoC noted |
| SANS | 1 | [isc.sans.edu](https://isc.sans.edu/diary/rss/33008) | Stack-string obfuscation example in malware |
| BleepingComputer | 1 | [bleepingcomputer.com](https://www.bleepingcomputer.com/news/legal/italy-disrupts-cinemagoal-piracy-app-that-stole-streaming-auth-codes/) | Italy disrupts CINEMAGOAL streaming-credential piracy app |
| Schneier | 1 | [schneier.com](https://www.schneier.com/) | Friday squid post (informational) |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Inventory and isolate all .NET services using Apache.NMS.AMQP (CVE-2025-54539) — unauthenticated RCE with no clean fixed-version guidance yet. Restrict AMQP ingress to known producers at the firewall and hunt for unexpected child processes from message-bus consumers.
- 🔴 **IMMEDIATE:** Patch BIND 9 across recursive resolvers, DoH endpoints, and authoritative servers (CVE-2026-3593 critical + six high-severity DoS/cache-poisoning issues). Disable DoH on internal resolvers that cannot be upgraded today.
- 🟠 **SHORT-TERM:** Upgrade Rsync to 3.4.3+ on backup servers, CI runners, and container base images (CVE-2026-29518, CVE-2026-45232 critical; CVE-2026-43619, CVE-2026-43617 high). Disable rsync-over-HTTP-proxy where unused.
- 🟠 **SHORT-TERM:** Patch DNSSEC validators and DNSCrypt deployments (CVE-2026-33278 / CVE-2026-32792). Constrain resolver clientele and add IDS coverage for malformed DNSCrypt opcodes.
- 🟠 **SHORT-TERM:** Telco, healthcare, and aerospace SOCs: validate exposure to ShinyHunters and Inc Ransom victims (Charter, Baker, DentaQuest, mymgroup.es). Rotate any shared credentials and stand up a third-party-incident playbook for supplier-side breaches.
- 🟡 **AWARENESS:** Patch Qt Network OpenSSL backend (CVE-2025-14575 rogue-CA loading), haveged (CVE-2026-41054 root EoP), libyang heap overflow (CVE-2026-44673), Pallets Click command injection (CVE-2026-7246), and NGINX njs (CVE-2026-8711) on next maintenance window.
- 🟢 **STRATEGIC:** Update ransomware tabletop scenarios to reflect the RaaS brand-cycling pattern observed this month (Nova ← RALord; Lockbit5 successor activity). Subscribe to CISA's new community KEV nomination workflow and route SOC-discovered exploited bugs through it.

---

*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 51 reports processed across 2 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
