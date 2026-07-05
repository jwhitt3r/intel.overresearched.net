---
layout: post
title:  "CTI Daily Brief: 2026-07-04 — Genesis and Wallstreet ransomware disclose 13 victims across healthcare, tech, construction and law enforcement"
date:   2026-07-05 20:04:23 +0000
description: "Genesis ransomware disclosed nine victims in a single wave; Wallstreet crew hit a US hospital and police department; Payload leaked an Italian film studio. No CVEs or CISA KEV additions in the period."
category: daily
tags: [cti, daily-brief, genesis, wallstreet, ransomlook]
classification: TLP:CLEAR
reporting_period: "2026-07-04"
generated: "2026-07-05"
draft: true
report_count: 17
severity: high
sources:
  - RansomLook
  - BleepingComputer
  - Telegram (redacted)
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-07-04 (24h) | TLP:CLEAR | 2026-07-05 |

## 1. Executive Summary

Seventeen reports were processed across two correlation batches in the last 24 hours, with the threat landscape dominated by ransomware leak-site disclosures aggregated by RansomLook (14 of 17 reports). The **Genesis** ransomware group disclosed nine new victims in a single wave targeting healthcare, technology, construction, staffing and chemical-production organisations. The **Wallstreet** crew added four victims including Baraga County Memorial Hospital (a US critical-access hospital) and the Edgewood Police Department, using Tor onion infrastructure and Tox for negotiations. The **Payload** group leaked Italian film production company Vela Film S.r.l. Two Telegram proxy reports flagged infrastructure potentially supporting phishing anonymity. No CVEs, CISA KEV additions, or confirmed in-the-wild exploitation events were observed in the period.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 0 | None in period |
| 🟠 **HIGH** | 13 | Genesis (9) and Wallstreet (3) ransomware victim disclosures; Payload (1) |
| 🟡 **MEDIUM** | 2 | Telegram proxy infrastructure with phishing-related characteristics |
| 🟢 **LOW** | 0 | None in period |
| 🔵 **INFO** | 2 | Flipper Zero firmware update; Wallstreet observational post |

## 3. Priority Intelligence Items

### 3.1 Genesis ransomware group discloses nine victims in coordinated leak wave

**Source:** [RansomLook — Genesis leak site](https://www.ransomlook.io/group/genesis)

The Genesis ransomware group posted nine new victim disclosures to its RansomLook-tracked leak site on 2026-07-05, all timestamped within a 24-second window (16:53:18–16:53:26). Victims span multiple sectors: **SBI Software** (ERP software provider), **DICON** (general construction), **Bri-Tech, Inc** (technology design and integration), **Synergy Interactive** (staffing), **Apex Agro, LLC** (chemical production), **Mirage Endoscopy Center** (healthcare), **East Texas Family Medicine** (healthcare), **Dunagan Associates** (residential real estate/insurance), and **Westgate** (construction management). Genesis's own description states the group is financially motivated, extracts data for extortion rather than encrypts, and publishes files in a "parsed" folder on darkweb forums after non-payment. The group claims it will not attack the same company twice and destroys data post-payment. Correlation confidence linking these to a single actor is 0.95 (shared Genesis actor, RansomLook aggregator, TTPs T1566 Phishing and T1496 Resource Hijacking). Attribution is directly self-claimed on the leak site and should be treated as unconfirmed operationally until victim organisations verify.

#### Indicators of Compromise
```
Onion: hxxp[:]//genesis6ixpb5mcy4kudybtw5op2wqlrkocfogbnenz3c647ibqixiad[.]onion/
Contact: genesis.info@onionmail[.]org
```

MITRE ATT&CK: T1566 (Phishing) · T1071 (Application Layer Protocol) · T1496 (Resource Hijacking) · T1530 (Data from Local System)

> **SOC Action:** Check whether any listed victim is a supplier, partner, or customer. Query mail gateways for inbound/outbound traffic to `onionmail.org` addresses. Block outbound Tor traffic from corporate egress where not explicitly required, and alert on any DNS or SNI lookups matching the Genesis onion hash. Notify legal/comms teams so any downstream contractual notification obligations can be assessed.

### 3.2 Wallstreet ransomware targets US critical-access hospital and police department

**Source:** [RansomLook — Wallstreet leak site](https://www.ransomlook.io/group/wallstreet)

The Wallstreet ransomware operation added four victims to its leak site in the reporting window: **Baraga County Memorial Hospital** (a US critical-access hospital providing emergency, surgery, imaging, rehab and outpatient care), **Asisken** (a medical assistance/health insurance provider with hospital networks in Ecuador and Colombia), **Edgewood Police Department** (part of the Pierce County Sheriff's Department, Washington State, US), and **Gold Standard Automotive** (vehicle service contracts). Wallstreet uses a single active `.onion` leak URL and lists a Tox ID for negotiation, indicating a small but operational crew. Correlation batch 212 (confidence 0.70) links the healthcare victims to the same actor via shared TTPs (T1566 Phishing) and North America region. The healthcare and law-enforcement targeting is consistent with the sector-agnostic, high-impact victim selection typical of financially motivated crews and elevates public-safety risk.

#### Indicators of Compromise
```
Onion: hxxp[:]//4dwiv37h7hhuhjpvtn72hme4ylcv3qoe65arfc6mbweal7als6ma7pyd[.]onion/
Tox ID: 0C659C8A2EE2EFEA357B688B08D917AEB3323B8CF49922095CBDA6388A93E64290E09FFCD406
```

MITRE ATT&CK: T1566 (Phishing)

> **SOC Action:** For healthcare and public-sector partners, verify the integrity of shared credentials and mutual-aid access. Hunt Windows event logs for anomalous RDP sessions from unusual geographies over the past 30 days, and query EDR for uTox/qTox client processes (`qtox.exe`, `utox.exe`) or clipboard writes containing the Tox ID pattern (64+ hex characters). Ensure clinical/ICS network segmentation is enforced given the hospital targeting pattern.

### 3.3 Payload group leaks Italian film production studio Vela Film S.r.l.

**Source:** [RansomLook — Payload leak site](https://www.ransomlook.io/group/payload)

The Payload ransomware group disclosed **Vela Film S.r.l.**, an Italian production company based in Rome specialising in cinema and television (credits include *La porta rossa* and *Volevo fare la rockstar*). Payload maintains multi-onion infrastructure — one leak URL (currently down), one file server (up, 86% uptime), and one chat server (down) — suggesting infrastructure churn or degradation. Correlation batch 213 links Payload's use of RansomLook aggregator infrastructure to Genesis (confidence 0.90) via shared malware/aggregator, and to SBI Software via T1071 Application Layer Protocol (confidence 0.70). This is a media-sector data-extortion event; downstream risk includes unreleased production material and personal data of contributors.

#### Indicators of Compromise
```
Onion (leak): hxxp[:]//payloadrz5yw227brtbvdqpnlhq3rdcdekdnn3rgucbcdeawq2v6vuyd[.]onion
Onion (file server): hxxp[:]//payload6eualw6kni6v2lqn7ovjcl76ojx25z5unsyvqo3lbqy3bo5qd[.]onion/
Onion (chat): hxxp[:]//payloadynyvabjacbun4uwhmxc7yvdzorycslzmnleguxjn7glahsvqd[.]onion
Ransom note filenames: RECOVER_payload.txt, recover_payload.txt
```

MITRE ATT&CK: T1071 (Application Layer Protocol) · T1566 (Phishing)

> **SOC Action:** For media/creative-sector clients, alert on filesystem creation of `RECOVER_payload.txt` or `recover_payload.txt` across shared production drives. Block outbound connections to the listed onion hashes at proxy/SNI level. Verify that offline, immutable backups of active production assets exist and can be restored within recovery-time objectives.

### 3.4 Telegram proxy infrastructure flagged for phishing-adjacent characteristics

**Source:** Telegram (channel name redacted)

Two Telegram MTProto proxy configuration links were surfaced with TLP:AMBER+STRICT classification. Both point to third-party proxy servers with the secret parameter carrying an embedded destination hostname — one referencing `yekta.net` (an Iranian ISP-related domain) and one referencing a Yahoo lookalike. The pattern of embedding destination hostnames in MTProto secrets is used by proxy operators to route Telegram traffic through specific TLS-fronting endpoints, which can also be abused for phishing anonymity or geo-evasion. Correlation confidence 0.70 links these to the T1566 Phishing TTP. No specific threat actor was named. This is contextual infrastructure intelligence rather than a confirmed campaign indicator.

#### Indicators of Compromise
```
Proxy host: 87.248.129[.]49:443
Proxy host: lux.lavazemi1.co[.]uk:2096
Reference domains (embedded in secret): biscotti.yekta[.]net, www.yahoo[.]com (lookalike)
```

MITRE ATT&CK: T1566 (Phishing) · T1090 (Proxy — inferred from infrastructure type)

> **SOC Action:** Alert on Telegram desktop/mobile client traffic from corporate networks to the two listed IPs on ports 443 and 2096. Review DLP policy on personal messaging clients on managed endpoints. If MTProto proxy use is permitted, restrict to a vetted allow-list of corporate-approved proxies only.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🟠 **HIGH** | Genesis ransomware group targeting multiple sectors with RansomLook aggregator | DICON, Bri-Tech, Synergy Interactive (and six other Genesis victims) |
| 🟠 **HIGH** | Ransomware campaigns targeting healthcare and law enforcement in the United States using phishing techniques | Baraga County Memorial Hospital, Asisken, Edgewood Police Department |
| 🟡 **MEDIUM** | Telegram proxy infrastructure potentially facilitating malicious activities | Two Turbotelproxy channel-sourced MTProto proxy links |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **The Gentlemen** (95 reports) — most prolific actor tracked across the last 30 days; not present in today's data
- **Qilin** (73 reports) — ongoing ransomware activity, last seen 2026-07-03
- **Deadlock** (55 reports) — high early-period activity, no recent posts
- **Lockbit5** (39 reports) — LockBit successor branding; last seen 2026-06-18
- **Akira** (25 reports) — persistent ransomware operator; last seen 2026-07-01
- **DragonForce** (24 reports) — sustained activity through late June
- **Genesis** (9 mentions today) — dominant actor in today's landscape

### Malware Families

- **RansomLook** (149 reports) — aggregator/tracker referenced across all leak-site posts; not a malware family per se but tagged as such in the pipeline
- **Tox1** (72 reports) — Tox negotiation client references, used by Wallstreet and others
- **Anubis ransomware** (11 reports) and **Anubis banking trojan** (10 reports) — dual-purpose brand
- **Akira ransomware** (10 reports) — active operator
- **Deadlock** (10 reports) — early-period spike

Note: No CVEs appeared in the last 24 hours of reporting. Trending vulnerability entities in the pipeline are all older CVEs (CVE-2023 and mid-2026 batches) last seen 2026-06-15 to 2026-06-30, none active in today's collection.

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| RansomLook | 14 | [ransomlook.io](https://www.ransomlook.io) | Aggregator surfacing Genesis, Wallstreet and Payload leak-site posts |
| BleepingComputer | 1 | [bleepingcomputer.com](https://www.bleepingcomputer.com/news/security/flipper-zero-firmware-development-continues-with-community-help/) | Flipper Zero firmware development update (info) |
| Telegram (redacted) | 2 | — | MTProto proxy configuration links (TLP:AMBER+STRICT) |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Cross-reference the 13 Genesis and Wallstreet victim organisations against your supplier, partner and customer master lists. Where any match, initiate a supply-chain risk review and confirm that shared credentials, VPN tunnels, or federated identity trust relationships have not been leveraged (finding 3.1, 3.2).
- 🔴 **IMMEDIATE:** For healthcare clients, verify offline immutable backups and test restore procedures against the Wallstreet TTPs. Baraga County Memorial Hospital is a critical-access facility — expect similar critical-access hospitals to be next in the sequence (finding 3.2).
- 🟠 **SHORT-TERM:** Deploy detections for the three Payload onion hashes and the two `RECOVER_payload.txt` note filenames across media, creative and production endpoints (finding 3.3).
- 🟠 **SHORT-TERM:** Review egress firewall rules and Zero Trust policy for outbound Tor and MTProto proxy connections. Even where Tor use is permitted for research, ensure per-user attribution and DLP inspection where feasible (findings 3.1, 3.2, 3.4).
- 🟡 **AWARENESS:** Brief IR on-call on the Genesis modus operandi (data-extortion only, no encryption, "parsed" folder publication, `genesis.info@onionmail[.]org` contact). Because Genesis does not encrypt, its intrusions may be detected only via egress volume anomalies rather than the usual encryption tripwires (finding 3.1).
- 🟢 **STRATEGIC:** Track The Gentlemen and Qilin, which dominate the 30-day pipeline view but did not surface in today's data. Their next activity cycle should be modelled as a queued backlog rather than a decline (finding 5).

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 17 reports processed across 2 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
