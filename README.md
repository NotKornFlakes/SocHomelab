# SOC Lab: Azure Honeypots with Microsoft Sentinel

I exposed three honeypots to the internet in Microsoft Azure and fed everything into Microsoft Sentinel. In about 20 hours I recorded **27,473 attack attempts from 33 IPs in 15 countries**. I also captured a complete Linux intrusion chain and identified a live crypto-mining botnet payload. The lab cost about **$4.50 a day**.

**[View the interactive dashboard →](https://notkornflakes.github.io/SocHomelab/)**
· [Full write-up on Medium](<medium-article-link>)

> Data snapshot: Oct 3–4, 2026. Numbers below will be updated with the final collection window.

---

## Headline results

| Metric | Result |
| --- | --- |
| Time to first attack | About 1 hour after the VM went live |
| Total attempts | 27,473 (25,476 RDP · 1,997 SSH) |
| Unique source IPs / countries | 33 / 15 |
| Busiest single source | 22,510 RDP attempts (82% of all traffic), about 2,480 per hour |
| Malware captured | Panchan crypto-mining botnet (ELF x86-64, 45/65 AV detections) |
| Successful logins to real systems | **None**. Only my own key-based logins |
| Cost | About $4.50/day (two VMs, disk, IPs; Sentinel on free trial) |

## Architecture

```mermaid
flowchart LR
    I((Internet<br/>bots & scanners)) -->|RDP 3389| W[Windows 10 VM<br/>firewall off]
    I -->|SSH 22| C[Cowrie<br/>fake Linux shell]
    I -->|SSH 2222| E[Endlessh<br/>tarpit]
    subgraph U[Ubuntu VM]
      C
      E
    end
    W -->|Security events 4624/4625<br/>Azure Monitor Agent| L[(Log Analytics<br/>workspace)]
    C -->|JSON logs<br/>custom table Cowrie_CL| L
    E -->|Syslog| L
    L --> S[Microsoft Sentinel<br/>KQL · GeoIP watchlist · workbooks · analytics rules]
    A[Analyst] -.->|key-only SSH on a<br/>non-standard port,<br/>one source IP| U
```

| Sensor | Exposure | What it answers |
| --- | --- | --- |
| Windows 10 VM | RDP 3389, host firewall disabled | Who attacks, from where, guessing which usernames |
| Cowrie (medium interaction) | SSH 22 | What attackers do after they think they are in |
| Endlessh (tarpit) | SSH 2222 | How long automated tools will wait on a server that never finishes connecting |

**Safeguards:** real admin access ran key-only on a non-standard port, restricted by NSG to one IP. The two VMs sat in separate resource groups and virtual networks. Captured malware was never executed and never left the quarantine folder.

## Key findings

**1. RDP was brute-forced nonstop, and none of it succeeded.**
One Netherlands-registered IP made 22,510 attempts in about 9 hours, roughly 41 a minute. A Düsseldorf bot made 1,790 in 7 hours. Two sources resolved to Azure-owned ranges, so attackers are renting the same cloud they attack. Event 4624 showed only my own logins.

**2. The SSH intrusion chain was split across specialized bots.**

| Stage | What happened | Evidence |
| --- | --- | --- |
| Access | Dictionary guessing: `admin` with an empty password, `admin/admin`, `root` with `1` through `1234567890` | Cowrie login events |
| Probe | Three IPs from related network blocks took hourly shifts, logging in once a minute to check CPU, GPU and uptime, and ran an `echo "xxxxxx"` script to detect honeypots | Same file hash written 104 times |
| Fetch | A one-line dropper sent an `auth_ok` beacon, hid in `/tmp`, used its own SSH key to `scp` a script from a staging server (`wget`/`curl` as backup), then deleted its tracks | Full session replay |
| Deliver | A 30 MB binary disguised as `sshd` was launched with `nohup` in a hidden folder against about 50 target IPs | Binary quarantined and identified as **Panchan** by hash |

A second fleet of four IPs in one /24 block made **exactly 500 SSH attempts each** in roughly 45-minute shifts. That looks like a per-IP quota built to avoid rate limits. **Lesson: block behavior and tool fingerprints, not individual IPs.**

**3. The tarpit showed modern scanners fail fast.**
Most bots gave up after 20–40 seconds (2–4 junk lines). The longest one stayed trapped for 17 minutes. The "stuck for days" tarpit stories mostly apply to older tooling.

## MITRE ATT&CK mapping

| Tactic | Technique | Evidence |
| --- | --- | --- |
| Reconnaissance | T1595.001 Scanning IP Blocks | Sub-second port probes; Nmap/ZGrab banners |
| Credential Access | T1110.001 Password Guessing | 22,510 RDP failures from one IP; sequential SSH lists |
| Initial Access | T1078.001 Default Accounts | `admin` with an empty password, `test2/test2` |
| Execution | T1059.004 Unix Shell | One-line bash droppers |
| Discovery | T1082 System Information Discovery | `uname -a`, CPU/GPU checks |
| Defense Evasion | T1497.001 Sandbox Evasion: System Checks | `echo "xxxxxx"` honeypot test |
| Command and Control | T1105 Ingress Tool Transfer | `scp` from the staging server; SFTP upload of `sshd` |
| Defense Evasion | T1036.005 Masquerading | Malware named `sshd` |
| Defense Evasion | T1564.001 Hidden Files and Directories | Dot-folder in `/tmp` |
| Defense Evasion | T1070.004 File Deletion | `rm -rf sshcfg key.ppk out_sh` |
| Impact | T1496 Resource Hijacking | Panchan crypto miner |

## Indicators of compromise (defanged)

| Type | Indicator | Context |
| --- | --- | --- |
| SHA-256 | `94f2e4d8d4436874785cd14e6e6d403507b8750852f7f2040352069a75da4c00` | Panchan miner disguised as `sshd` |
| SHA-256 | `af77b643964afd794460d28ab8a11b0ec8790cd5463abfde126613a4f3bccd32` | Honeypot-detection script used by the probe fleet |
| URL | `hxxps://217.60.102[.]5/sh` | Second-stage payload (staging server) |
| SSH key fingerprint | `SHA256:O/at8341SoPpKvTPvMsJSgjQm30md9VTS2it25sY0vg` | The dropper's key for its staging server |
| IPv4 | `177.74.153[.]10`, `130.12.180[.]51` | Payload delivery and dropper |
| IPv4 | `80.94.92[.]234`, `80.94.92[.]55`, `92.118.39[.]49` | Probe fleet sharing one tool hash |

Many attacking IPs are likely compromised third-party devices, so treat IP indicators as low-to-medium confidence. Hashes and the staging host are high confidence.

## Detections built

| Rule | Logic | Severity |
| --- | --- | --- |
| [RDP brute force](queries/detections/rdp-bruteforce.kql) | 10+ failed logons from one IP in 5 minutes | Medium |
| [Brute force then success](queries/detections/bruteforce-then-success.kql) | A successful logon from an IP with 10+ failures in the past hour | High |
| [Linux dropper pattern](queries/detections/linux-dropper-pattern.kql) | Download tool + world-writable path + execute in one command | High |

The thresholds are tuned so the observed bots trigger them but a user who mistypes a password does not. Every false positive costs paid analyst time.

## Cost: defender vs attacker

| | Cost |
| --- | --- |
| This lab | ~$4.50/day |
| Renting a generic botnet | ~$5/day ([Trend Micro via The Register](https://www.theregister.com/2020/05/27/criminal_services_cheaper/)) |
| The hijacked devices doing the attacking | $0 to the operator |
| Average US data breach, 2025 | $10.22M ([IBM via Bluefin](https://www.bluefin.com/bluefin-news/ibms-2025-data-breach-report-key-findings-and-the-years-biggest-attacks/)) |

Attacks cost attackers almost nothing. Defenders pay in people and hours, and losing costs millions. The controls that stopped every attempt here were cheap: key-only SSH, no public management ports, and logging with tuned alerts.

## Repository layout

```
SocHomelab/
├── index.html                  Interactive dashboard (static snapshot, no live Azure connection)
├── README.md
└── queries/
    ├── 01-rdp-failed-logins-geo.kql
    ├── 02-successful-logins-check.kql
    ├── 03-rdp-top-usernames.kql
    ├── 04-attackers-both-vms.kql     Summary export used by the dashboard
    ├── 05-hourly-timeline.kql        Timeline export used by the dashboard
    ├── 06-cowrie-credentials.kql
    ├── 07-cowrie-commands.kql
    ├── 08-cowrie-file-captures.kql
    ├── 09-cowrie-session-time.kql
    ├── 10-endlessh-tarpit.kql
    ├── 11-sensor-health.kql
    └── detections/
        ├── rdp-bruteforce.kql
        ├── bruteforce-then-success.kql
        └── linux-dropper-pattern.kql
```

Replace `<your-home-ip>` in the queries with your own IP so your logins are excluded. The GeoIP queries need a Sentinel watchlist with alias `geoip` and SearchKey `network`.

## Skills demonstrated

Azure networking and NSGs · Log Analytics and data collection rules · Microsoft Sentinel (KQL, watchlists, workbooks, analytics rules) · honeypot deployment (Cowrie, Endlessh) · threat hunting and session-replay analysis · safe malware triage by hash · MITRE ATT&CK mapping · IOC handling and defanging · detection engineering · cost and risk communication · data visualization (D3).

## Limitations

This is a short collection window of opportunistic, automated attacks, not targeted ones. GeoIP shows where an IP is registered, not where an operator is. Cowrie is detectable, so some bots aborted early. Malware was identified by hash only, with no dynamic analysis, by design.

## Credits

The lab is based on [Josh Madakor's SOC lab](https://github.com/joshmadakor1/Cyber-Course), extended with Cowrie, Endlessh, cross-sensor KQL, detections and a custom dashboard. The Panchan identification is corroborated by [E. Thomason](https://ethomason.com/posts/panchan-sshd-miner/) and [KlavanSec](https://klavansec.substack.com/p/i-left-a-server-exposed-to-the-internet).
