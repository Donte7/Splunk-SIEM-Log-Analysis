# Splunk SIEM & Log Analysis

![Splunk](https://img.shields.io/badge/Splunk-Enterprise-black?style=flat-square&logo=splunk&logoColor=white)
![Azure](https://img.shields.io/badge/Azure-VM-0078D4?style=flat-square&logo=microsoftazure&logoColor=white)
![Windows Server](https://img.shields.io/badge/Windows_Server-2022-0078D4?style=flat-square&logo=windows&logoColor=white)
![Status](https://img.shields.io/badge/Status-Completed-brightgreen?style=flat-square)

> Deploying a SIEM, ingesting Windows Security event logs, writing SPL detection queries, building a security dashboard, and configuring automated alerting — all in a free Azure home lab environment.

---

## Objective

A medium-sized organisation generates millions of log events daily across workstations, servers, firewalls, and cloud resources. Without a SIEM, security teams cannot search across those systems, correlate events, or detect attack patterns in real time.

This lab demonstrates how to deploy Splunk Enterprise as a SIEM, collect Windows Security event logs from an Active Directory server, write SPL queries to identify suspicious activity, and build detection capabilities that mirror what a SOC analyst uses in production environments.

---

## Certification Alignment

| Certification | Relevant domains covered |
|---|---|
| CompTIA Security+ | Security monitoring, log analysis, incident response concepts |
| CompTIA CySA+ | Threat detection, SIEM operation, behavioral analytics |
| Splunk Core Certified User | SPL, indexing, dashboards, alerts, data inputs |

---

## Environment

| Component | Details |
|---|---|
| SIEM platform | Splunk Enterprise (free licence — 500 MB/day) |
| Splunk host | Azure VM — Ubuntu 22.04 LTS (Standard_B2s, 2 vCPU / 4 GB RAM) |
| Log source | Azure VM — Windows Server 2022 (Active Directory from Lab 01) |
| Log forwarder | Splunk Universal Forwarder (installed on Windows VM) |
| Network | Both VMs in the same Azure VNet — forwarder sends to port 9997 |
| Cost | $0 — Splunk free licence + Azure free tier eligible VM sizes |

---

## Architecture

```
┌─────────────────────────┐          ┌──────────────────────────────┐
│  Windows Server 2022    │          │  Ubuntu 22.04 (Splunk)       │
│  (Active Directory VM)  │          │                              │
│                         │  :9997   │  ┌────────────────────────┐  │
│  Splunk Universal  ─────┼──────────┼─▶│  Splunk Indexer        │  │
│  Forwarder              │  TCP     │  │  index: windows_logs   │  │
│                         │          │  └───────────┬────────────┘  │
│  Event Logs collected:  │          │              │               │
│  • Security (4624/4625) │          │  ┌───────────▼────────────┐  │
│  • System (7036)        │          │  │  Splunk Web UI :8000   │  │
│  • Application          │          │  │  Search · Dashboards   │  │
│                         │          │  │  Alerts · Reports      │  │
└─────────────────────────┘          │  └────────────────────────┘  │
                                     └──────────────────────────────┘
```

---

## Steps Completed

### 1. Deployed Splunk Enterprise on Azure
- Provisioned an Ubuntu 22.04 VM (Standard_B2s) in Azure
- Downloaded and installed Splunk Enterprise via `dpkg`
- Enabled Splunk as a system service (`boot-start`) so it persists across reboots
- Opened NSG inbound rules for port 8000 (web UI) and port 9997 (forwarder input)
- Set the public IP to Static to avoid address changes between sessions

### 2. Configured data inputs
- Enabled a receiving port on 9997 inside Splunk (Settings → Forwarding and Receiving)
- Created a dedicated index named `windows_logs`
- Installed Splunk Universal Forwarder on the Windows Server VM
- Created `inputs.conf` at `C:\Program Files\SplunkUniversalForwarder\etc\system\local\` to collect Security, System, and Application event logs
- Restarted the forwarder service to apply configuration

### 3. Generated test log data
- Ran a PowerShell script as Administrator to simulate realistic security events:
  - 15 failed logon attempts (EventCode 4625)
  - 1 successful logon (EventCode 4624)
  - Service start/stop cycles (EventCode 7036)
  - Account lockout trigger (EventCode 4740)
  - Application log warnings (EventCode 1001)
- Verified data arrival in Splunk with: `index=windows_logs | head 100`

### 4. Wrote SPL detection queries
Searched for authentication patterns and suspicious activity — see [queries/splunk-searches.spl](queries/splunk-searches.spl) for all queries with inline comments.

### 5. Built a security dashboard
Created a **Windows Security Overview** dashboard with four panels:
- Account activity (last 24h) — bar chart of logins by account
- Top processes (last 24h) — event list of process creation activity
- Login activity over time — line chart showing authentication volume
- After-hours logins — table of logins outside 07:00–19:00

### 6. Configured an automated alert
- Alert name: *High Privileged Logon Count*
- Searches for EventCode 4672 (privileged logon) on a 15-minute schedule
- Triggers when any account exceeds 50 privileged logon events
- Logs to Splunk's built-in triggered alerts (Activity → Triggered Alerts)

---

## SPL Queries

All queries are saved in [`queries/splunk-searches.spl`](queries/splunk-searches.spl). Key searches:

```spl
-- Confirm data is flowing
index=windows_logs | head 100

-- Successful logins by account
index=windows_logs sourcetype=WinEventLog:Security EventCode=4624
| stats count by Account_Name
| sort -count

-- After-hours login detection
index=windows_logs sourcetype=WinEventLog:Security EventCode=4624
| eval hour=strftime(_time, "%H")
| where hour < 7 OR hour > 19
| table _time, Account_Name, Account_Domain, ComputerName
| sort -_time

-- Privileged logon alert threshold
index=windows_logs sourcetype=WinEventLog:Security EventCode=4672
| stats count as privilege_logons by Account_Name, ComputerName
| where privilege_logons > 50
```

---

## Key Windows Event IDs Referenced

| Event ID | Description | Security relevance |
|---|---|---|
| 4624 | Successful logon | Baseline authentication tracking |
| 4625 | Failed logon | Brute force / credential spray detection |
| 4672 | Special privileges assigned at logon | Privileged access monitoring |
| 4688 | New process created | Malware execution, threat hunting |
| 4697 | Service installed | Persistence mechanism detection |
| 4740 | Account locked out | Password spray attack indicator |
| 7036 | Service started or stopped | Service manipulation detection |

---

## Screenshots

> Add your screenshots to the `assets/` folder and update the paths below.

| Windows Security Overview dashboard | Alert configuration |
|---|---|
| ![Dashboard](assets/dashboard.png) | ![Alert](assets/alert.png) |

| SPL search results — EventCode 4624 | Forwarder receiving port config |
|---|---|
| ![Search results](assets/spl-results.png) | ![Receiving port](assets/receiving-port.png) |

---

## Files in This Lab

```
lab-03-splunk-siem/
├── README.md                     ← this file
├── assets/                       ← screenshots
│   ├── dashboard.png
│   ├── alert.png
│   ├── spl-results.png
│   └── receiving-port.png
├── queries/
│   └── splunk-searches.spl       ← all SPL queries with comments
├── configs/
│   └── inputs.conf               ← Universal Forwarder config
└── scripts/
    └── log-generator.ps1         ← PowerShell test data generator
```

---

## Lessons Learned

- **NSG rules are the most common failure point** — port 8000 and 9997 must both be explicitly opened. The connection timeout error looks identical whether Splunk is down or the port is blocked; always check NSG first.
- **VNet Peering is required if VMs are in separate VNets** — even with correct NSG rules, cross-VNet traffic is blocked by default. Best practice is to put all lab VMs in one shared VNet from the start.
- **`inputs.conf` requires an explicit `index =` line** — without it, events go to the default `main` index and appear missing from `windows_logs` searches.
- **Static public IPs save time** — Azure reassigns public IPs on VM restart by default. Setting the assignment to Static means browser bookmarks and NSG rules never need updating.
- **Alert thresholds need tuning** — the 50-event threshold for EventCode 4672 generates false positives on a fresh VM where system accounts fire frequently. In a production environment this would be baselined over 7–14 days before going live.

---

## Career Relevance

| Role | How this lab applies |
|---|---|
| SOC Analyst Tier 1 | Monitoring dashboards, searching logs, identifying failed auth patterns |
| SOC Analyst Tier 2–3 | Building detection rules, correlating events, threat hunting with SPL |
| Cloud Security Engineer | Same SIEM concepts underpin Microsoft Sentinel and AWS Security Hub |
| Incident Responder | Log timeline reconstruction, scope-of-compromise analysis |

---

## Related Labs

- [Lab 01 — Active Directory & Identity Management](../lab-01-active-directory/)
- [Lab 02 — coming soon]

---

*Part of the [Security Home Lab SOP series](../../README.md)*
