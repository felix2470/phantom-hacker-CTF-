## Phantom-Hacker-CTF
![Image](https://github.com/user-attachments/assets/2d7f2606-d294-4023-b01e-2d4339aa0c8b)

## Scenario Summary

Acme Corp’s top administrator, **Bubba Rockerfeatherman III**, is unknowingly the gatekeeper of trillions in digital assets stored inside heavily encrypted internal vaults. His privileged account is the sole key to this empire.
A stealthy APT group, known as **The Phantom Hackers,** has launched a **multi-stage attack** targeting Bubba’s credentials and gaining persistent access to Acme’s infrastructure. This includes:
- **Social engineering (phishing)**
- **Credential harvesting**
- **Fileless malware and in-memory abuse**
- **Registry and scheduled task–based persistence**

You’ve been assigned to stop the breach in progress and **hunt down evidence of the intrusion chain**, using telemetry from **Microsoft Defender for Endpoint**, with a known compromised device:

- **Compromised Host:** `anthony-001`
- **Privileged Account Targeted:** `bubba.rockerfeatherman`
- ![Image](https://github.com/user-attachments/assets/62a4cdc7-d245-44ed-b671-0de373957db5)

- ## Introduction

- **Hunt Title / Case ID:** *The Great Admin Heist*
- **Date Range Investigated:** 07/05/2025 (30-day back review)
- **Analyst:** *Mohammed A*
- **Environment:** Microsoft Azure Threat-Hunting Lab
- **Platforms Used:** Microsoft Defender for Endpoint (MDE), Microsoft Sentinel
- **Query Language:** Kusto Query Language (KQL)
- **Frameworks Applied:** PEAK, MITRE ATT&CK

## Mission & Hypothesis

> Mission:
> 
> 
> Track and expose the actions of The Phantom Hackers inside Acme’s environment by analyzing telemetry from `anthony-001`. Identify the entry point, credentials abuse,
>  persistence mechanisms, and potential data staging or exfiltration activity.
> 

> Hypothesis:
> 
> 
> The attacker phished or socially engineered Bubba, gained credential access, and executed stealthy persistence on `anthony-001` using native system binary abuse living of the land LOBIN abuse,
>  registry edits, and task scheduler abuse. 
> 
> We expect to find:
> 
- Possible PowerShell, Lolin Abuse, if phishing is involved.
- `New-LocalUser`, `reg add`, `schtasks` activity
- Suspicious access to protected files and possible exfil.
- Outbound network activity not tied to business ops

# Phase 1 – Initial Access

**PEAK Step:** Prepare → Enrich

**MITRE Tactic:** Initial Access (TA0001)

**Technique:** T1110.001 – Brute Force: Password Guessing

---

## What We Investigated

We began by reviewing the login activity on host `anthony-001` for May 7, 2025, to identify any unusual access patterns, brute-force attempts, or logins from suspicious IP addresses. 
The threat scenario mentioned phishing, but we wanted to **verify if access occurred**, how it happened, and whether **initial brute-force or credential abuse was successful**.

```KQL
   
//KQL Query Used
    DeviceLogonEvents
    | where DeviceName == "anthony-001"
    | where Timestamp > ago(30d)
    | project Timestamp, AccountName, ActionType, LogonType, RemoteIP
    | order by Timestamp desc
```
![image](https://github.com/user-attachments/assets/02588398-474f-4221-b0dd-067bb88d3ef4)
![image](https://github.com/user-attachments/assets/739ee7ab-117c-475f-895a-be14a9e3f73e)

### What We Found

- Multiple **failed login attempts** were recorded from IPs including:
    - `102.88.21.216`
    - `193.37.69.105`
    - `80.94.95.203`
- Targeted usernames included: `administrator`, `admin`, `test`, `anthony-001`
- **No immediate success was recorded** from those brute-force attempts
- **This shows scanning/reconnaissance behaviour,** likely automated

However, shortly after the brute-force window ended, we noticed the following:

- A **successful logon** occurred from IP `49.147.196.23`
- **Account used:** `4nth0ny!` (privileged)
- **Logon Type:** RemoteInteractive (RDP)
- This login triggered interactive sessions and process activity from the same user.

```kql
  //kql used 
   DeviceLogonEvents
  | where DeviceName == "anthony-001"
  | where Timestamp between (datetime(2025-05-07 00:59:00) .. datetime(2025-05-07 09:00:00))
  | where LogonType == "Network" or LogonType == "RemoteInteractive"
  | where ActionType == "LogonSuccess"
  | project Timestamp, AccountName, LogonType, RemoteIP, InitiatingProcessFileName
  | order by Timestamp asc
```
![image](https://github.com/user-attachments/assets/1979eaf3-5c16-42ea-bc1c-b8f618aa374b)

### MITRE Technique Mapping

- **Tactic:** Initial Access (TA0001)
- **Technique:** T1110.001 – Brute Force: Password Guessing - no success.
- **Technique (follow-up):** T1078 – Valid Accounts (confirmed in next stage)

---

### Pivot to Next Phase - Execution & Suspicious Process Discovery

---

With the RDP logon by `4nth0ny!` Confirmed, and no signs of brute force success leading up to it, we consider this a **valid account compromise and successful initial access**.

At this point in the investigation, we shift into **“Analyse” -** we want to determine **what the attacker did after gaining a foothold.**

---

### Thought Process

We don't yet know how the attacker executed their next stage - but based on the threat scenario (phishing-based), we expect they may have abused **common built-in tools** like:

- `powershell.exe`
- `cmd.exe`
- `rundll32.exe`
- or other signed Windows binaries (LOLBins)

This aligns with common attacker tradecraft observed in MITRE techniques like:

- **T1059.001** – PowerShell
- **T1059.003** – Windows Command Shell
- **T1218** – Signed Binary Proxy Execution (LOLBins)

---

### Next Investigation Step

We will query all **process activity launched by `4nth0ny!`**, and specifically filter for those known to be abused by attackers.

We're not currently looking for a specific payload. We're looking for any behaviour that re**sembles execution** following an RDP login.

# Phase 2 – Execution & Post-Access Behaviour

**PEAK Step:** Analyse

**MITRE Tactics:**

- Execution (TA0002)
- Persistence (TA0003)

**Techniques We Expect to Validate:**

- T1059.001 – PowerShell
- T1059.003 – Windows Command Shell
- T1053.005 – Scheduled Task Creation
- T1547.001 – Registry Run Keys

---

### What We Investigated

Now that we confirmed the attacker logged into `anthony-001` using the `4nth0ny!` Account, our goal was to determine **what was executed next**. We began by reviewing **all process executions** tied to `4nth0ny!,`

Starting with common attack tools such as:

- `powershell.exe`
- `cmd.exe`
- `rundll32.exe`
- `cscript.exe`
- `wscript.exe`
- Any other signed Windows tools that could be used for stealth execution (LOLbins)

```kql
//KQL Used

  DeviceProcessEvents
| where DeviceName == "anthony-001"
| where InitiatingProcessAccountName =~ "4nth0ny!"
| where FileName in~ ("powershell.exe", "cmd.exe", "rundll32.exe", "wscript.exe", "cscript.exe", "certutil.exe", "regsvr32.exe")
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName, FolderPath
| order by Timestamp asc
```
![image](https://github.com/user-attachments/assets/d4778fb4-1c0c-4a70-8a79-c6b48e976c02)

### What We Found

- Multiple instances of `powershell.exe` and `cmd.exe` were executed shortly after the RDP login.
- The processes were **initiated by user session binaries,** such as `explorer.exe` and `runtimebroker.exe`, suggesting user-level interaction.
- One of the PowerShell instances **compiled and dropped an executable named `BitSentinelCore.exe`** into `C:\ProgramData\`
```kql
//kql used
DeviceFileEvents
| where DeviceName == "anthony-001"
| where FileName =~ "BitSentinelCore.exe"
| project Timestamp, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine


DeviceProcessEvents
| where DeviceName == "anthony-001"
| where FileName =~ "BitSentinelCore.exe"
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessAccountName, FolderPath
| order by Timestamp asc
```
![image](https://github.com/user-attachments/assets/870e37b9-4494-46cb-983a-1817fc629dc3)
## Key Details
| Time (UTC) | Process | Details |
| --- | --- | --- |
| 01:24:04 | `powershell.exe` | Initiated from `explorer.exe` session |
| 02:02:14 | `cmd.exe` | Spawned by `powershell.exe` |
| 02:02:14 | `BitSentinelCore.exe` | Created on disk in `C:\ProgramData\` |
| 02:03:16 | `cmd.exe` → `schtasks.exe` | Created scheduled task for persistence |

### Execute Binary Payload Details In MDE

We successfully identified the malicious binary in MDE, extracting crucial details that will assist in our investigation.
![image](https://github.com/user-attachments/assets/b64c57f2-05f2-4e93-be05-4da4aa51cb51)
![image](https://github.com/user-attachments/assets/e434dea0-6593-432d-943f-3e86b56d463a)
![image](https://github.com/user-attachments/assets/9e9fddd0-3598-419e-8a2e-746cd9d12c44)
![image](https://github.com/user-attachments/assets/eb0f580a-fa8c-4cc3-a0f6-b6ff3a9d659c)
![image](https://github.com/user-attachments/assets/003cd4cb-cf78-4b23-929a-4dfc24351725)

### Observations

- PowerShell, followed by command line execution and binary drop, matches post-access execution behaviour.
- The binary appears to have been compiled on the endpoint, but we don't know how at this point in the investigation.
- The naming (`BitSentinelCore.exe`) raised suspicion as it mimics security software.
- Initial analysis shows `BitSentinelCore.exe` is an unsigned, lightweight binary that writes suspicious files and modifies a `Run` registry key for persistence.
  It also injects into `cmd.exe`, suggesting stealthy execution.
- The attacker did not attempt privilege escalation. They remained within `4nth0ny!`’s context.
### MITRE Technique Mapping (Confirmed from Execution Phase)

| Tactic | Technique ID | Description |
| --- | --- | --- |
| Execution | T1059.001 | PowerShell Execution |
| Execution | T1059.003 | Command Shell |
| Execution | T1204.002 | User Execution (based on later findings) |

### Pivot to Next Phase – Persistence Investigation

---

Our next step is to determine **how the attacker ensured continued access**. Since `BitSentinelCore.exe` was dropped, we now investigate:

- **Registry modifications** (e.g., `Run` key)
- **Scheduled tasks**
- Any evidence of **file staging**, credential harvesting, or telemetry deception

We will validate this behaviour using:

- Registry event logs
- Task scheduler creation events
- Further file I/O analysis from the malware

  # Phase 3 – Execution and Malware Delivery

**PEAK Step:** Analyse → Trace

**MITRE Tactics:**

- Execution (TA0002)
- Defence Evasion (TA0005)
- Initial Delivery (TA0001, revisited)

---

### What We Investigated

After confirming `4nth0ny!` Logged in and a suspicious execution occurred, we needed to determine:

- **How was the malware (`BitSentinelCore.exe`) delivered or created?**
- **Which process initiated its presence on disk?**
- **Was it downloaded, compiled, or dropped by another executable?**

We pivoted to `DeviceFileEvents` to check what created the `BitSentinelCore.exe` binary.
```kql
//kql used
DeviceFileEvents
| where DeviceName == "anthony-001"
| where FileName =~ "BitSentinelCore.exe"
| project Timestamp, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine

```
![image](https://github.com/user-attachments/assets/f26f8b08-395d-4c3a-8bc5-157ecb9d59ba)

### What We Found

- **File Created:** `BitSentinelCore.exe`
- **Timestamp:** May 7, 2025, 02:00:36 AM UTC
- **Location:** `C:\ProgramData\BitSentinelCore.exe`
- **Initiated By:** `csc.exe` (C# Compiler)
- **Command Line Used:**
```
"csc.exe" /noconfig /fullpaths @"C:\Users\4nth0ny!\AppData\Local\Temp\c5gy0jzg\c5gy0jzg.cmdline"
```
### Interpretation

- This confirms that the attacker **compiled the binary on the victim’s machine using the native .NET compiler** `csc.exe`.
- The `.cmdline` file suggests the source was stored temporarily under the user's local temp directory, a common technique for avoiding detection and **bypassing file upload restrictions**.
- No download or dropper was needed; this was **fileless delivery until the moment of compilation**.

  ### MITRE Technique Mapping

---

| Tactic | Technique ID | Description |
| --- | --- | --- |
| Execution | T1059.001 | PowerShell or scripting execution (csc.exe is a compiler script execution) |
| Defense Evasion | T1127 | Compiled HTML Application or `.NET` Binary compiled at runtime |
| Defense Evasion | T1218.005 | csc.exe as a Living Off the Land Binary (LOLBIN) |












  
  

