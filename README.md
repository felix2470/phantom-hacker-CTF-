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
- **Analyst:** *Felix*
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


# Phase 4 – Malware Execution and Persistence Setup

**PEAK Step:** Act → Confirm

**MITRE Tactics:**

- Execution (TA0002)
- Persistence (TA0003)
- Defence Evasion (TA0005)

---

### What We Investigated

After verifying that `BitSentinelCore.exe` was compiled to disk, our next step was to determine:

1. **Was it executed?**
2. **Did it immediately persist across reboots and logins?**
3. **Did we find evidence of registry or scheduled task abuse?**

This would help us validate the presence, intent, and mechanism used by the attacker to maintain access.

---

### What We Found

We traced the binary launch using process telemetry:

- **Timestamp:** May 7, 2025, 02:02:14 AM UTC
- **Initiating Process:** `explorer.exe`
- **Target Executable:** `BitSentinelCore.exe`
- This suggests that the **user (Bubba/4nth0ny!) manually double-clicked the executable**.

This is consistent with **phishing + user execution (T1204.002)**, a classic delivery strategy in social engineering attacks.

```
//kql used
DeviceProcessEvents
| where DeviceName == "anthony-001"
| where FileName =~ "BitSentinelCore.exe"
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessAccountName, FolderPath
| order by Timestamp asc
```
![image](https://github.com/user-attachments/assets/8b0cf2fc-73fc-4faa-8f3e-f277edb200a0)
### Interpretation

- This was **user-triggered malware**, not stealthy auto-loading via Windows internals, possibly due to a **phishing link** or a deceptive antivirus installer ("BitSentinelCore.exe").
- The attacker relied on the user’s action to launch the malware.

---

### Registry Persistence

- Upon execution, the malware created a registry key under the Run location:
```
HKEY_CURRENT_USER\S-1-5-21-2009930472-1356288797-1940124928-500\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
```

- **Key Name:** `BitSecSvc`
- **Value:** `"C:\ProgramData\BitSentinelCore.exe"`
- **Process Creating Key:** `BitSentinelCore.exe`

The name `BitSecSvc` mimics legitimate Windows services, such as `Security Centre`, designed to evade detection through **naming impersonation**.

---

### Scheduled Task Persistence

- **Malware:** `BitSentinelCore.exe` (unsigned, fake AV)
- **Execution Chain:** `BitSentinelCore.exe` → `cmd.exe` → `schtasks.exe`
- **Persistence:** Creates a daily task named `UpdateHealthTelemetry`
- **Task Action:** Runs `C:\ProgramData\BitSentinelCore.exe` at 14:00
- **Evasion:** Task name mimics legitimate Windows telemetry
- Within seconds of execution, we observed the creation of a **Daily Scheduled Task**:
```
schtasks /Create /SC DAILY /TN "UpdateHealthTelemetry" /TR "C:\ProgramData\BitSentinelCore.exe" /ST 14:00
```
## KQL – Registry and Task Abuse
```
DeviceRegistryEvents
| where DeviceName == "anthony-001"
| where RegistryKey has_any (
    @"\Software\Microsoft\Windows\CurrentVersion\Run",
    @"\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    @"\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    @"\System\CurrentControlSet\Services"
)
| project Timestamp, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
```
![image](https://github.com/user-attachments/assets/0dd96bfe-4f80-42bf-960e-95a493854894)
```
DeviceRegistryEvents
| where DeviceName == "anthony-001"
| where RegistryKey matches regex @"\\(Run|RunOnce|Explorer\\Run|Services)$"
| project Timestamp, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
```
![image](https://github.com/user-attachments/assets/acd12cb3-63c8-4b0b-bf85-092f9f499feb)

### **Execution Flow Details:**

| Step | Process | Details |
| --- | --- | --- |
| 1 | `BitSentinelCore.exe` | Dropped malware binary located at `C:\ProgramData\BitSentinelCore.exe`. Executed under `4nth0ny!`’s session. |
| 2 | `cmd.exe` | Spawned by the malware with the `/c` flag to execute a scheduled task silently. |
| 3 | `schtasks.exe` | Launched by `cmd.exe` to create a **daily task** named `UpdateHealthTelemetry`, pointing to the malware binary. |

![image](https://github.com/user-attachments/assets/d3c13f6f-fed8-4650-b2d2-f17f79fb7fb4)
![image](https://github.com/user-attachments/assets/c3c98fb6-f9f2-488a-95d1-b92abe8882b9)
```
DeviceProcessEvents
| where DeviceName == "anthony-001"
| where FileName in~ ("schtasks.exe", "cmd.exe")
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
```
![image](https://github.com/user-attachments/assets/66187040-d31f-4e31-9bf9-f8391d07693f)
```
DeviceProcessEvents
| where DeviceName == "anthony-001"
| where InitiatingProcessFileName =~ "BitSentinelCore.exe"
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
```
![image](https://github.com/user-attachments/assets/be018664-721f-47f2-afa7-ebd1ac9323b7)

### MITRE Technique Mapping

| Tactic | Technique ID | Description |
| --- | --- | --- |
| Execution | T1204.002 | User Execution – Malicious file manually launched |
| Persistence | T1053.005 | Scheduled Task / Job |
| Persistence | T1547.001 | Registry Run Keys / Startup Folder |
| Defense Evasion | T1036.005 | Masquerading – Service name mimics security product |

# Phase 5 – Credential Access and Data Collection

**PEAK Step:** Execute → Analyse

**MITRE Tactics:**

- Credential Access (TA0006)
- Collection (TA0009)

---

### What We Investigated

Now that we’ve established malware persistence, the focus shifted to **malicious post-execution behaviour**, notably:

- Evidence of **credential theft**
- File creation related to **keylogging or surveillance**
- Registry or file I/O patterns consistent with **data staging**

---

### What We Found

### **Credential Harvesting Artefact**

After persistence was established, `BitSentinelCore.exe` **wrote a suspicious log file** to the
following location:
```
C:\Users\4nth0ny!\AppData\Roaming\ThreatMetrics\systemreport.txt
```
Strings extracted from the binary and confirmed in the file:
```
Captured User: bubba.admin
Captured Pass: V@ultHunter2025!
```
This indicates keylogging or credential capture in plaintext.
![image](https://github.com/user-attachments/assets/d1dc434c-3fd9-4647-8b42-6859015688e0)
---
Click Here: Full Binary Analysis Report
---

### Registry Reads & Environment Recon

From Defender for Endpoint telemetry, we observed **extensive registry reads** originating from `BitSentinelCore.exe`. These included:

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer`
- `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager`
- `HKCU\Control Panel\Desktop\MuiCached`

These reads are often used by malware to:

- Determine **execution environment or user session info**
- Identify **active users, language settings, or OS version**
- Avoid sandboxes or triggers based on locale

This behaviour supports **TA0009 (Collection)** and **TA0005 (Defence Evasion)**.

```kql
/// KQL USED
DeviceFileEvents
| where DeviceName == "anthony-001"
| where InitiatingProcessFileName =~ "BitSentinelCore.exe"
| where FolderPath has_any ("AppData", "Temp", "ProgramData", "Roaming", "Windows\\System32")
| project Timestamp, FileName, FolderPath, SHA256, InitiatingProcessCommandLine
| order by Timestamp asc

DeviceFileEvents
| where DeviceName == "anthony-001"
| where FolderPath startswith "C:\\Users\\4nth0ny!\\AppData\\Roaming\\ThreatMetrics"
| project Timestamp, FileName, FolderPath, SHA256, InitiatingProcessFileName
| order by Timestamp asc
```
![image](https://github.com/user-attachments/assets/12cba102-9c16-4b18-90e3-49309ee507f0)

``` KQL USED
DeviceFileEvents
| where DeviceName == "anthony-001"
| where FolderPath startswith "C:\\Users\\4nth0ny!\\AppData\\Roaming\\"
| project Timestamp, FileName, FolderPath, SHA256, InitiatingProcessFileName
| order by Timestamp asc
```
![image](https://github.com/user-attachments/assets/561c726e-7348-4489-ac1a-ebddb66fc4bd)

```
DeviceProcessEvents
| where DeviceName == "anthony-001"
| where ProcessCommandLine has "Roaming\\ThreatMetrics"
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName
```
![image](https://github.com/user-attachments/assets/94433baf-8669-42b2-b73e-993188464f21)

- On **May 7, 2025, at 2:06:51 AM**, the file `systemreport.txt`, located within the `ThreatMetrics` directory, was opened by `notepad.exe` via `explorer.exe`,
- suggesting that the file was manually reviewed or checked after creation.
- A corresponding shortcut (`.lnk`) file was created for this report file:
```
C:\Users\4nth0ny!\AppData\Roaming\Microsoft\Windows\Recent\systemreport.lnk
```

- Additional `.lnk` artefacts found in the same `Recent` folder include:
    - `ThreatMetrics.lnk` — shortcut to the malware's working directory
    - `FinanceStatements.lnk`, `Document3.lnk`, shortcuts to sensitive corporate data accessed/staged
- These artefacts correlate tightly with the observed timeline of malware execution and credential capture behaviour.

**Mapped IOCs:**

| **Indicator** | **Type** | **Description** |
| --- | --- | --- |
| `BitSentinelCore.exe` | Executable | Malware keylogger, deployed via phishing |
| `ThreatMetrics` | Folder name | Fake security telemetry directory |
| `systemreport.txt` | File | Likely output of keylogger |
| `systemreport.lnk` | Shortcut | Suggests user-level file access |
| SHA256 of .lnk files | File hash | As captured in Defender logs |
| `notepad.exe` spawn | Process artifact | Opened report file manually |
| Timestamp: `3:06:51 AM` | Temporal IOC | Aligns to post-compromise access |

### MITRE Technique Mapping

| Tactic | Technique ID | Description |
| --- | --- | --- |
| Credential Access | T1056.001 | Keylogging – Captured typed credentials |
| Collection | T1119 | Automated Collection – Writes logs of user behavior |
| Defense Evasion | T1027 | Obfuscated Files or Information – Clean structure, hidden folders |
| Discovery | T1082 | System Information Discovery via registry |

# Phase 6 – Timeline Correlation and Forensic Attribution

**PEAK Step:** Analyse → Know

**MITRE Tactics:**

- Execution (TA0002)
- Persistence (TA0003)
- Credential Access (TA0006)
- Impact (TA0040)

### What We Investigated

After establishing that `BitSentinelCore.exe` captured credentials and created persistence mechanisms, we now aimed to:

- **Link all malicious events** back to a **single initial action**
- **Correlate execution timestamps** of key attacker behaviours
- Confirm the **root cause event** using telemetry from Defender and Sentinel

---

### Key Discovery – Timeline Correlation

### **Initial Compilation of Malware**

Using the following KQL query:
```kql
DeviceFileEvents
| where DeviceName == "anthony-001"
| where FileName =~ "BitSentinelCore.exe"
| project Timestamp, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
```
![image](https://github.com/user-attachments/assets/acc35361-c185-4408-b6b7-b36a4be9ddc3)

We confirmed:

| Time (UTC) | Event |
| --- | --- |
| **2025-05-07T02:00:36.794406Z** | `BitSentinelCore.exe` created by `csc.exe` |
| **2025-05-07T02:02:14Z** | File manually executed by `explorer.exe` |
| **2025-05-07T02:02:14Z** | Registry Run Key created |
| **2025-05-07T02:03:20Z** | `schtasks.exe` creates daily scheduled task |
| **2025-05-07T02:06:51Z** | `notepad.exe` opens `systemreport.txt` |

### Defender Timeline View

Screenshots from Microsoft Defender’s timeline interface validate that `BitSentinelCore.exe`:

- Was **manually executed** by user `4nth0ny!`
- Spawned **cmd.exe**, which then launched **schtasks.exe**
- Created a **registry run key**
- Dropped a keylogging output file
- Loaded a suspicious `System.ni.dll` into memory

### **Execution Timeline & Root Cause**

| Time (UTC) | Action |
| --- | --- |
| **`2025-05-07T02:00:36Z`** | `BitSentinelCore.exe` compiled by dropper via `csc.exe` using script at `Temp\*.cmdline` |
| **`2025-05-07T02:02:14Z`** | User `4nth0ny!` executes malware via `explorer.exe` |
| **`2025-05-07T02:02:14Z`** | Malware writes persistence key: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` |
| **`2025-05-07T02:03:20Z`** | `schtasks.exe` creates daily task `UpdateHealthTelemetry` to run `BitSentinelCore.exe` |
| **Following** | PowerShell, DLL compilation (`csc.exe`), and host enumeration observed |

![image](https://github.com/user-attachments/assets/046783e3-a254-450a-bd2b-6900c3799db1)

### MITRE Technique Mapping

| Tactic | Technique ID | Description |
| --- | --- | --- |
| Execution | T1204.002 | User Execution: Malicious File |
| Persistence | T1053.005 | Scheduled Task/Job |
| Persistence | T1547.001 | Registry Run Keys/Startup Folder |
| Credential Access | T1056.001 | Keylogging (ThreatMetrics folder) |
| Impact | T1565.001 | Stored Data Manipulation (Credential log file) |


# Phase 7 – Exfiltration, Discovery, and Impact

**PEAK Step:** Know → Finalise

**MITRE Tactics:**

- Discovery (TA0007)
- Collection (TA0009)
- Exfiltration (TA0010)
- Impact (TA0040)

### What We Investigated

Having confirmed persistence and credential access, our final objective was to validate whether:

- The attacker **discovered sensitive data or system context**
- Files were **collected or accessed** for staging
- Any **network exfiltration** occurred
- Signs of **cleanup or impact** were present (e.g., log tampering, deletion)

We focused on reviewing:

- **File access** across AcmeCorp’s corporate document folders
- **Archive creation attempts**, such as `.zip`, `.7z`, or `.rar` files
- **PowerShell and CMD activity** related to staging or exfiltration commands
- **Outbound network connections** from attacker processes (`powershell.exe`, `cmd.exe`, `BitSentinelCore.exe`)

### KQL Queries Used

### 1. Access to Corporate Documents

```
DeviceFileEvents
| where DeviceName == "anthony-001"
| where FolderPath startswith "C:\\Users\\4nth0ny!\\AppData\\Roaming\\"
| project Timestamp, FileName, FolderPath, SHA256, InitiatingProcessFileName
| order by Timestamp asc
```
![image](https://github.com/user-attachments/assets/d95520f4-d52c-4cd0-9aca-342357cd342d)

2. Archive File Creation
```
DeviceFileEvents
| where DeviceName == "anthony-001"
| where FileName endswith ".zip" or FileName endswith ".7z" or FileName endswith ".rar"
| project Timestamp, FileName, FolderPath, InitiatingProcessFileName
```
![image](https://github.com/user-attachments/assets/3fbaf444-f2c8-466c-bf61-e7a12e14806f)

3. Network Exfiltration Attempts

```
DeviceNetworkEvents
| where DeviceName == "anthony-001"
| where InitiatingProcessFileName in ("powershell.exe", "cmd.exe", "BitSentinelCore.exe")
| where RemoteIP != "127.0.0.1" and RemoteIP != "::1"
| project Timestamp, RemoteIP, RemotePort, InitiatingProcessFileName

```
![image](https://github.com/user-attachments/assets/b529d216-0451-42e2-a599-f758f910963f)
![image](https://github.com/user-attachments/assets/f31ffd98-30c2-439b-bf0d-5b8c9de79324)
### What We Found
---
### **Sensitive File Accessed – Shortcut Locations**

| File Shortcut | Location |
| --- | --- |
| `Document3.lnk` | `C:\Users\4nth0ny!\AppData\Roaming\Microsoft\Windows\Recent\Document3.lnk` |
| `FinanceStatements.lnk` | `C:\Users\4nth0ny!\AppData\Roaming\Microsoft\Windows\Recent\FinanceStatements.lnk` |
| `systemreport.lnk` | `C:\Users\4nth0ny!\AppData\Roaming\Microsoft\Windows\Recent\systemreport.lnk` |
| `ThreatMetrics.lnk` | `C:\Users\4nth0ny!\AppData\Roaming\Microsoft\Windows\Recent\ThreatMetrics.lnk` |

These .lnk files are clear indicators that the original documents (e.g., Document3.txt, FinanceStatements.txt) and the keylogger output (systemreport.txt) 
were interacted with via Explorer, confirming staging or viewing activity.

### Archive File Creation

- Two `.zip` files named `VMAgentLogs.zip` were created at approximately `2025-05-07T02:55:00Z`
- The **creation process** was `collectguestlogs.exe`, a legitimate diagnostic utility
- No `.rar`, `.7z`, or other compressed files were created by attacker processes
- No suspicious archiving behaviour or data staging through attacker tooling was found

---

### Outbound Network Traffic

- Outbound connections were initiated by both `powershell.exe` and `BitSentinelCore.exe`
- All traffic was directed to **internal Cyber Range infrastructure**
- No beaconing to external C2 servers, suspicious DNS queries, or data uploads were identified
- IPs were verified via VirusTotal and identified as **benign Microsoft-owned lab endpoints**
![image](https://github.com/user-attachments/assets/ea4724cf-704b-4cea-a4be-fa0a02130a39)
![image](https://github.com/user-attachments/assets/5d3916b9-43dc-4467-9f0e-d0c3298fbee0)
---
### Interpretation

- **Discovery:** Confirmed: attacker used PowerShell to explore sensitive directories pre-compromise
- **Collection:** Confirmed: documents were accessed, but not staged for exfil using attacker tooling
- **Exfiltration:** Simulated only: no confirmed external data transfer occurred
- **Impact:** Minimal: credentials were harvested, but no data was leaked or systems were damaged

---

### Final Outcome

- **Persistence was established**, but **the threat was contained before it could be fully exfiltrated.**
- **Credential theft confirmed** (plaintext credentials of privileged user)
- **No lateral movement, no privilege escalation, and no destructive actions**
- **Key IOCs identified**: `BitSentinelCore.exe`, `ThreatMetrics`, `systemreport.txt`, and scheduled task abuse

### MITRE Technique Mapping

| Tactic | Technique ID | Description |
| --- | --- | --- |
| Discovery | T1083 | File and Directory Discovery |
| Collection | T1005 | Data from Local System (FinanceReports etc.) |
| Exfiltration | T1041 | Exfiltration over C2 (simulated only) |
| Impact | T1565.001 | Stored Data Manipulation (systemreport.txt) |

## Defensive Recommendations

| Area | Actionable Recommendation |
| --- | --- |
| **Endpoint Hardening** | Block or restrict execution of `csc.exe`, `schtasks.exe`, and other LOLBins for non-admin users. |
| **User Awareness** | Conduct training focused on recognizing phishing and fake antivirus lures. |
| **Detection Engineering** | Implement alerts for scheduled tasks created in unusual directories or with suspicious names (e.g., `UpdateHealthTelemetry`). |
| **Registry Monitoring** | Monitor for changes in `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, especially outside business hours. |
| **EDR Logic** | Build detections for unusual process chains like `explorer.exe → schtasks.exe → BitSentinelCore.exe`. |
| **Access Control** | Review and reduce RDP exposure; enforce MFA for all privileged accounts. |
| **Threat Hunting** | Hunt for presence of files and folders such as `ThreatMetrics\systemreport.txt`, `BitSentinelCore.exe`, or registry keys like `BitSecSvc`. |
| **IOCs & Threat Intel** | Block observed IPs, file hashes, and monitor for future recurrence of any related indicators. |

# Appendix

---

## MITRE ATT&CK Technique Mapping

- This mapping reflects both the **simulated phishing scenario** (where the user clicks the BitSentinel attachment) and the **observable system behaviour** (manual execution via `explorer.exe`).
- The creation of the local user account `4nth0ny!` B**efore malware execution, it** suggests that the attacker's activity began **via reverse shell before launching the main payload**, which aligns with the simulation.

This is a lab scenario, so some actions were simulated. However, our telemetry confirms that the malware was compiled and executed locally, with full telemetry indicating stealthy persistence, credential logging, and potential staging.

This is a lab scenario, so some actions were simulated. However, our telemetry confirms that the malware was compiled and executed locally, with full telemetry indicating stealthy persistence, credential logging, and potential staging.

| Tactic | Technique ID | Description |
| --- | --- | --- |
| **Initial Access** | [T1566.001](https://attack.mitre.org/techniques/T1566/001) | **Phishing: Spearphishing Attachment** – Bubba was simulated to click a phishing attachment (BitSentinel), representing initial user interaction |
| **Execution** | [T1204.002](https://attack.mitre.org/techniques/T1204/002) | **User Execution** – BitSentinelCore.exe was manually executed by the user via `explorer.exe` |
| **Execution** | [T1059.001](https://attack.mitre.org/techniques/T1059/001) | **PowerShell** – Used in early-stage execution, staging, and likely reverse shell setup |
| **Execution** | [T1127.001](https://attack.mitre.org/techniques/T1127/001) | **Compile After Delivery** – BitSentinelCore.exe was compiled via `csc.exe` using a `.cmdline` script post-phishing |
| **Execution** | [T1059.003](https://attack.mitre.org/techniques/T1059/003) | **Windows Command Shell** – Used for command execution and launching scheduled tasks |
| **Persistence** | [T1547.001](https://attack.mitre.org/techniques/T1547/001) | **Registry Run Keys / Startup Folder** – Registry key added under HKCU to maintain persistence |
| **Persistence** | [T1053.005](https://attack.mitre.org/techniques/T1053/005) | **Scheduled Task / Job** – Task created to re-launch BitSentinelCore.exe daily at 14:00 |
| **Credential Access** | [T1056.001](https://attack.mitre.org/techniques/T1056/001) | **Keylogging** – Captured credentials stored in `systemreport.txt` within the `ThreatMetrics` folder |
| **Credential Access** | [T1552.002](https://attack.mitre.org/techniques/T1552/002) | **Credentials in Registry** – Registry access by support module for possible session/user profiling |
| **Discovery** | [T1083](https://attack.mitre.org/techniques/T1083) | **File and Directory Discovery** – PowerShell accessed AcmeCorp folders to identify sensitive data |
| **Discovery** | [T1018](https://attack.mitre.org/techniques/T1018) | **Remote System Discovery** – Registry enumeration included session and environment info |
| **Discovery** | [T1082](https://attack.mitre.org/techniques/T1082) | **System Information Discovery** – Malware checked OS/user locale for sandbox evasion |
| **Defense Evasion** | [T1036.005](https://attack.mitre.org/techniques/T1036/005) | **Masquerading** – Malware disguised as `BitSentinelCore.exe`, mimicking AV software |
| **Defense Evasion** | [T1127](https://attack.mitre.org/techniques/T1127) | **Trusted Developer Utilities Proxy Execution** – Use of native `csc.exe` to compile payload post-phishing |
| **Defense Evasion** | [T1218.010](https://attack.mitre.org/techniques/T1218/010) | **Signed Binary Proxy Execution: Native Image** – `System.ni.dll` abused for stealthy DLL loading from trusted paths |
| **Collection** | [T1005](https://attack.mitre.org/techniques/T1005) | **Data from Local System** – PowerShell accessed documents from sensitive corporate folders |
| **Collection** | [T1119](https://attack.mitre.org/techniques/T1119) | **Automated Collection** – Keylog output and `.lnk` shortcuts staged in the background |
| **Exfiltration (Simulated)** | [T1041](https://attack.mitre.org/techniques/T1041) | **Exfiltration Over C2 Channel** – Simulated telemetry showed expected behavior, but no real C2 communication occurred |
| **Impact** | [T1565.001](https://attack.mitre.org/techniques/T1565/001) | **Stored Data Manipulation** – `systemreport.txt` contained captured credentials |

## Timeline of Confirmed Attacker Activity

- **Peak attacker activity** occurred between **02:00 and 04:00 UTC**.
- **Initial access** was achieved using **valid credentials**, not via brute force.
- The intrusion relied on **manual execution** of a **locally compiled payload**, followed by stealthy **persistence** and **credential logging**.
- **No destructive behaviour** (e.g., ransomware or wipers) was identified during the simulation.
- All observed **network activity** was **simulated within the Cyber Range**; no actual exfiltration or C2 communication occurred.

| Time (UTC) | Event Description |
| --- | --- |
| **01:22:57** | Successful logon from external IP `49.147.196.23` using pre-staged account `4nth0ny!` (`LogonType: Network`, via `lsass.exe`) |
| **01:23:04** | RDP session initiated using `4nth0ny!` (RemoteInteractive), confirming attacker foothold and lateral access |
| **01:30:12** | `powershell.exe` accessed sensitive files in `C:\Users\4nth0ny!\Documents\AcmeCorp\` – initial discovery activity |
| **02:00:36** | Custom payload `BitSentinelCore.exe` compiled on-host via `csc.exe` using `.cmdline` C# script (not phishing-delivered) |
| **02:02:14** | `bubba.admin` manually executed `BitSentinelCore.exe` via `explorer.exe` – likely user action simulated in phishing scenario |
| **02:02:14** | Malware created registry persistence key: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\BitSecSvc` |
| **02:02:14** | `ThreatMetrics` folder created under `Roaming`; keylogger log `systemreport.txt` written (staged credential capture) |
| **02:03:16** | `cmd.exe` spawned `schtasks.exe` to schedule daily execution via `UpdateHealthTelemetry` task |
| **02:06:51** | `notepad.exe` opened `systemreport.txt` – likely verification or demonstration step in simulation |
| **02:06:51** | Shortcut `.lnk` files created: `systemreport.lnk`, `FinanceStatements.lnk` – confirms attacker file access |
| **02:55:00** | `collectguestlogs.exe` generated `VMAgentLogs.zip` – confirmed **lab tool**, not attacker activity |

## **Indicators of Compromise (IOCs)**

| Type | Value | Description |
| --- | --- | --- |
| **IP Address** | `49.147.196.23` | Source of successful RDP access |
| **IP Address** | `102.88.21.216`, `193.37.69.105`, `80.94.95.203` | Sources of brute-force attempts (failed logins) |
| **Executable** | `BitSentinelCore.exe` | Malicious binary compiled and dropped locally |
| **SHA256** | `9b091ea29ddbf3dc965a03939d06a219698e9476baf450ee39ed360096e5d9ed` | BitSentinelCore.exe hash |
| **File Size** | `5.12 KB` | BitSentinelCore.exe |
| **Signer** | Unsigned | No digital signature |
| **File** | `System.dll` | Malicious DLL loaded post-execution |
| **SHA256** | `1c64b73b4621819891e0fa026353c6b396f3100243602fd3e3c8af51e1b613e9` | System.dll hash |
| **File Size** | `13.06 MB` | System.dll |
| **Signer** | Unsigned | No digital signature |
| **SHA256** | `a53016505b836a6f0a0e53d3348b9bbf36327d725482ebc98e3f4327c43bd906` | `systemreport.lnk` (keylogger shortcut) |
| **SHA256** | `e114eef23022dd5835f10ad39e390aae777bb2ab093bb899bbd1377745d6c01a` | `FinanceStatements.lnk` shortcut |
| **SHA256** | `00f9d3ea1820ce8d2b9faf4faf51b78d22bdae229a04763bf5aa1d064e55998a` | `Document3.lnk` shortcut |
| **Registry Key** | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\BitSecSvc` | Persistence via autorun |
| **Scheduled Task** | `UpdateHealthTelemetry` | Hidden scheduled task created by malware |
| **Folder** | `C:\Users\4nth0ny!\AppData\Roaming\ThreatMetrics` | Storage location for keylogger logs |
| **File** | `systemreport.txt` | Captured plaintext credentials |
| **File** | `systemreport.lnk` | Shortcut to harvested credentials |
| **File Path** | `C:\ProgramData\BitSentinelCore.exe` | Malware payload drop location |
| **Process** | `csc.exe` | Used to compile the malicious binary |


### References

- [**MITRE ATT&CK](https://attack.mitre.org/)** – Utilised for mapping adversary behaviours to recognised Tactics, Techniques, and Procedures (TTPs), providing a comprehensive understanding of potential threats.
- [**PEAK Threat Hunting Framework**](https://www.splunk.com/en_us/blog/security/peak-threat-hunting-framework.html) – Employed to structure the threat hunting process through its phases: Prepare, Execute, and Act with Knowledge, facilitating a systematic and practical approach to identifying and mitigating threats. ([Informa TechTarget](https://www.techtarget.com/searchsecurity/tip/Threat-hunting-frameworks-techniques-and-methodologies?utm_source=chatgpt.com))

Report Compiled By:

Felix , Cybersecurity Support Analyst (Intern)

Environment: Cyber Range

Date: 28/05/2025

Mentor & Lead Instructor: Josh Madakor
























  
  

