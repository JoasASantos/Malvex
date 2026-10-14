---
name: lateral-movement
description: Use when Malvex needs to analyze lateral movement capabilities including PsExec, WMI, WinRM, DCOM techniques, credential relay and network propagation.
---

# Skill: lateral-movement

Vector: `lateral-movement` | agent: static-core, dynamic-analysis | platforms: windows, linux
ATT&CK: T1021 (Remote Services), T1570 (Lateral Tool Transfer), T1550 (Use Alternate Auth)

## Objective

Analyze lateral movement capabilities — remote service exploitation, credential relay,
network propagation, self-spreading mechanisms, and worm-like behavior.

## Checklist

- SMB/PsExec-style remote execution (service creation over SMB)
- WMI remote process creation (Win32_Process.Create)
- WinRM/PowerShell remoting
- DCOM lateral movement (ShellBrowserWindow, MMC20.Application)
- Pass-the-hash / pass-the-ticket / overpass-the-hash
- Network scanning / host discovery
- Credential dumping for propagation (LSASS, SAM, cached creds)
- Exploit-based propagation (EternalBlue, BlueKeep, ProxyLogon)
- Self-spreading / worm behavior

## Procedure

1. **Network discovery**: identify host enumeration — ARP scanning, DNS querying,
   NetBIOS/LDAP queries, port scanning, Active Directory enumeration.
2. **Credential harvesting**: identify credential access for lateral movement — LSASS
   dumping (MiniDumpWriteDump), SAM extraction, Kerberos ticket harvesting.
3. **Remote execution**: identify remote execution methods — SCM service creation (PsExec
   pattern), WMI process creation, WinRM script execution, SSH, DCOM.
4. **Authentication abuse**: identify pass-the-hash (NTLM relay), pass-the-ticket
   (Kerberos), token impersonation for remote access.
5. **Propagation logic**: determine if the malware self-propagates — copies itself to
   remote shares, creates scheduled tasks, or exploits vulnerabilities.
6. **Target selection**: identify how targets are chosen — subnet scanning, AD group
   membership, cached credential targets, hardcoded target lists.

## Proof

Lateral movement chain documented: credential acquisition → target selection → remote
execution method → payload deployment, with specific APIs and techniques identified.

## Evidence out

- locus: network scanning routine, credential access, remote execution code
- detail: technique, target selection logic, credential type, propagation method
- confidence: high when full chain traced
- follow-up: `credential-data-access` for credential theft, `persistence-analysis` for remote persistence

## Guardrail

LLM output is a lead, not proof. Lateral movement chains must be traced through code.
