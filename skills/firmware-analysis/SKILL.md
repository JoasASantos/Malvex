---
name: firmware-analysis
description: Use when Malvex needs to analyze firmware images including embedded OS extraction, bootloader analysis, hardcoded credentials and firmware-specific backdoors.
---

# Skill: firmware-analysis

Vector: `firmware-analysis` | agent: static-core | platforms: linux, embedded
ATT&CK: T1542.001 (System Firmware), T1195.003 (Compromise Hardware Supply Chain)

## Objective

Analyze firmware images — filesystem extraction, bootloader analysis, hardcoded
credentials, backdoor accounts, vulnerable services, and firmware-level persistence.

## Checklist

- Firmware format identification (squashfs, JFFS2, UBIFS, cramfs, raw)
- Filesystem extraction and analysis
- Bootloader analysis (U-Boot, GRUB, custom)
- Hardcoded credentials (default passwords, SSH keys, certificates)
- Backdoor services (hidden telnet, debug ports, undocumented APIs)
- Known CVEs in embedded components (BusyBox, OpenSSL, lighttpd)

## Procedure

1. **Format identification**: use `binwalk`, `unblob`, or `file` to identify firmware
   container format, compression, and filesystem types.
2. **Extraction**: extract filesystem with `binwalk -e`, `jefferson` (JFFS2),
   `sasquatch` (squashfs variants), `ubi_reader` (UBIFS).
3. **Credential scan**: search extracted filesystem for hardcoded passwords in
   `/etc/shadow`, `/etc/passwd`, config files, init scripts, web interfaces.
4. **Service analysis**: identify running services from init scripts (rcS, inittab,
   systemd units), check for debug/backdoor ports.
5. **Binary analysis**: analyze key binaries (web server, management daemon) for
   buffer overflows, command injection, authentication bypass.
6. **Component inventory**: identify versions of BusyBox, kernel, OpenSSL, and other
   components for CVE mapping.

## Proof

Extracted filesystem with identified vulnerabilities, hardcoded credentials extracted
with exact file paths, backdoor services documented.

## Evidence out

- locus: firmware offset, filesystem path, binary function
- detail: vulnerability type, credential, service, affected component version
- confidence: high for credential extraction; varies for binary analysis
- follow-up: `library-dependency-map` for component CVEs

## Guardrail

LLM output is a lead, not proof. Extract and verify every credential and service.
