---
name: stealer-analysis
description: Use when Malvex needs to analyze information stealer malware including credential harvesting, browser data theft, crypto wallet theft, clipboard hijacking and data exfiltration.
---

# Skill: stealer-analysis

Vector: `stealer-analysis` | agent: static-core, dynamic-analysis | platforms: windows, linux, macos
ATT&CK: T1555 (Credentials from Password Stores), T1539 (Steal Web Session Cookie)

## Objective

Analyze information stealer capabilities — credential harvesting from browsers, email
clients, FTP clients; crypto wallet theft; clipboard hijacking; screenshot capture;
keylogging; and data staging/exfiltration.

## Checklist

- Browser data targets (Chrome, Firefox, Edge, Opera — cookies, passwords, history, autofill)
- Email client targets (Outlook, Thunderbird, mail database files)
- Crypto wallet targets (MetaMask, Exodus, Electrum, wallet.dat, seed phrases)
- FTP/SSH client targets (FileZilla, WinSCP, PuTTY saved sessions)
- Clipboard monitoring/hijacking (crypto address replacement)
- Screenshot/webcam capture
- Keylogging mechanisms
- Data staging, compression, and exfiltration channel

## Procedure

1. **Target identification**: scan strings and code for browser profile paths
   (`%LOCALAPPDATA%\Google\Chrome\User Data`), database filenames (`Login Data`,
   `cookies.sqlite`, `key4.db`), wallet paths, credential store APIs.
2. **Decryption analysis**: identify how the stealer decrypts browser passwords —
   DPAPI (CryptUnprotectData), NSS (PK11SDR_Decrypt), SQLite database parsing.
3. **Wallet targeting**: identify cryptocurrency wallet file paths, browser extension IDs
   (MetaMask, Phantom), seed phrase extraction methods.
4. **Clipboard hijack**: identify clipboard monitoring (GetClipboardData/SetClipboardData
   loop) with regex matching for crypto addresses and replacement logic.
5. **Data staging**: identify how stolen data is collected — temp directory, archive
   creation (ZIP/RAR), naming conventions, file size limits.
6. **Exfiltration**: identify exfil channel — HTTP POST, Telegram bot API, Discord webhook,
   SMTP, FTP upload. Extract C2/drop endpoints.

## Proof

Specific targets identified with file paths and decryption methods. Exfiltration channel
documented with endpoint information extracted.

## Evidence out

- locus: target enumeration routines, decryption functions, exfil routine
- detail: targeted applications, decryption method, exfil channel, drop endpoints
- confidence: high when paths and APIs confirmed
- follow-up: `credential-data-access` for depth, `exfiltration-analysis` for exfil detail

## Guardrail

LLM output is a lead, not proof. Target paths and API usage must be traced in code.
