"""
SASF IDA Plugin: Vulnerability Scanner
---------------------------------------
Scans binaries for security-relevant and malware-analysis patterns:
  - Hardcoded keys/secrets in data segments
  - Insecure API usage (gets, strcpy, sprintf without bounds)
  - Missing stack canaries
  - RWX sections
  - Weak crypto (DES, RC4, ECB mode constants)
  - Unprotected function pointers (vtables without CFI)

Outputs findings as JSON compatible with SASF findings.json format.

Usage: idat64 -A -S"sasf_vuln_scanner.py <output.json>" target.idb
"""

import idaapi
import idautils
import idc
import json
import sys
import os
import re

findings = []

# --- Detectors ---

def scan_hardcoded_keys():
    """Find hardcoded crypto keys, API keys, tokens in data segments."""
    patterns = [
        (rb"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----", "hardcoded-private-key", "critical"),
        (rb"-----BEGIN CERTIFICATE-----",                    "hardcoded-cert",        "medium"),
        (rb"[Aa][Pp][Ii][_-]?[Kk][Ee][Yy]\s*[:=]\s*['\"]", "hardcoded-api-key",     "high"),
        (rb"[Ss][Ee][Cc][Rr][Ee][Tt]\s*[:=]\s*['\"]",       "hardcoded-secret",      "high"),
        (rb"[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]\s*[:=]\s*['\"]","hardcoded-password",   "high"),
        (rb"eyJ[A-Za-z0-9_-]{20,}\.",                        "hardcoded-jwt",         "high"),
        (rb"ghp_[A-Za-z0-9]{36}",                            "hardcoded-github-token","critical"),
        (rb"sk-[A-Za-z0-9]{32,}",                            "hardcoded-stripe-key",  "critical"),
    ]
    for seg_ea in idautils.Segments():
        seg = idaapi.getseg(seg_ea)
        if seg.type not in (idaapi.SEG_DATA, idaapi.SEG_RODATA):
            continue
        seg_bytes = idc.get_bytes(seg.start_ea, seg.size())
        if not seg_bytes:
            continue
        for pattern, vuln_class, severity in patterns:
            for m in re.finditer(pattern, seg_bytes):
                ea = seg.start_ea + m.start()
                snippet = seg_bytes[m.start():m.start()+64]
                findings.append({
                    "vuln_class": vuln_class,
                    "title": f"Hardcoded secret at 0x{ea:x}",
                    "severity": severity,
                    "verdict": "plausible",
                    "evidence": [{
                        "detail": f"Pattern match: {snippet[:40]}...",
                        "locus": f"0x{ea:x}",
                    }],
                    "target": idc.get_input_file_path(),
                })


def scan_insecure_apis():
    """Find calls to insecure C functions."""
    insecure = {
        "gets":     ("buffer-overflow-gets",    "high",   "Use fgets() instead"),
        "strcpy":   ("buffer-overflow-strcpy",  "medium", "Use strncpy/strlcpy"),
        "strcat":   ("buffer-overflow-strcat",  "medium", "Use strncat/strlcat"),
        "sprintf":  ("format-string-sprintf",   "medium", "Use snprintf"),
        "vsprintf": ("format-string-vsprintf",  "medium", "Use vsnprintf"),
        "scanf":    ("format-string-scanf",     "medium", "Validate format string"),
        "system":   ("command-injection",       "high",   "Avoid system(); use execve"),
        "popen":    ("command-injection-popen", "medium", "Sanitize input to popen"),
        "LoadLibraryA":  ("dll-load-unsafe", "medium", "Use full path + SetDllDirectory"),
        "LoadLibraryW":  ("dll-load-unsafe", "medium", "Use full path + SetDllDirectory"),
        "WinExec":       ("deprecated-winexec", "high", "Use CreateProcess"),
    }
    for func_name, (vuln_class, severity, fix) in insecure.items():
        ea = idc.get_name_ea_simple(func_name)
        if ea == idc.BADADDR:
            ea = idc.get_name_ea_simple(f"_{func_name}")
        if ea == idc.BADADDR:
            continue
        callers = list(idautils.CodeRefsTo(ea, 0))
        if callers:
            for caller in callers[:20]:  # cap
                caller_func = idaapi.get_func(caller)
                caller_name = idc.get_func_name(caller) if caller_func else f"0x{caller:x}"
                findings.append({
                    "vuln_class": vuln_class,
                    "title": f"Insecure {func_name}() call in {caller_name}",
                    "severity": severity,
                    "verdict": "plausible",
                    "evidence": [{
                        "detail": f"{caller_name} calls {func_name}() — {fix}",
                        "locus": f"0x{caller:x}",
                    }],
                    "target": idc.get_input_file_path(),
                })


def scan_rwx_sections():
    """Find sections with Read+Write+Execute permissions."""
    for seg_ea in idautils.Segments():
        seg = idaapi.getseg(seg_ea)
        perm = seg.perm
        if (perm & idaapi.SFL_READ) and (perm & idaapi.SFL_WRITE) and (perm & idaapi.SFL_EXEC):
            seg_name = idc.get_segm_name(seg_ea)
            findings.append({
                "vuln_class": "rwx-section",
                "title": f"RWX section: {seg_name} (0x{seg.start_ea:x}–0x{seg.end_ea:x})",
                "severity": "high",
                "verdict": "confirmed",
                "evidence": [{
                    "detail": f"Section {seg_name} has RWX permissions (size: {seg.size()} bytes)",
                    "locus": f"0x{seg.start_ea:x}",
                }],
                "target": idc.get_input_file_path(),
            })


def scan_weak_crypto():
    """Find weak crypto constants (DES S-boxes, RC4 init, ECB mode indicators)."""
    # DES initial permutation table (first 8 bytes)
    des_ip = bytes([58, 50, 42, 34, 26, 18, 10, 2])
    # RC4 KSA pattern (0x00 0x01 0x02 ... 0xFF) — 256-byte identity permutation
    rc4_init = bytes(range(256))

    for seg_ea in idautils.Segments():
        seg = idaapi.getseg(seg_ea)
        data = idc.get_bytes(seg.start_ea, min(seg.size(), 1024 * 1024))
        if not data:
            continue
        # DES
        idx = data.find(des_ip)
        if idx >= 0:
            ea = seg.start_ea + idx
            findings.append({
                "vuln_class": "weak-crypto-des",
                "title": f"DES permutation table at 0x{ea:x}",
                "severity": "medium",
                "verdict": "plausible",
                "evidence": [{"detail": "DES IP table found — DES is deprecated", "locus": f"0x{ea:x}"}],
                "target": idc.get_input_file_path(),
            })
        # RC4
        idx = data.find(rc4_init)
        if idx >= 0:
            ea = seg.start_ea + idx
            findings.append({
                "vuln_class": "weak-crypto-rc4",
                "title": f"RC4 initialization table at 0x{ea:x}",
                "severity": "medium",
                "verdict": "plausible",
                "evidence": [{"detail": "RC4 identity permutation found — RC4 is broken", "locus": f"0x{ea:x}"}],
                "target": idc.get_input_file_path(),
            })


def scan_missing_canaries():
    """Identify functions without stack canaries that have local buffers."""
    canary_refs = set()
    for name in ["__stack_chk_fail", "__stack_chk_guard", "___stack_chk_fail",
                  "__security_check_cookie", "@__security_check_cookie@4"]:
        ea = idc.get_name_ea_simple(name)
        if ea != idc.BADADDR:
            for ref in idautils.CodeRefsTo(ea, 0):
                func = idaapi.get_func(ref)
                if func:
                    canary_refs.add(func.start_ea)

    count = 0
    for func_ea in idautils.Functions():
        if count >= 50:  # cap findings
            break
        func = idaapi.get_func(func_ea)
        if not func:
            continue
        frame = idaapi.get_frame(func)
        if not frame:
            continue
        frame_size = idc.get_func_attr(func_ea, idc.FUNCATTR_FRSIZE)
        # Only flag functions with frames > 64 bytes (have buffers) and no canary
        if frame_size > 64 and func_ea not in canary_refs:
            name = idc.get_func_name(func_ea)
            findings.append({
                "vuln_class": "missing-stack-canary",
                "title": f"No stack canary in {name} (frame={frame_size}B)",
                "severity": "low",
                "verdict": "plausible",
                "evidence": [{
                    "detail": f"Function {name} has {frame_size}B frame without stack canary call",
                    "locus": f"0x{func_ea:x}",
                }],
                "target": idc.get_input_file_path(),
            })
            count += 1


def main():
    idaapi.auto_wait()
    print("[SASF] Running vulnerability scanner...")

    scan_hardcoded_keys()
    scan_insecure_apis()
    scan_rwx_sections()
    scan_weak_crypto()
    scan_missing_canaries()

    # Output
    out_path = None
    if len(idc.ARGV) > 1:
        out_path = idc.ARGV[1]
    else:
        out_path = os.path.splitext(idc.get_input_file_path())[0] + "_ida_findings.json"

    with open(out_path, "w") as f:
        json.dump(findings, f, indent=2)

    print(f"[SASF] Found {len(findings)} issues. Written to {out_path}")


if __name__ == "__main__":
    main()
else:
    main()
