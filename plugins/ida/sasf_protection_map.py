"""
SASF IDA Plugin: Protection Map
---------------------------------
Maps all anti-tampering, anti-debug, integrity check, and obfuscation routines
in the binary. Produces a JSON protection map that SASF agents use to plan
bypass strategies.

Detects: checksum loops, timing checks, debugger queries, environment
fingerprinting, TLS callbacks, DllMain guards, constructor/destructor chains.

Usage: idat64 -A -S"sasf_protection_map.py" target.idb
"""

import idaapi
import idautils
import idc
import json
import os

protections = []


def find_tls_callbacks():
    """Detect TLS callback functions (PE only)."""
    # TLS directory in PE header
    tls_ea = idaapi.get_imagebase()
    for seg_ea in idautils.Segments():
        name = idc.get_segm_name(seg_ea)
        if ".tls" in name.lower():
            protections.append({
                "type": "tls-callback",
                "addr": f"0x{seg_ea:x}",
                "desc": f"TLS section found at {name}",
                "bypass": "Patch TLS directory pointer or NOP callback body",
            })
    # Check for known TLS callback naming
    for func_ea in idautils.Functions():
        name = idc.get_func_name(func_ea)
        if "TlsCallback" in name or "tls_callback" in name.lower():
            protections.append({
                "type": "tls-callback",
                "addr": f"0x{func_ea:x}",
                "func": name,
                "desc": "Named TLS callback",
                "bypass": "NOP the callback or patch TLS directory",
            })


def find_checksum_loops():
    """Detect potential integrity check loops (CRC/hash over code sections)."""
    integrity_apis = [
        "CRC32", "crc32", "adler32", "MD5", "SHA1", "SHA256",
        "CCDigest", "CC_MD5", "CC_SHA1", "CC_SHA256",
        "BCryptHash", "CryptHashData",
    ]
    for api_name in integrity_apis:
        ea = idc.get_name_ea_simple(api_name)
        if ea == idc.BADADDR:
            ea = idc.get_name_ea_simple(f"_{api_name}")
        if ea == idc.BADADDR:
            continue
        for xref in idautils.CodeRefsTo(ea, 0):
            func = idaapi.get_func(xref)
            if func:
                fname = idc.get_func_name(func.start_ea)
                protections.append({
                    "type": "integrity-check",
                    "addr": f"0x{func.start_ea:x}",
                    "func": fname,
                    "api": api_name,
                    "desc": f"{fname} calls {api_name} — possible code integrity check",
                    "bypass": f"Patch return value or NOP call to {api_name}",
                })


def find_antidebug():
    """Detect anti-debug API calls."""
    antidebug_apis = {
        # Windows
        "IsDebuggerPresent":        "Check PEB.BeingDebugged",
        "CheckRemoteDebuggerPresent": "Remote debugger query",
        "NtQueryInformationProcess": "ProcessDebugPort/ProcessDebugFlags",
        "NtQuerySystemInformation":  "SystemKernelDebuggerInformation",
        "OutputDebugStringA":       "SEH-based anti-debug trick",
        "OutputDebugStringW":       "SEH-based anti-debug trick",
        "CloseHandle":              "Invalid handle exception trick",
        "NtSetInformationThread":   "ThreadHideFromDebugger",
        "GetTickCount":             "Timing-based anti-debug",
        "QueryPerformanceCounter":  "Timing-based anti-debug",
        "rdtsc":                    "Timing-based anti-debug (inline)",
        # macOS/Linux
        "ptrace":                   "PT_DENY_ATTACH / PTRACE_TRACEME",
        "sysctl":                   "P_TRACED flag check",
        "getppid":                  "Parent process check",
        "task_get_exception_ports":  "Exception port tampering check",
    }
    for api, desc in antidebug_apis.items():
        ea = idc.get_name_ea_simple(api)
        if ea == idc.BADADDR:
            ea = idc.get_name_ea_simple(f"_{api}")
        if ea == idc.BADADDR:
            continue
        callers = list(idautils.CodeRefsTo(ea, 0))
        for caller in callers[:10]:
            func = idaapi.get_func(caller)
            fname = idc.get_func_name(func.start_ea) if func else f"0x{caller:x}"
            protections.append({
                "type": "anti-debug",
                "addr": f"0x{caller:x}",
                "func": fname,
                "api": api,
                "desc": f"{fname} uses {api} — {desc}",
                "bypass": f"Patch {api} return value or hook it via Frida",
            })


def find_anti_tamper():
    """Detect code signing and entitlement checks."""
    tamper_apis = {
        "SecCodeCheckValidity":     "macOS code signing validation",
        "SecStaticCodeCreateWithPath": "macOS static code signature",
        "SecRequirementCreateWithString": "macOS code requirement",
        "WinVerifyTrust":           "Windows Authenticode check",
        "CertGetCertificateChain":  "Windows cert chain validation",
        "MmGetSystemRoutineAddress": "Kernel routine resolution",
    }
    for api, desc in tamper_apis.items():
        ea = idc.get_name_ea_simple(api)
        if ea == idc.BADADDR:
            ea = idc.get_name_ea_simple(f"_{api}")
        if ea == idc.BADADDR:
            continue
        for xref in idautils.CodeRefsTo(ea, 0):
            func = idaapi.get_func(xref)
            fname = idc.get_func_name(func.start_ea) if func else f"0x{xref:x}"
            protections.append({
                "type": "anti-tamper",
                "addr": f"0x{xref:x}",
                "func": fname,
                "api": api,
                "desc": f"{fname} calls {api} — {desc}",
                "bypass": f"Patch {api} to always return success",
            })


def find_environment_checks():
    """Detect VM/sandbox/emulator detection."""
    env_indicators = [
        ("vmware", "VMware detection"),
        ("virtualbox", "VirtualBox detection"),
        ("vbox", "VirtualBox detection"),
        ("qemu", "QEMU detection"),
        ("sandbox", "Sandbox detection"),
        ("cydia", "Jailbreak detection (Cydia)"),
        ("substrate", "Jailbreak detection (Substrate)"),
        ("frida", "Frida detection"),
        ("xposed", "Xposed detection"),
        ("magisk", "Root detection (Magisk)"),
        ("su", "Root detection (su binary)"),
    ]
    for s in idautils.Strings():
        try:
            val = str(s).lower()
        except Exception:
            continue
        for indicator, desc in env_indicators:
            if indicator in val:
                for xref in idautils.DataRefsTo(s.ea):
                    func = idaapi.get_func(xref)
                    if func:
                        fname = idc.get_func_name(func.start_ea)
                        protections.append({
                            "type": "environment-check",
                            "addr": f"0x{func.start_ea:x}",
                            "func": fname,
                            "string": val[:80],
                            "desc": f"{fname} references '{indicator}' — {desc}",
                            "bypass": f"Patch string comparison or hook function",
                        })
                break


def main():
    idaapi.auto_wait()
    print("[SASF] Building protection map...")

    find_tls_callbacks()
    find_checksum_loops()
    find_antidebug()
    find_anti_tamper()
    find_environment_checks()

    # Deduplicate by (type, addr)
    seen = set()
    unique = []
    for p in protections:
        key = (p["type"], p["addr"])
        if key not in seen:
            seen.add(key)
            unique.append(p)

    # Output
    out_path = os.path.splitext(idc.get_input_file_path())[0] + "_protection_map.json"
    with open(out_path, "w") as f:
        json.dump({
            "binary": idc.get_input_file_path(),
            "total_protections": len(unique),
            "protections": unique,
        }, f, indent=2)

    # Summary
    type_counts = {}
    for p in unique:
        type_counts[p["type"]] = type_counts.get(p["type"], 0) + 1

    print(f"\n[SASF] Protection map: {len(unique)} entries")
    for t, c in sorted(type_counts.items(), key=lambda x: -x[1]):
        print(f"  {t:20s}: {c}")
    print(f"\nOutput: {out_path}")


if __name__ == "__main__":
    main()
else:
    main()
