"""
SASF IDA Plugin: Auto-Rename Functions
---------------------------------------
Scans binaries for packer, protector, runtime, and malware-family patterns.
and renames functions with descriptive prefixes. Runs via IDA's batch mode or
interactively. Works with both IDA 7.x and IDA 9.x Python API.

Usage (batch):  idat64 -A -S"sasf_auto_rename.py" target.idb
Usage (interactive): File > Script file... > sasf_auto_rename.py
"""

import idaapi
import idautils
import idc
import re
from collections import defaultdict

# Known shielding SDK signatures: (byte pattern, name prefix, description)
SIGNATURES = [
    # Arxan / Digital.ai
    (b"ArxanProtect",       "arxan_",     "Arxan protection routine"),
    (b"TransformIT",        "arxan_tit_", "Arxan TransformIT handler"),
    (b"GuardIT",            "arxan_git_", "Arxan GuardIT check"),
    # Warsaw / Diebold GAS
    (b"GbpSv",              "warsaw_",    "Warsaw/GAS service routine"),
    (b"Gbp",                "warsaw_",    "Warsaw/GAS component"),
    (b"core.war",           "warsaw_",    "Warsaw core module"),
    # Promon SHIELD
    (b"PromonShield",       "promon_",    "Promon SHIELD routine"),
    (b"JNI_OnLoad",         "jni_",       "JNI entry (possible Promon hook)"),
    # Certificate pinning
    (b"SSLPinning",         "pin_",       "SSL Pinning check"),
    (b"X509TrustManager",   "pin_tm_",    "X509 Trust Manager override"),
    (b"certificatePin",     "pin_",       "Certificate pinning function"),
    # Anti-debug
    (b"IsDebuggerPresent",  "adb_",       "Anti-debug: IsDebuggerPresent"),
    (b"NtQueryInformation", "adb_ntq_",   "Anti-debug: NtQueryInformationProcess"),
    (b"ptrace",             "adb_pt_",    "Anti-debug: ptrace check"),
    (b"sysctl",             "adb_sys_",   "Anti-debug: sysctl P_TRACED"),
    # Integrity
    (b"checkSignature",     "integ_",     "Integrity: signature check"),
    (b"verifyChecksum",     "integ_",     "Integrity: checksum verification"),
]

# String-based heuristics: if a function references these strings, rename it
STRING_HINTS = {
    "frida":            "detect_frida_",
    "substrate":        "detect_substrate_",
    "xposed":           "detect_xposed_",
    "magisk":           "detect_magisk_",
    "/proc/self/maps":  "scan_maps_",
    "/proc/self/status":"scan_status_",
    "ro.debuggable":    "check_debug_prop_",
    "DYLD_INSERT":      "check_dyld_inject_",
    "__RESTRICT":       "check_restrict_",
    "com.apple.security.app-sandbox": "check_sandbox_ent_",
}

renamed = defaultdict(list)
total_renamed = 0


def get_func_strings(func_ea):
    """Collect all string references within a function."""
    strings = []
    func = idaapi.get_func(func_ea)
    if not func:
        return strings
    for head in idautils.Heads(func.start_ea, func.end_ea):
        for xref in idautils.DataRefsFrom(head):
            s = idc.get_strlit_contents(xref, -1, idc.STRTYPE_C)
            if s:
                strings.append(s.decode("utf-8", errors="replace"))
            s = idc.get_strlit_contents(xref, -1, idc.STRTYPE_C_16)
            if s:
                strings.append(s.decode("utf-16-le", errors="replace"))
    return strings


def rename_by_signatures():
    """Scan all functions for byte pattern matches and rename."""
    global total_renamed
    for seg_ea in idautils.Segments():
        seg = idaapi.getseg(seg_ea)
        if seg.type != idaapi.SEG_CODE:
            continue
        for func_ea in idautils.Functions(seg.start_ea, seg.end_ea):
            func_bytes = idc.get_bytes(func_ea, min(4096, idc.get_func_attr(func_ea, idc.FUNCATTR_END) - func_ea))
            if not func_bytes:
                continue
            for pattern, prefix, desc in SIGNATURES:
                if pattern in func_bytes:
                    old_name = idc.get_func_name(func_ea)
                    if old_name.startswith("sub_") or old_name.startswith("_"):
                        new_name = f"{prefix}{func_ea:x}"
                        if idc.set_name(func_ea, new_name, idc.SN_NOWARN):
                            renamed[prefix].append((func_ea, old_name, new_name, desc))
                            total_renamed += 1
                    break


def rename_by_strings():
    """Rename functions based on referenced strings."""
    global total_renamed
    for func_ea in idautils.Functions():
        old_name = idc.get_func_name(func_ea)
        if not (old_name.startswith("sub_") or old_name.startswith("_")):
            continue
        func_strings = get_func_strings(func_ea)
        full_text = " ".join(func_strings).lower()
        for hint, prefix in STRING_HINTS.items():
            if hint.lower() in full_text:
                new_name = f"{prefix}{func_ea:x}"
                if idc.set_name(func_ea, new_name, idc.SN_NOWARN):
                    renamed[prefix].append((func_ea, old_name, new_name, f"string ref: {hint}"))
                    total_renamed += 1
                break


def rename_by_imports():
    """Tag functions that call known security-relevant imports."""
    global total_renamed
    import_map = {
        "CreateToolhelp32Snapshot": "enum_proc_",
        "OpenProcess":             "open_proc_",
        "VirtualAllocEx":          "valloc_remote_",
        "WriteProcessMemory":      "wpm_",
        "NtWriteVirtualMemory":    "nt_wvm_",
        "CreateRemoteThread":      "crt_",
        "NtCreateThreadEx":        "nt_cte_",
        "SetWindowsHookEx":        "hook_win_",
        "mach_vm_write":           "mach_write_",
        "task_for_pid":            "task4pid_",
        "SecTrustEvaluate":        "sec_trust_",
    }
    for func_ea in idautils.Functions():
        old_name = idc.get_func_name(func_ea)
        if not old_name.startswith("sub_"):
            continue
        func = idaapi.get_func(func_ea)
        if not func:
            continue
        for head in idautils.Heads(func.start_ea, func.end_ea):
            for xref in idautils.CodeRefsFrom(head, 0):
                callee = idc.get_func_name(xref)
                if callee in import_map:
                    new_name = f"{import_map[callee]}{func_ea:x}"
                    if idc.set_name(func_ea, new_name, idc.SN_NOWARN):
                        renamed[import_map[callee]].append(
                            (func_ea, old_name, new_name, f"calls {callee}")
                        )
                        total_renamed += 1
                    break


def print_report():
    """Print summary of all renames."""
    print(f"\n{'='*60}")
    print(f"SASF Auto-Rename Report — {total_renamed} functions renamed")
    print(f"{'='*60}")
    for prefix, entries in sorted(renamed.items()):
        print(f"\n  [{prefix}] — {len(entries)} functions")
        for ea, old, new, desc in entries[:10]:  # limit output
            print(f"    0x{ea:x}: {old} -> {new}  ({desc})")
        if len(entries) > 10:
            print(f"    ... and {len(entries)-10} more")
    print(f"\n{'='*60}\n")


def main():
    idaapi.auto_wait()
    print("[SASF] Starting auto-rename pass...")
    rename_by_signatures()
    rename_by_strings()
    rename_by_imports()
    print_report()
    # Save IDB with renames
    idc.save_database(idc.get_idb_path(), idaapi.DBFL_COMP)
    print("[SASF] Database saved with renames.")


if __name__ == "__main__":
    main()
else:
    main()
