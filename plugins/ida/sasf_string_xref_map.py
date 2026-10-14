"""
SASF IDA Plugin: String Cross-Reference Map
---------------------------------------------
Builds a JSON map of interesting strings and every function that references
them. Useful for finding crypto keys, URLs, file paths, debug strings, error
messages, and format strings across the binary.

Output: string_xref_map.json — consumed by SASF agents to locate attack surface.

Usage: idat64 -A -S"sasf_string_xref_map.py" target.idb
"""

import idaapi
import idautils
import idc
import json
import os
import re

# Categories of interesting strings
CATEGORIES = {
    "url":       re.compile(r"https?://[^\s\"']+", re.I),
    "ip":        re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?\b"),
    "path_win":  re.compile(r"[A-Z]:\\[^\s\"']+"),
    "path_unix": re.compile(r"/(?:usr|var|tmp|etc|proc|dev|opt|home|Applications)/[^\s\"']*"),
    "registry":  re.compile(r"HKEY_[A-Z_]+\\[^\s\"']+", re.I),
    "format":    re.compile(r"%[0-9*]*[diouxXeEfFgGaAcspn%]"),
    "crypto":    re.compile(r"(AES|DES|RSA|SHA|MD5|HMAC|PBKDF|BCrypt|Argon)", re.I),
    "debug":     re.compile(r"(DEBUG|TRACE|VERBOSE|LOG_LEVEL|assert|ASSERT)", re.I),
    "error":     re.compile(r"(error|fail|exception|invalid|denied|unauthorized)", re.I),
    "secret":    re.compile(r"(password|secret|token|api.?key|credential|private)", re.I),
    "xpc":       re.compile(r"com\.[a-z0-9.-]+\.(xpc|service|helper|agent)", re.I),
    "bundle":    re.compile(r"com\.[a-z0-9.-]+", re.I),
    "pipe":      re.compile(r"\\\\.\\pipe\\[^\s\"']+", re.I),
    "env":       re.compile(r"(DYLD_|LD_PRELOAD|LD_LIBRARY_PATH|PATH=|HOME=)"),
}


def categorize(s):
    """Return list of matching categories for a string."""
    cats = []
    for cat, regex in CATEGORIES.items():
        if regex.search(s):
            cats.append(cat)
    return cats if cats else ["other"]


def main():
    idaapi.auto_wait()
    print("[SASF] Building string cross-reference map...")

    xref_map = {}
    total = 0

    for s in idautils.Strings():
        try:
            val = str(s)
        except Exception:
            val = idc.get_strlit_contents(s.ea, -1, s.strtype)
            if val:
                val = val.decode("utf-8", errors="replace")
            else:
                continue

        if len(val) < 4:  # skip very short strings
            continue

        cats = categorize(val)
        if cats == ["other"] and len(val) < 12:
            continue  # skip short uncategorized strings

        # Find all xrefs to this string
        refs = []
        for xref in idautils.DataRefsTo(s.ea):
            func = idaapi.get_func(xref)
            if func:
                refs.append({
                    "func": idc.get_func_name(func.start_ea),
                    "addr": f"0x{xref:x}",
                    "func_addr": f"0x{func.start_ea:x}",
                })
            else:
                refs.append({
                    "func": None,
                    "addr": f"0x{xref:x}",
                    "func_addr": None,
                })

        if not refs:
            continue

        entry = {
            "string": val[:256],  # cap length
            "addr": f"0x{s.ea:x}",
            "length": s.length,
            "categories": cats,
            "xrefs": refs,
        }

        key = f"0x{s.ea:x}"
        xref_map[key] = entry
        total += 1

    # Output
    out_path = os.path.splitext(idc.get_input_file_path())[0] + "_string_xrefs.json"
    with open(out_path, "w") as f:
        json.dump({
            "binary": idc.get_input_file_path(),
            "total_strings": total,
            "strings": xref_map,
        }, f, indent=2)

    print(f"[SASF] Mapped {total} interesting strings. Output: {out_path}")

    # Print summary by category
    cat_counts = {}
    for entry in xref_map.values():
        for cat in entry["categories"]:
            cat_counts[cat] = cat_counts.get(cat, 0) + 1

    print("\n  Category breakdown:")
    for cat, count in sorted(cat_counts.items(), key=lambda x: -x[1]):
        print(f"    {cat:15s}: {count}")


if __name__ == "__main__":
    main()
else:
    main()
