# SASF radare2 Script: Quick Security Audit
# -------------------------------------------
# Performs a fast security audit without IDA/Ghidra.
# Useful for initial triage and when full decompilation isn't available.
#
# Checks:
#   - Binary protections (RELRO, NX, PIE, canary, ASLR)
#   - Interesting imports (crypto, network, debug, injection)
#   - Hardcoded strings (URLs, keys, paths, credentials)
#   - Section permissions (RWX)
#   - Entry point analysis
#   - Cross-references to dangerous functions
#
# Usage: r2 -i sasf_quick_audit.r2 -q <binary>
#        r2 -i sasf_quick_audit.r2 -q -A <binary>  (with full analysis)

echo "===== SASF Quick Security Audit ====="
echo ""

# Binary info
echo "--- Binary Info ---"
i

echo ""
echo "--- Binary Protections ---"
iI~canary
iI~nx
iI~pic
iI~relro
iI~stripped

echo ""
echo "--- Sections & Permissions ---"
iS~rwx
iS~mrwx

echo ""
echo "--- Entry Points ---"
ie

echo ""
echo "--- Imports: Security-Relevant ---"
echo "[Crypto]"
ii~crypt
ii~aes
ii~des
ii~rsa
ii~sha
ii~md5
ii~ssl
ii~tls
ii~CCCrypt
ii~BCrypt
ii~EVP_

echo ""
echo "[Anti-Debug]"
ii~IsDebuggerPresent
ii~NtQueryInformation
ii~ptrace
ii~sysctl
ii~GetTickCount
ii~QueryPerformance
ii~OutputDebugString

echo ""
echo "[Process Injection]"
ii~VirtualAlloc
ii~WriteProcessMemory
ii~CreateRemoteThread
ii~NtCreateThread
ii~OpenProcess
ii~mach_vm
ii~task_for_pid

echo ""
echo "[Network]"
ii~connect
ii~send
ii~recv
ii~socket
ii~WSA
ii~curl
ii~http
ii~WinHttp

echo ""
echo "[File/Registry]"
ii~CreateFile
ii~WriteFile
ii~RegOpen
ii~RegSet
ii~RegQuery

echo ""
echo "--- Strings: Interesting ---"
echo "[URLs]"
iz~http://
iz~https://

echo ""
echo "[Paths]"
iz~/proc/
iz~/tmp/
iz~/var/
iz~HKEY_
iz~\\pipe\\

echo ""
echo "[Potential Secrets]"
iz~password
iz~secret
iz~token
iz~api_key
iz~apikey
iz~private
iz~credential

echo ""
echo "[Debug/Anti-RE]"
iz~debug
iz~frida
iz~substrate
iz~xposed
iz~magisk
iz~jailbreak
iz~root

echo ""
echo "[Crypto Indicators]"
iz~BEGIN
iz~AES
iz~DES
iz~RSA
iz~ENCRYPT

echo ""
echo "--- Dangerous Function XRefs ---"
aaa 2>/dev/null
echo "[gets]"
axt @@ sym.imp.gets 2>/dev/null
echo "[strcpy]"
axt @@ sym.imp.strcpy 2>/dev/null
echo "[sprintf]"
axt @@ sym.imp.sprintf 2>/dev/null
echo "[system]"
axt @@ sym.imp.system 2>/dev/null

echo ""
echo "--- Entropy (packer detection) ---"
rahash2 -a entropy -b 65536 $FILE 2>/dev/null || echo "(run with -A for entropy)"

echo ""
echo "===== SASF Audit Complete ====="
