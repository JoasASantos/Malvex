/**
 * SASF Frida Script: Runtime Memory Scanner
 * -------------------------------------------
 * Scans process memory at runtime for:
 *   - Plaintext credentials (passwords, tokens, API keys)
 *   - Crypto keys in heap (AES keys, RSA key material)
 *   - Decrypted strings (post-deobfuscation)
 *   - Sensitive data exposure (PII, financial data)
 *
 * Can run periodic scans or trigger on specific events.
 *
 * Usage: frida -l sasf_memory_scanner.js -f <target>
 */

'use strict';

const findings = [];
let scanCount = 0;

function log(msg) { console.log(`[SASF-MEM] ${msg}`); }

// ==================== Pattern Definitions ====================

const PATTERNS = [
    // Credentials
    { name: 'jwt-token',     regex: /eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}/,   severity: 'high',     cat: 'credential' },
    { name: 'bearer-token',  regex: /[Bb]earer\s+[A-Za-z0-9_\-.~+\/]{20,}/,         severity: 'high',     cat: 'credential' },
    { name: 'basic-auth',    regex: /[Bb]asic\s+[A-Za-z0-9+\/=]{10,}/,              severity: 'high',     cat: 'credential' },
    { name: 'api-key',       regex: /[Aa]pi[_-]?[Kk]ey[\s:="']+[A-Za-z0-9_\-]{16,}/,severity: 'high',    cat: 'credential' },
    { name: 'password-field', regex: /[Pp]assword[\s:="']+[^\s"']{4,}/,              severity: 'high',     cat: 'credential' },

    // URLs with auth
    { name: 'url-with-creds', regex: /https?:\/\/[^:]+:[^@]+@[^\s"']+/,             severity: 'critical', cat: 'credential' },

    // Generic PII and financial-data indicators; classify intent, do not collect victim data.
    { name: 'cpf',           regex: /\d{3}\.\d{3}\.\d{3}-\d{2}/,                    severity: 'medium',   cat: 'pii' },
    { name: 'card-number',   regex: /\b[45]\d{3}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/,severity: 'critical',cat: 'pii' },
    { name: 'cnpj',          regex: /\d{2}\.\d{3}\.\d{3}\/\d{4}-\d{2}/,             severity: 'medium',   cat: 'pii' },

    // Crypto material
    { name: 'private-key',   regex: /-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----/, severity: 'critical', cat: 'crypto' },
    { name: 'hex-key-32',    regex: /[0-9a-f]{64}/i,                                 severity: 'low',      cat: 'crypto' },

    // Endpoints
    { name: 'internal-url',  regex: /https?:\/\/(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)[^\s"']+/,severity: 'medium', cat: 'network' },
    { name: 'api-endpoint',  regex: /https?:\/\/api\.[^\s"']+/,                      severity: 'info',     cat: 'network' },
];

// ==================== Scanner ====================

function scanRegion(base, size, regionName) {
    let data;
    try {
        data = base.readUtf8String(Math.min(size, 1024 * 1024));
    } catch (e) {
        try {
            data = base.readCString(Math.min(size, 1024 * 1024));
        } catch (e2) {
            return; // unreadable
        }
    }
    if (!data) return;

    for (const pattern of PATTERNS) {
        const matches = data.match(new RegExp(pattern.regex, 'g'));
        if (matches) {
            for (const match of matches.slice(0, 5)) { // cap per pattern
                const finding = {
                    type: pattern.name,
                    severity: pattern.severity,
                    category: pattern.cat,
                    value: match.substring(0, 80) + (match.length > 80 ? '...' : ''),
                    region: regionName,
                    addr: base.toString(),
                    scan: scanCount,
                };
                findings.push(finding);
                log(`FOUND [${pattern.severity}] ${pattern.name}: ${finding.value}`);
            }
        }
    }
}

function scanHeap() {
    scanCount++;
    log(`Starting scan #${scanCount}...`);

    const ranges = Process.enumerateRanges('r--');
    let scanned = 0;
    let totalBytes = 0;

    for (const range of ranges) {
        // Skip very large mappings (likely mapped files)
        if (range.size > 100 * 1024 * 1024) continue;
        // Skip known system libraries unless they contain heap
        const file = range.file;
        if (file && file.path && (
            file.path.includes('/usr/lib/') ||
            file.path.includes('/System/') ||
            file.path.includes('\\Windows\\System32\\'))) continue;

        scanRegion(range.base, range.size, file ? file.path : 'anon');
        scanned++;
        totalBytes += range.size;
    }

    log(`Scan #${scanCount} complete: ${scanned} regions, ${(totalBytes / 1024 / 1024).toFixed(1)}MB, ${findings.length} total findings`);
}

// ==================== Event-Triggered Scanning ====================

function hookDecryptionPoints() {
    // Hook common decryption functions to scan the output buffer
    const decryptAPIs = [
        { module: null, name: 'CCCrypt' },           // macOS CommonCrypto
        { module: null, name: 'EVP_DecryptFinal_ex' }, // OpenSSL
        { module: 'bcrypt.dll', name: 'BCryptDecrypt' }, // Windows CNG
    ];

    for (const api of decryptAPIs) {
        try {
            const addr = Module.findExportByName(api.module, api.name);
            if (addr) {
                Interceptor.attach(addr, {
                    onLeave(retval) {
                        log(`${api.name} returned — triggering targeted scan`);
                        // Scan recent allocations for decrypted content
                        setTimeout(() => scanHeap(), 100);
                    }
                });
                log(`Hooked ${api.name} for post-decryption scanning`);
            }
        } catch (e) {}
    }
}

// ==================== Continuous Monitoring ====================

function startPeriodicScan(intervalMs) {
    setInterval(() => {
        scanHeap();
        // Send findings to host
        if (findings.length > 0) {
            send({
                type: 'memory-scan-results',
                scan: scanCount,
                findings: findings.slice(-50), // last 50
                total: findings.length,
            });
        }
    }, intervalMs);
    log(`Periodic scanning every ${intervalMs}ms`);
}

// ==================== RPC Interface ====================
rpc.exports = {
    scan: function() {
        scanHeap();
        return findings;
    },
    getFindings: function() {
        return findings;
    },
    getSummary: function() {
        const byCat = {};
        for (const f of findings) {
            byCat[f.category] = (byCat[f.category] || 0) + 1;
        }
        return { total: findings.length, scans: scanCount, byCategory: byCat };
    },
    clearFindings: function() {
        findings.length = 0;
        log('Findings cleared');
    }
};

// ==================== Main ====================
log('Memory scanner loaded.');
log(`${PATTERNS.length} detection patterns active.`);

// Initial scan after 2 seconds (let the app initialize)
setTimeout(() => {
    scanHeap();
    hookDecryptionPoints();
}, 2000);

// Periodic scan every 30 seconds
startPeriodicScan(30000);
