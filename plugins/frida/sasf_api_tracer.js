/**
 * SASF Frida Script: Security API Tracer
 * ----------------------------------------
 * Traces security-relevant API calls with argument/return value logging.
 * Covers: file I/O, process creation, registry, crypto, network, IPC.
 *
 * Output format: JSON lines for easy parsing by SASF agents.
 *
 * Usage: frida -l sasf_api_tracer.js -f <target>
 */

'use strict';

const platform = Process.platform;
let traceCount = 0;

function emit(category, api, args, retval, extra) {
    traceCount++;
    const entry = {
        id: traceCount,
        cat: category,
        api: api,
        args: args,
        ret: retval,
        tid: Process.getCurrentThreadId(),
        ts: Date.now(),
    };
    if (extra) entry.extra = extra;
    send(entry);
}

function safeReadUtf8(ptr, maxLen) {
    if (!ptr || ptr.isNull()) return null;
    try { return ptr.readUtf8String(maxLen || 260); } catch (e) { return `<ptr:${ptr}>`; }
}

function safeReadUtf16(ptr, maxLen) {
    if (!ptr || ptr.isNull()) return null;
    try { return ptr.readUtf16String(maxLen || 260); } catch (e) { return `<ptr:${ptr}>`; }
}

// ==================== File I/O ====================
function traceFileIO() {
    if (platform === 'windows') {
        // CreateFileW
        hookIfExists('kernel32.dll', 'CreateFileW', {
            onEnter(args) {
                this.path = safeReadUtf16(args[0]);
                this.access = args[1].toInt32();
            },
            onLeave(retval) {
                emit('file', 'CreateFileW', { path: this.path, access: this.access }, retval.toInt32());
            }
        });

        // WriteFile
        hookIfExists('kernel32.dll', 'WriteFile', {
            onEnter(args) {
                this.handle = args[0].toInt32();
                this.size = args[2].toInt32();
            },
            onLeave(retval) {
                emit('file', 'WriteFile', { handle: this.handle, size: this.size }, retval.toInt32());
            }
        });
    } else {
        // open
        hookIfExists(null, 'open', {
            onEnter(args) { this.path = safeReadUtf8(args[0]); this.flags = args[1].toInt32(); },
            onLeave(retval) { emit('file', 'open', { path: this.path, flags: this.flags }, retval.toInt32()); }
        });

        // write
        hookIfExists(null, 'write', {
            onEnter(args) { this.fd = args[0].toInt32(); this.size = args[2].toInt32(); },
            onLeave(retval) { emit('file', 'write', { fd: this.fd, size: this.size }, retval.toInt32()); }
        });
    }
}

// ==================== Process ====================
function traceProcess() {
    if (platform === 'windows') {
        hookIfExists('kernel32.dll', 'CreateProcessW', {
            onEnter(args) {
                this.app = safeReadUtf16(args[0]);
                this.cmdLine = safeReadUtf16(args[1]);
            },
            onLeave(retval) {
                emit('process', 'CreateProcessW', { app: this.app, cmdLine: this.cmdLine }, retval.toInt32());
            }
        });

        hookIfExists('kernel32.dll', 'OpenProcess', {
            onEnter(args) {
                this.access = args[0].toInt32();
                this.pid = args[2].toInt32();
            },
            onLeave(retval) {
                emit('process', 'OpenProcess', { access: this.access, pid: this.pid }, retval.toInt32());
            }
        });

        hookIfExists('kernel32.dll', 'VirtualAllocEx', {
            onEnter(args) {
                this.proc = args[0].toInt32();
                this.size = args[1].toInt32();
                this.prot = args[3].toInt32();
            },
            onLeave(retval) {
                emit('process', 'VirtualAllocEx', {
                    process: this.proc, size: this.size,
                    protect: this.prot, rwx: (this.prot & 0x40) !== 0
                }, retval.toString());
            }
        });

        hookIfExists('kernel32.dll', 'WriteProcessMemory', {
            onEnter(args) {
                this.proc = args[0].toInt32();
                this.addr = args[1].toString();
                this.size = args[3].toInt32();
            },
            onLeave(retval) {
                emit('process', 'WriteProcessMemory', {
                    process: this.proc, addr: this.addr, size: this.size
                }, retval.toInt32());
            }
        });
    } else {
        hookIfExists(null, 'execve', {
            onEnter(args) { this.path = safeReadUtf8(args[0]); },
            onLeave(retval) { emit('process', 'execve', { path: this.path }, retval.toInt32()); }
        });

        hookIfExists(null, 'fork', {
            onLeave(retval) { emit('process', 'fork', {}, retval.toInt32()); }
        });

        if (platform === 'darwin') {
            hookIfExists(null, 'task_for_pid', {
                onEnter(args) { this.pid = args[1].toInt32(); },
                onLeave(retval) {
                    emit('process', 'task_for_pid', { pid: this.pid }, retval.toInt32());
                }
            });
        }
    }
}

// ==================== Registry (Windows) ====================
function traceRegistry() {
    if (platform !== 'windows') return;

    hookIfExists('advapi32.dll', 'RegOpenKeyExW', {
        onEnter(args) {
            this.hkey = args[0].toInt32();
            this.subKey = safeReadUtf16(args[1]);
        },
        onLeave(retval) {
            emit('registry', 'RegOpenKeyExW', { hkey: this.hkey, subKey: this.subKey }, retval.toInt32());
        }
    });

    hookIfExists('advapi32.dll', 'RegSetValueExW', {
        onEnter(args) {
            this.hkey = args[0].toInt32();
            this.name = safeReadUtf16(args[1]);
            this.type = args[3].toInt32();
        },
        onLeave(retval) {
            emit('registry', 'RegSetValueExW', { hkey: this.hkey, name: this.name, type: this.type }, retval.toInt32());
        }
    });
}

// ==================== Network ====================
function traceNetwork() {
    const lib = platform === 'windows' ? 'ws2_32.dll' : null;

    hookIfExists(lib, 'connect', {
        onEnter(args) {
            this.sockaddr = args[1];
            try {
                const family = this.sockaddr.readU16();
                if (family === 2) { // AF_INET
                    const port = (this.sockaddr.add(2).readU8() << 8) | this.sockaddr.add(3).readU8();
                    const ip = [0,1,2,3].map(i => this.sockaddr.add(4+i).readU8()).join('.');
                    this.target = `${ip}:${port}`;
                } else if (family === 30 || family === 10) { // AF_INET6
                    this.target = '<IPv6>';
                } else {
                    this.target = `family=${family}`;
                }
            } catch (e) { this.target = '<unknown>'; }
        },
        onLeave(retval) {
            emit('network', 'connect', { target: this.target }, retval.toInt32());
        }
    });

    hookIfExists(lib, 'send', {
        onEnter(args) { this.size = args[2].toInt32(); },
        onLeave(retval) { emit('network', 'send', { size: this.size }, retval.toInt32()); }
    });

    hookIfExists(lib, 'recv', {
        onEnter(args) { this.size = args[2].toInt32(); },
        onLeave(retval) { emit('network', 'recv', { requested: this.size }, retval.toInt32()); }
    });
}

// ==================== IPC ====================
function traceIPC() {
    if (platform === 'windows') {
        hookIfExists('kernel32.dll', 'CreateNamedPipeW', {
            onEnter(args) { this.name = safeReadUtf16(args[0]); },
            onLeave(retval) { emit('ipc', 'CreateNamedPipeW', { name: this.name }, retval.toInt32()); }
        });
    }

    if (platform === 'darwin') {
        hookIfExists(null, 'xpc_connection_create_mach_service', {
            onEnter(args) { this.service = safeReadUtf8(args[0]); },
            onLeave(retval) {
                emit('ipc', 'xpc_connection_create_mach_service', { service: this.service }, retval.toString());
            }
        });
    }
}

// ==================== Helpers ====================
function hookIfExists(module, name, callbacks) {
    try {
        const addr = Module.findExportByName(module, name);
        if (addr) {
            Interceptor.attach(addr, callbacks);
        }
    } catch (e) {}
}

// ==================== Main ====================
console.log(`[SASF-TRACE] Platform: ${platform}`);
console.log('[SASF-TRACE] Starting security API tracer...');

traceFileIO();
traceProcess();
traceRegistry();
traceNetwork();
traceIPC();

console.log('[SASF-TRACE] API tracer active. Events sent via send().');
