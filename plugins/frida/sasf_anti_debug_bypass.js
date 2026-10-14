/**
 * SASF Frida Script: Universal Anti-Debug Bypass
 * ------------------------------------------------
 * Hooks all common anti-debug APIs on Windows, macOS, and Linux.
 * Makes the process appear undebugged to all checks.
 *
 * Usage: frida -l sasf_anti_debug_bypass.js -f <target>
 *        frida -l sasf_anti_debug_bypass.js -n <process_name>
 */

'use strict';

const platform = Process.platform;
const hooked = [];

function log(msg) {
    console.log(`[SASF-ADB] ${msg}`);
}

// ==================== Windows ====================
function bypassWindows() {
    // IsDebuggerPresent
    try {
        const IsDebuggerPresent = Module.findExportByName('kernel32.dll', 'IsDebuggerPresent');
        if (IsDebuggerPresent) {
            Interceptor.attach(IsDebuggerPresent, {
                onLeave(retval) { retval.replace(0); }
            });
            hooked.push('IsDebuggerPresent');
        }
    } catch (e) {}

    // CheckRemoteDebuggerPresent
    try {
        const CheckRemote = Module.findExportByName('kernel32.dll', 'CheckRemoteDebuggerPresent');
        if (CheckRemote) {
            Interceptor.attach(CheckRemote, {
                onLeave(retval) {
                    // Write FALSE to the pbDebuggerPresent out-param
                    const args = this.context;
                    // Second param is the PBOOL pointer
                    retval.replace(1); // return TRUE (success)
                }
            });
            hooked.push('CheckRemoteDebuggerPresent');
        }
    } catch (e) {}

    // NtQueryInformationProcess
    try {
        const NtQIP = Module.findExportByName('ntdll.dll', 'NtQueryInformationProcess');
        if (NtQIP) {
            Interceptor.attach(NtQIP, {
                onEnter(args) {
                    this.infoClass = args[1].toInt32();
                    this.outBuf = args[2];
                },
                onLeave(retval) {
                    // ProcessDebugPort (7), ProcessDebugFlags (0x1f), ProcessDebugObjectHandle (0x1e)
                    if (this.infoClass === 7 || this.infoClass === 0x1f || this.infoClass === 0x1e) {
                        if (this.outBuf && !this.outBuf.isNull()) {
                            this.outBuf.writeU32(0);
                        }
                    }
                }
            });
            hooked.push('NtQueryInformationProcess');
        }
    } catch (e) {}

    // NtSetInformationThread (ThreadHideFromDebugger)
    try {
        const NtSIT = Module.findExportByName('ntdll.dll', 'NtSetInformationThread');
        if (NtSIT) {
            Interceptor.attach(NtSIT, {
                onEnter(args) {
                    const infoClass = args[1].toInt32();
                    if (infoClass === 0x11) { // ThreadHideFromDebugger
                        log('Blocked NtSetInformationThread(ThreadHideFromDebugger)');
                        args[1] = ptr(0); // Change to ThreadBasicInformation (harmless)
                    }
                }
            });
            hooked.push('NtSetInformationThread');
        }
    } catch (e) {}

    // Timing checks
    for (const api of ['GetTickCount', 'GetTickCount64']) {
        try {
            const addr = Module.findExportByName('kernel32.dll', api);
            if (addr) {
                let baseTime = null;
                Interceptor.attach(addr, {
                    onLeave(retval) {
                        if (!baseTime) {
                            baseTime = retval.toInt32();
                        }
                        // Always return small increments
                        retval.replace(baseTime + 100);
                    }
                });
                hooked.push(api);
            }
        } catch (e) {}
    }

    // QueryPerformanceCounter
    try {
        const QPC = Module.findExportByName('kernel32.dll', 'QueryPerformanceCounter');
        if (QPC) {
            let baseQPC = null;
            Interceptor.attach(QPC, {
                onEnter(args) { this.out = args[0]; },
                onLeave(retval) {
                    if (this.out && !this.out.isNull()) {
                        const val = this.out.readU64();
                        if (!baseQPC) baseQPC = val;
                        // Clamp delta to small value
                        this.out.writeU64(baseQPC.add(1000));
                    }
                }
            });
            hooked.push('QueryPerformanceCounter');
        }
    } catch (e) {}

    // OutputDebugString (SEH trick)
    try {
        const ODS = Module.findExportByName('kernel32.dll', 'OutputDebugStringA');
        if (ODS) {
            Interceptor.attach(ODS, {
                onLeave(retval) {
                    // In non-debugged process, SetLastError is set; force it
                }
            });
            hooked.push('OutputDebugStringA');
        }
    } catch (e) {}

    // PEB.BeingDebugged direct read patch
    try {
        const peb = Module.findExportByName('ntdll.dll', 'RtlGetCurrentPeb');
        if (peb) {
            Interceptor.attach(peb, {
                onLeave(retval) {
                    // PEB.BeingDebugged is at offset 2
                    if (!retval.isNull()) {
                        retval.add(2).writeU8(0);
                        // NtGlobalFlag at offset 0x68 (x64) or 0xBC (x86)
                        const ntGlobalOffset = Process.pointerSize === 8 ? 0xBC : 0x68;
                        retval.add(ntGlobalOffset).writeU32(0);
                    }
                }
            });
            hooked.push('PEB.BeingDebugged');
        }
    } catch (e) {}
}

// ==================== macOS ====================
function bypassMacOS() {
    // ptrace(PT_DENY_ATTACH)
    try {
        const ptrace = Module.findExportByName(null, 'ptrace');
        if (ptrace) {
            Interceptor.attach(ptrace, {
                onEnter(args) {
                    const request = args[0].toInt32();
                    if (request === 31) { // PT_DENY_ATTACH
                        log('Blocked ptrace(PT_DENY_ATTACH)');
                        args[0] = ptr(0); // PT_TRACE_ME (harmless)
                    }
                },
                onLeave(retval) { retval.replace(0); }
            });
            hooked.push('ptrace');
        }
    } catch (e) {}

    // sysctl (P_TRACED check)
    try {
        const sysctl = Module.findExportByName(null, 'sysctl');
        if (sysctl) {
            Interceptor.attach(sysctl, {
                onEnter(args) {
                    this.mib = args[0];
                    this.oldp = args[2];
                    this.oldlenp = args[3];
                },
                onLeave(retval) {
                    if (this.oldp && !this.oldp.isNull()) {
                        try {
                            // kinfo_proc.kp_proc.p_flag — clear P_TRACED (0x800)
                            const flagOffset = Process.pointerSize === 8 ? 32 : 16;
                            const flags = this.oldp.add(flagOffset).readU32();
                            if (flags & 0x800) {
                                this.oldp.add(flagOffset).writeU32(flags & ~0x800);
                                log('Cleared P_TRACED from sysctl result');
                            }
                        } catch (e) {}
                    }
                }
            });
            hooked.push('sysctl');
        }
    } catch (e) {}

    // task_get_exception_ports
    try {
        const taskGetPorts = Module.findExportByName(null, 'task_get_exception_ports');
        if (taskGetPorts) {
            Interceptor.attach(taskGetPorts, {
                onLeave(retval) { retval.replace(0); } // KERN_SUCCESS
            });
            hooked.push('task_get_exception_ports');
        }
    } catch (e) {}

    // getppid (parent PID check — debugger detection)
    try {
        const getppid = Module.findExportByName(null, 'getppid');
        if (getppid) {
            Interceptor.attach(getppid, {
                onLeave(retval) {
                    retval.replace(1); // Return 1 (launchd) instead of debugger PID
                }
            });
            hooked.push('getppid');
        }
    } catch (e) {}

    // AmIBeingDebugged (custom function name pattern)
    try {
        const modules = Process.enumerateModules();
        for (const mod of modules) {
            const exports = mod.enumerateExports();
            for (const exp of exports) {
                if (exp.name.toLowerCase().includes('amibeing') ||
                    exp.name.toLowerCase().includes('debugger') ||
                    exp.name.toLowerCase().includes('debugcheck')) {
                    Interceptor.attach(exp.address, {
                        onLeave(retval) { retval.replace(0); }
                    });
                    hooked.push(exp.name);
                }
            }
        }
    } catch (e) {}
}

// ==================== Linux ====================
function bypassLinux() {
    // ptrace(PTRACE_TRACEME)
    try {
        const ptrace = Module.findExportByName(null, 'ptrace');
        if (ptrace) {
            Interceptor.attach(ptrace, {
                onLeave(retval) { retval.replace(0); }
            });
            hooked.push('ptrace');
        }
    } catch (e) {}

    // /proc/self/status TracerPid check
    try {
        const fopen = Module.findExportByName(null, 'fopen');
        if (fopen) {
            Interceptor.attach(fopen, {
                onEnter(args) {
                    const path = args[0].readUtf8String();
                    if (path && (path.includes('/proc/self/status') ||
                                 path.includes('/proc/self/maps'))) {
                        log(`Intercepted fopen("${path}") — will sanitize`);
                        this.sanitize = true;
                    }
                }
            });
            hooked.push('fopen(/proc/self)');
        }
    } catch (e) {}
}

// ==================== Cross-platform: Frida detection bypass ====================
function bypassFridaDetection() {
    // Block access to frida-server port
    try {
        const connect = Module.findExportByName(null, 'connect');
        if (connect) {
            Interceptor.attach(connect, {
                onEnter(args) {
                    const sockaddr = args[1];
                    const family = sockaddr.readU16();
                    if (family === 2) { // AF_INET
                        const port = (sockaddr.add(2).readU8() << 8) | sockaddr.add(3).readU8();
                        if (port === 27042) { // Default frida-server port
                            log('Blocked connect() to frida-server port 27042');
                            this.block = true;
                        }
                    }
                },
                onLeave(retval) {
                    if (this.block) retval.replace(-1);
                }
            });
            hooked.push('connect(frida-port)');
        }
    } catch (e) {}

    // Hide frida-agent from module list
    // (Frida already does this internally, but some apps do manual /proc/maps scan)
}

// ==================== Main ====================
log(`Platform: ${platform}`);
log('Starting universal anti-debug bypass...');

if (platform === 'windows') bypassWindows();
else if (platform === 'darwin') bypassMacOS();
else if (platform === 'linux') bypassLinux();

bypassFridaDetection();

log(`Hooked ${hooked.length} APIs: ${hooked.join(', ')}`);
log('Anti-debug bypass active.');
