"use strict";

const green = "\x1b[1;36m"
const reset = "\x1b[0m"

let allocatedBuffers = [];
let originalPageProtections = new Map();

// DLLs-related
let skipDllOepInstr32 = null;
let skipDllOepInstr64 = null;
let dllOepCandidate = null;

// TLS-related
let skipTlsInstr32 = null;
let skipTlsInstr64 = null;
let tlsCallbackCount = 0;

function log(message) {
    console.log(`${green}frida-agent${reset}: ${message}`);
}

function initializeTrampolines() {
    const instructionsBytes = new Uint8Array([
        0xC3,                                          // ret
        0xC2, 0x0C, 0x00,                              // ret 0x0C
        0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3,            // mov eax, 1; ret
        0xB8, 0x01, 0x00, 0x00, 0x00, 0xC2, 0x0C, 0x00 // mov eax, 1; ret 0x0C
    ]);

    let bufferPointer = Memory.alloc(instructionsBytes.length);
    Memory.protect(bufferPointer, instructionsBytes.length, 'rwx');
    bufferPointer.writeByteArray(instructionsBytes.buffer);

    skipTlsInstr64 = bufferPointer;
    skipTlsInstr32 = bufferPointer.add(0x1);
    skipDllOepInstr64 = bufferPointer.add(0x4);
    skipDllOepInstr32 = bufferPointer.add(0xA);
}

function rangeContainsAddress(range, address) {
    const rangeStart = range.base;
    const rangeEnd = range.base.add(range.size);
    return rangeStart.compare(address) <= 0 && rangeEnd.compare(address) > 0;
}

function notifyOepFound(dumpedModule, oepCandidate) {
    let isDotNetInitialized = isDotNetProcess();
    send({ 'event': 'oep_reached', 'OEP': oepCandidate, 'BASE': dumpedModule.base, 'DOTNET': isDotNetInitialized })
    let sync_op = recv('block_on_oep', function (_value) { });
    sync_op.wait();
}

function isDotNetProcess() {
    return Process.findModuleByName("clr.dll") != null;
}

function changePageProtectionsAndRegisterExceptionHandler(dumpedModule, expectedOepRanges, moduleIsDll) {
    // Ensure potential OEP ranges are not executable by default
    expectedOepRanges.forEach((oepRange) => {
        const sectionStart = dumpedModule.base.add(oepRange[0]);
        const expectedSectionSize = oepRange[1];
        Memory.protect(sectionStart, expectedSectionSize, 'rw-');
        originalPageProtections.set(sectionStart.toString(), [expectedSectionSize, "r-x"]);
    });

    // Register an exception handler that'll detect the OEP
    Process.setExceptionHandler(exp => {
        let expectionHandled = false;
        let oepCandidate = exp.context.pc;
        expectedOepRanges.forEach((oepRange) => {
            const sectionStart = dumpedModule.base.add(oepRange[0]);
            const sectionSize = oepRange[1];
            const sectionRange = { base: sectionStart, size: sectionSize };

            if (rangeContainsAddress(sectionRange, oepCandidate)) {
                // If we're in a TLS callback, the first argument is the
                // module's base address
                if (!moduleIsDll && isTlsCallback(exp.context, dumpedModule)) {
                    log(`TLS callback #${tlsCallbackCount} detected (at ${exp.context.pc}), skipping ...`);
                    tlsCallbackCount++;

                    // Modify PC to skip the callback's execution and return
                    skipTlsCallback(exp.context);
                    expectionHandled = true;
                    return;
                }

                // Restore pages' intended protections
                originalPageProtections.forEach((pair, address_str, _map) => {
                    let size = pair[0];
                    let originalProtection = pair[1];
                    Memory.protect(ptr(address_str), size, originalProtection);
                });

                let threadId = Process.getCurrentThreadId();
                log(`OEP found (thread #${threadId}): ${oepCandidate}`);
                if (moduleIsDll) {
                    // Save the potential OEP and and skip `DllMain` (`DLL_PROCESS_ATTACH`).
                    // Note: When dumping DLLs we have to release the loader
                    // lock before starting to dump.
                    // Other threads might call `DllMain` with the `DLL_THREAD_ATTACH`
                    // reason later on but it's okay.
                    dllOepCandidate = oepCandidate;
                    skipDllEntryPoint(exp.context);
                    expectionHandled = true;
                    return;
                }

                // Report the potential OEP
                notifyOepFound(dumpedModule, oepCandidate);
            }
        });

        return expectionHandled;
    });
    log("Exception handler registered");
}

function isTlsCallback(exceptionCtx, dumpedModule) {
    if (Process.arch == "x64") {
        // If we're in a TLS callback, the first argument is the
        // module's base address
        let moduleBase = exceptionCtx.rcx;
        if (!moduleBase.equals(dumpedModule.base)) {
            return false;
        }
        // If we're in a TLS callback, the first argument is the
        // reason (from 0 to 3).
        let reason = exceptionCtx.rdx;
        if (reason.compare(ptr(4)) > 0) {
            return false;
        }
    }
    else if (Process.arch == "ia32") {
        let sp = exceptionCtx.sp;

        let moduleBase = sp.add(0x4).readPointer();
        if (!moduleBase.equals(dumpedModule.base)) {
            return false;
        }
        let reason = sp.add(0x8).readPointer();
        if (reason.compare(ptr(4)) > 0) {
            return false;
        }
    } else {
        return false;
    }

    return true;
}

function skipTlsCallback(exceptionCtx) {
    if (Process.arch == "x64") {
        // Redirect to a `ret` instruction
        exceptionCtx.rip = skipTlsInstr64;
    }
    else if (Process.arch == "ia32") {
        // Redirect to a `ret 0xC` instruction
        exceptionCtx.eip = skipTlsInstr32;
    }
}

function skipDllEntryPoint(exceptionCtx) {
    if (Process.arch == "x64") {
        // Redirect to a `mov eax, 1; ret` instructions
        exceptionCtx.rip = skipDllOepInstr64;
    }
    else if (Process.arch == "ia32") {
        // Redirect to a `mov eax, 1; ret 0xC` instructions
        exceptionCtx.eip = skipDllOepInstr32;
    }
}

function walk_back_stack_for_oep(context, module) {
    const backtrace = Thread.backtrace(context, Backtracer.FUZZY);
    if (backtrace.length == 0) {
        return null;
    }

    const originalTextSection = Process.findRangeByAddress(backtrace[0]);
    if (originalTextSection == null) {
        return null;
    }

    const moduleStart = module.base;
    const moduleEnd = module.base.add(module.size);
    if (moduleStart.compare(originalTextSection.base) > 0 || moduleEnd.compare(originalTextSection.base) <= 0) {
        return null;
    }

    let oepCandidate = null;
    const textSectionStart = originalTextSection.base;
    const textSectionEnd = originalTextSection.base.add(originalTextSection.size);
    backtrace.forEach(addr => {
        if (textSectionStart.compare(addr) <= 0 && textSectionEnd.compare(addr) > 0) {
            oepCandidate = addr;
        }
    });
    return oepCandidate;
}

// Define available RPCs
rpc.exports = {
    setupOepTracing: function (moduleName, expectedOepRanges) {
        log(`Setting up OEP tracing for "${moduleName}"`);

        let targetIsDll = moduleName.endsWith(".dll");
        let dumpedModule = null;
        let exceptionHandlerRegistered = false;
        let queryPerformanceCounterHooked = false;
        let corExeMainHooked = false;

        initializeTrampolines();

        // If the target isn't a DLL, it should be loaded already
        if (!targetIsDll) {
            dumpedModule = Process.findModuleByName(moduleName);
            if (dumpedModule != null) {
                changePageProtectionsAndRegisterExceptionHandler(dumpedModule, expectedOepRanges, targetIsDll);
            }
        }

        // Hook `ntdll.LdrLoadDll` on exit to get called at a point where the
        // loader lock is released. Needed to unpack (32-bit) DLLs.
        const loadDll = Module.findExportByName('ntdll', 'LdrLoadDll');
        Interceptor.attach(loadDll, {
            onLeave: function (_args) {
                // If `dllOepCandidate` is set, proceed with the dumping
                if (dllOepCandidate != null) {
                    notifyOepFound(dumpedModule, dllOepCandidate);
                }
            }
        });

        // Hook `ntdll.RtlActivateActivationContextUnsafeFast` on exit as a mean
        // to get called after new PE images are loaded and before their entry
        // point is called. Needed to unpack DLLs.
        const activateActivationContext = Module.findExportByName('ntdll', 'RtlActivateActivationContextUnsafeFast');
        Interceptor.attach(activateActivationContext, {
            onLeave: function (_args) {
                if (dumpedModule == null) {
                    dumpedModule = Process.findModuleByName(moduleName);
                    if (dumpedModule == null) {
                        // Module isn't loaded yet
                        return;
                    }
                    log(`Target module has been loaded (thread #${this.threadId}) ...`);
                }
                // After this, the target module is loaded.

                if (targetIsDll) {
                    if (!exceptionHandlerRegistered) {
                        changePageProtectionsAndRegisterExceptionHandler(dumpedModule, expectedOepRanges, targetIsDll);
                        exceptionHandlerRegistered = true;
                    }
                }

                // Hook `kernel32.QueryPerformanceCounter` if present.
                // This is used to detect an approximation of the entry point
                // of Delphi executables which are not propely handled yet.
                const queryPerformanceCounter = Module.findExportByName('kernel32', 'QueryPerformanceCounter');
                if (queryPerformanceCounter != null && !queryPerformanceCounterHooked) {
                    Interceptor.attach(queryPerformanceCounter, {
                        onEnter: function (_args) {
                            let oepCandidate = walk_back_stack_for_oep(this.context, dumpedModule);
                            if (oepCandidate != null) {
                                // "Rewind" call/jmp
                                oepCandidate = oepCandidate.sub(5);
                                log(`Potential OEP (thread #${this.threadId}): ${oepCandidate} (inaccurate)`);
                                notifyOepFound(dumpedModule, oepCandidate);
                            }
                        }
                    });
                    queryPerformanceCounterHooked = true;
                }

                // Hook `clr.InitializeFusion` if present.
                // This is used to detect a good point during the CLR's
                // initialization, to dump .NET EXE assemblies
                const corExeMain = Module.findExportByName('clr', 'InitializeFusion');
                if (corExeMain != null && !corExeMainHooked) {
                    Interceptor.attach(corExeMain, {
                        onEnter: function (_args) {
                            log(`.NET assembly loaded (thread #${this.threadId})`);
                            notifyOepFound(dumpedModule, '0');
                        }
                    });
                    corExeMainHooked = true;
                }
            }
        });
    },
    getArchitecture: function () { return Process.arch; },
    getPointerSize: function () { return Process.pointerSize; },
    getPageSize: function () { return Process.pageSize; },
    findModuleByAddress: function (address) {
        let module = Process.findModuleByAddress(ptr(address));
        return module == null ? undefined : module;
    },
    findRangeByAddress: function (address) {
        let range = Process.findRangeByAddress(ptr(address));
        return range == null ? undefined : range;
    },
    findExportByName: function (module_name, export_name) {
        let mod = Process.findModuleByName(module_name);
        if (mod == null) {
            return undefined;
        }

        let address = mod.findExportByName(export_name);
        return address == null ? undefined : address;
    },
    enumerateModules: function () {
        const modules = Process.enumerateModules();
        let moduleNames = [];
        modules.forEach(module => {
            moduleNames = moduleNames.concat(module.name);
        });
        return moduleNames;
    },
    enumerateModuleRanges: function (moduleName) {
        let ranges = Process.enumerateRangesSync("r--");
        return ranges.filter(range => {
            const module = Process.findModuleByAddress(range.base);
            return module != null && module.name.toUpperCase() == moduleName.toUpperCase();
        });
    },
    enumerateExportedFunctions: function (excludedModuleName) {
        const modules = Process.enumerateModules();
        let exports = [];
        modules.forEach(m => {
            if (m.name != excludedModuleName) {
                m.enumerateExports().forEach(e => {
                    if (e.type == "function") {
                        exports = exports.concat(e);
                    }
                });
            }
        });
        return exports;
    },
    allocateProcessMemory: function (size, near) {
        let sizeRounded = size + (Process.pageSize - size % Process.pageSize);
        let addr = Memory.alloc(sizeRounded, { near: ptr(near), maxDistance: 0xff000000 });
        allocatedBuffers.push(addr)
        return addr;
    },
    queryMemoryProtection: function (address) {
        return Process.getRangeByAddress(ptr(address))['protection'];
    },
    setMemoryProtection: function (address, size, protection) {
        return Memory.protect(ptr(address), size, protection);
    },
    readProcessMemory: function (address, size) {
        return Memory.readByteArray(ptr(address), size);
    },
    writeProcessMemory: function (address, bytes) {
        return Memory.writeByteArray(ptr(address), bytes);
    }
};
