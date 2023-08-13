"use strict";

const green = "\x1b[1;36m"
const reset = "\x1b[0m"

let allocatedBuffers = [];
let originalPageProtections = new Map();
let oepTracingListeners = [];
let oepReached = false;

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
    oepReached = true;
    
    // Make OEP ranges readable and writeable during the dumping phase
    setOepRangesProtection('rw-');
    // Remove hooks used to find the OEP
    removeOepTracingHooks();

    let isDotNetInitialized = isDotNetProcess();
    send({ 'event': 'oep_reached', 'OEP': oepCandidate, 'BASE': dumpedModule.base, 'DOTNET': isDotNetInitialized })
    let sync_op = recv('block_on_oep', function (_value) { });
    // Note: never returns
    sync_op.wait();
}

function isDotNetProcess() {
    return Process.findModuleByName("clr.dll") != null;
}

function makeOepRangesInaccessible(dumpedModule, expectedOepRanges) {
    // Ensure potential OEP ranges are not accessible
    expectedOepRanges.forEach((oepRange) => {
        const sectionStart = dumpedModule.base.add(oepRange[0]);
        const expectedSectionSize = oepRange[1];
        Memory.protect(sectionStart, expectedSectionSize, '---');
        originalPageProtections.set(sectionStart.toString(), expectedSectionSize);
    });
}

function setOepRangesProtection(protection) {
    // Set pages' protection
    originalPageProtections.forEach((size, address_str, _map) => {
        Memory.protect(ptr(address_str), size, protection);
    });
}

function removeOepTracingHooks() {
    oepTracingListeners.forEach(listener => {
        listener.detach();
    })
    oepTracingListeners = [];
}

function registerExceptionHandler(dumpedModule, expectedOepRanges, moduleIsDll) {
    // Register an exception handler that'll detect the OEP
    Process.setExceptionHandler(exp => {
        let oepCandidate = exp.context.pc;
        let threadId = Process.getCurrentThreadId();

        if (exp.memory != null) {
            // Weird case where executing code actually only triggers a "read"
            // access violation on inaccessible pages. This can happen on some
            // 32-bit executables.
            if (exp.memory.operation == "read" && exp.memory.address.equals(exp.context.pc)) {
                // If we're in a TLS callback, the first argument is the
                // module's base address
                if (!moduleIsDll && isTlsCallback(exp.context, dumpedModule)) {
                    log(`TLS callback #${tlsCallbackCount} detected (at ${exp.context.pc}), skipping ...`);
                    tlsCallbackCount++;

                    // Modify PC to skip the callback's execution and return
                    skipTlsCallback(exp.context);
                    return true;
                }

                log(`OEP found (thread #${threadId}): ${oepCandidate}`);
                // Report the potential OEP
                notifyOepFound(dumpedModule, oepCandidate);
            }

            // If the access violation is not an execution, "allow" the operation.
            // Note: Pages will be reprotected on the next call to
            // `NtProtectVirtualMemory`.
            if (exp.memory.operation != "execute") {
                Memory.protect(exp.memory.address, Process.pageSize, "rw-");
                return true;
            }
        }

        let expectionHandled = false;
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
                
                if (moduleIsDll) {
                    // Save the potential OEP and and skip `DllMain` (`DLL_PROCESS_ATTACH`).
                    // Note: When dumping DLLs we have to release the loader
                    // lock before starting to dump.
                    // Other threads might call `DllMain` with the `DLL_THREAD_ATTACH`
                    // or `DLL_THREAD_DETACH` reasons later so we also skip the `DllMain`
                    // even after the OEP has been reached.
                    if (!oepReached) {
                        log(`OEP found (thread #${threadId}): ${oepCandidate}`);
                        dllOepCandidate = oepCandidate;
                    } 

                    skipDllEntryPoint(exp.context);
                    expectionHandled = true;
                    return;
                }

                // Report the potential OEP
                log(`OEP found (thread #${threadId}): ${oepCandidate}`);
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
        // If we're in a TLS callback, the second argument is the
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

// Define available RPCs
rpc.exports = {
    setupOepTracing: function (moduleName, expectedOepRanges) {
        log(`Setting up OEP tracing for "${moduleName}"`);

        let targetIsDll = moduleName.endsWith(".dll");
        let dumpedModule = null;

        initializeTrampolines();

        // If the target isn't a DLL, it should be loaded already
        if (!targetIsDll) {
            dumpedModule = Process.findModuleByName(moduleName);
        }

        // Hook `ntdll.LdrLoadDll` on exit to get called at a point where the
        // loader lock is released. Needed to unpack (32-bit) DLLs.
        const loadDll = Module.findExportByName('ntdll', 'LdrLoadDll');
        const loadDllListener = Interceptor.attach(loadDll, {
            onLeave: function (_args) {
                // If `dllOepCandidate` is set, proceed with the dumping
                // but only once (for our target). Then let other executions go
                // through as it's not DLLs we're intersted in.
                if (dllOepCandidate != null && !oepReached) {
                    notifyOepFound(dumpedModule, dllOepCandidate);
                }
            }
        });
        oepTracingListeners.push(loadDllListener);

        let exceptionHandlerRegistered = false;
        const ntProtectVirtualMemory = Module.findExportByName('ntdll', 'NtProtectVirtualMemory');
        if (ntProtectVirtualMemory != null) {
            const ntProtectVirtualMemoryListener = Interceptor.attach(ntProtectVirtualMemory, {
                onEnter: function (args) {
                    let addr = args[1].readPointer();
                    if (dumpedModule != null && addr.equals(dumpedModule.base)) {
                        // Reset potential OEP ranges to not accessible to
                        // (hopefully) catch the entry point next time.
                        makeOepRangesInaccessible(dumpedModule, expectedOepRanges);
                        if (!exceptionHandlerRegistered) {
                            registerExceptionHandler(dumpedModule, expectedOepRanges, targetIsDll);
                            exceptionHandlerRegistered = true;
                        }
                    }
                }
            });
            oepTracingListeners.push(ntProtectVirtualMemoryListener);
        }

        // Hook `ntdll.RtlActivateActivationContextUnsafeFast` on exit as a mean
        // to get called after new PE images are loaded and before their entry
        // point is called. Needed to unpack DLLs.
        let initializeFusionHooked = false;
        const activateActivationContext = Module.findExportByName('ntdll', 'RtlActivateActivationContextUnsafeFast');
        const activateActivationContextListener = Interceptor.attach(activateActivationContext, {
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
                        makeOepRangesInaccessible(dumpedModule, expectedOepRanges);
                        registerExceptionHandler(dumpedModule, expectedOepRanges, targetIsDll);
                        exceptionHandlerRegistered = true;
                    }
                }

                // Hook `clr.InitializeFusion` if present.
                // This is used to detect a good point during the CLR's
                // initialization, to dump .NET EXE assemblies
                const initializeFusion = Module.findExportByName('clr', 'InitializeFusion');
                if (initializeFusion != null && !initializeFusionHooked) {
                    const initializeFusionListener = Interceptor.attach(initializeFusion, {
                        onEnter: function (_args) {
                            log(`.NET assembly loaded (thread #${this.threadId})`);
                            notifyOepFound(dumpedModule, '0');
                        }
                    });
                    oepTracingListeners.push(initializeFusionListener);
                    initializeFusionHooked = true;
                }
            }
        });
        oepTracingListeners.push(activateActivationContextListener);
    },
    notifyDumpingFinished: function () {
        // Make OEP executable again once dumping is finished
        setOepRangesProtection('rwx');
    },
    getArchitecture: function () { return Process.arch; },
    getPointerSize: function () { return Process.pointerSize; },
    getPageSize: function () { return Process.pageSize; },
    findModuleByAddress: function (address) {
        return Process.findModuleByAddress(ptr(address));
    },
    findRangeByAddress: function (address) {
        return Process.findRangeByAddress(ptr(address));
    },
    findExportByName: function (moduleName, exportName) {
        const mod = Process.findModuleByName(moduleName);
        if (mod == null) {
            return null;
        }

        return mod.findExportByName(exportName);
    },
    enumerateModules: function () {
        const modules = Process.enumerateModules();
        const moduleNames = modules.map(module => {
            return module.name;
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
        const exports = modules.reduce((acc, m) => {
            if (m.name != excludedModuleName) {
                m.enumerateExports().forEach(e => {
                    if (e.type == "function" && e.hasOwnProperty('address')) {           
                        acc.push(e);
                    }
                });
            }

            return acc;
        }, []);
        return exports;
    },
    allocateProcessMemory: function (size, near) {
        const sizeRounded = size + (Process.pageSize - size % Process.pageSize);
        const addr = Memory.alloc(sizeRounded, { near: ptr(near), maxDistance: 0xff000000 });
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
