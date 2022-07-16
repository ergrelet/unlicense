"use strict";

const green = "\x1b[1;36m"
const reset = "\x1b[0m"

let allocatedBuffers = [];
let originalPageProtections = new Map();

// TLS-related
let skipTlsInstr32 = null;
let skipTlsInstr64 = null;
let tlsCallbackCount = 0;

function log(message) {
    console.log(`${green}frida-agent${reset}: ${message}`);
}

function initializeTlsTrampolines() {
    // ret; ret 0xC
    const instructionsBytes = new Uint8Array([0xC3, 0xC2, 0x0C, 0x00]);

    let bufferPointer = Memory.alloc(instructionsBytes.length);
    Memory.protect(bufferPointer, instructionsBytes.length, 'rwx');
    bufferPointer.writeByteArray(instructionsBytes.buffer);

    skipTlsInstr64 = bufferPointer;
    skipTlsInstr32 = bufferPointer.add(0x1);
}

function rangeContainsAddress(range, address) {
    const rangeStart = range.base;
    const rangeEnd = range.base.add(range.size);
    return rangeStart.compare(address) <= 0 && rangeEnd.compare(address) > 0;
}

function isDotNetProcess() {
    return Process.findModuleByName("clr.dll") != null;
}

function changePageProtectionsAndRegisterExceptionHandler(dumpedModule, expectedOepRanges, moduleIsDll) {
    // Ensure potential OEP ranges are not executable by default
    expectedOepRanges.forEach((oepRange) => {
        let textSectionStart = dumpedModule.base.add(oepRange[0]);
        let textSectionSize = oepRange[1];
        Memory.protect(textSectionStart, textSectionSize, 'rw-');
        originalPageProtections.set(textSectionStart.toString(), [textSectionSize, "r-x"]);
    });

    // Register an exception handler that'll detect the OEP
    Process.setExceptionHandler(exp => {
        let expectionHandled = false;
        let oepCandidate = exp.context.pc;
        expectedOepRanges.forEach((oepRange) => {
            let textSectionStart = dumpedModule.base.add(oepRange[0]);
            let textSectionSize = oepRange[1];
            let textSectionRange = { base: textSectionStart, size: textSectionSize };

            if (rangeContainsAddress(textSectionRange, oepCandidate)) {
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
                log(`Potential OEP: ${oepCandidate}`);

                // Restore pages' intended protections
                originalPageProtections.forEach((pair, address_str, _map) => {
                    let size = pair[0];
                    let originalProtection = pair[1];
                    Memory.protect(ptr(address_str), size, originalProtection);
                });

                // Report the potential OEP
                let isDotNetInitialized = isDotNetProcess();
                send({ 'event': 'oep_reached', 'OEP': oepCandidate, 'BASE': dumpedModule.base, 'DOTNET': isDotNetInitialized })
                let sync_op = recv('block_on_oep', function (_value) { });
                sync_op.wait();
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

        initializeTlsTrampolines();

        // If the target isn't a DLL, it should be loaded already
        if (!targetIsDll) {
            dumpedModule = Process.findModuleByName(moduleName);
            if (dumpedModule != null) {
                changePageProtectionsAndRegisterExceptionHandler(dumpedModule, expectedOepRanges, targetIsDll);
            }
        }

        // Hook `ntdll.NtMapViewOfSection` as a mean to get called when new PE
        // images are loaded. Needed to unpack DLLs.
        const ntMapViewOfSection = Module.findExportByName('ntdll', 'NtMapViewOfSection');
        Interceptor.attach(ntMapViewOfSection, {
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
                                log(`Potential OEP (thread #${this.threadId}): ${oepCandidate}`);
                                send({ 'event': 'oep_reached', 'OEP': oepCandidate, 'BASE': dumpedModule.base, 'DOTNET': false })
                                let sync_op = recv('block_on_oep', function (_value) { });
                                sync_op.wait();
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
                            log(`Potential .NET assembly entry (thread #${this.threadId})`);
                            send({ 'event': 'oep_reached', 'OEP': '0', 'BASE': dumpedModule.base, 'DOTNET': true })
                            let sync_op = recv('block_on_oep', function (_value) { });
                            sync_op.wait();
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
    enumerateExportedFunctions: function () {
        const modules = Process.enumerateModules();
        let exports = [];
        modules.forEach(module => {
            exports = exports.concat(module.enumerateExports());
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
