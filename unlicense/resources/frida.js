"use strict";

const green = "\x1b[1;36m"
const reset = "\x1b[0m"

let allocatedBuffers = [];
let originalPageProtections = new Map();

function log(message) {
    console.log(`${green}frida-agent${reset}: ${message}`);
}

function rangeContainsAddress(range, address) {
    const rangeStart = range.base;
    const rangeEnd = range.base.add(range.size);
    return rangeStart.compare(address) <= 0 && rangeEnd.compare(address) > 0;
}

function isDotNetProcess() {
    return Process.findModuleByName("clr.dll") != null;
}

function changePageProtectionsAndRegisterExceptionHandler(dumpedModule, expectedOepRanges) {
    // Ensure potential OEP ranges are not executable by default
    expectedOepRanges.forEach((oepRange) => {
        let textSectionStart = dumpedModule.base.add(oepRange[0]);
        let textSectionSize = oepRange[1];
        Memory.protect(textSectionStart, textSectionSize, 'rw-');
        originalPageProtections.set(textSectionStart.toString(), [textSectionSize, "r-x"]);
    });

    // Register an exception handler that'll detect the OEP
    Process.setExceptionHandler(exp => {
        let oepCandidate = exp.context.pc;

        expectedOepRanges.forEach((oepRange) => {
            let textSectionStart = dumpedModule.base.add(oepRange[0]);
            let textSectionSize = oepRange[1];
            let textSectionRange = { base: textSectionStart, size: textSectionSize };

            if (rangeContainsAddress(textSectionRange, oepCandidate)) {
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

        return false;
    });
    log("Exception handler registered");
}

// Define available RPCs
rpc.exports = {
    setupOepTracing: function (moduleName, expectedOepRanges) {
        log(`Setting up OEP tracing for "${moduleName}"`);

        let targetIsDll = moduleName.endsWith(".dll");
        let dumpedModule = null;
        let exceptionHandlerRegistered = false;
        let corExeMainHooked = false;

        // If the target isn't a DLL, it should be loaded already
        if (!targetIsDll) {
            dumpedModule = Process.findModuleByName(moduleName);
            if (dumpedModule != null) {
                changePageProtectionsAndRegisterExceptionHandler(dumpedModule, expectedOepRanges);
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
                        changePageProtectionsAndRegisterExceptionHandler(dumpedModule, expectedOepRanges);
                        exceptionHandlerRegistered = true;
                    }
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
