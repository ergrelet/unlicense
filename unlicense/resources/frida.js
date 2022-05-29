"use strict";

let allocatedBuffers = [];

function log(message) {
    console.log(`frida-agent: ${message}`);
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

function compute_real_oep_msvcrt(oepCandidate, isDll) {
    if (Process.arch == "ia32") {
        if (isDll) {
            // Note: This assumes the OEP looks like this (MSVC) and `oepCandidate`
            // is located after the call:
            //   push    ebp
            //   mov     ebp, esp
            //   cmp     [ebp+fdwReason], 1
            //   jnz     short loc_X
            //   call    __security_init_cookie
            return oepCandidate.sub(0xE);
        }

        // Note: This assumes the OEP looks like this (MSVC) and `oepCandidate`
        // is located after the call:
        //   call __security_init_cookie
        //   jmp __tmainCRTStartup
        return oepCandidate.sub(5);

    } else if (Process.arch == "x64") {
        if (isDll) {
            // Note: This assumes the OEP looks like this (MSVC) and `oepCandidate`
            // is located after the call:
            //   mov [rsp+8h], rbx
            //   mov [rsp+10h], rsi
            //   push rdi
            //   sub rsp, 20h
            //   mov rdi, r8
            //   mov ebx, edx
            //   mov rsi, rcx
            //   cmp edx, 1
            //   jnz short loc_X
            //   call __security_init_cookie
            return oepCandidate.sub(0x21);
        }

        // Note: This assumes the OEP looks like this (MSVC) and `oepCandidate`
        // is located after the call:
        //   sub rsp, 0x28
        //   call __security_init_cookie
        //   add rsp, 0x28
        //   jmp __tmainCRTStartup
        return oepCandidate.sub(9);

    } else {
        // FIXME
        return oepCandidate;
    }
}

// Define available RPCs
rpc.exports = {
    setupOepTracing: function (moduleName) {
        log(`Setting up OEP tracing for "${moduleName}"`);

        let isDll = moduleName.endsWith(".dll");
        let dumpedModule = null;
        let getSystemTimeAsFileTimeHooked = false;
        let corExeMainHooked = false;
        // Hook `ntdll.NtMapViewOfSection` as a mean to get called when new PE
        // images are loaded.
        const ntMapViewOfSection = Module.findExportByName('ntdll', 'NtMapViewOfSection');
        Interceptor.attach(ntMapViewOfSection, {
            onLeave: function (_args) {
                if (dumpedModule == null) {
                    dumpedModule = Process.findModuleByName(moduleName);
                    if (dumpedModule == null) {
                        // Module isn't loaded yet
                        return;
                    }
                    log("Target module is loaded ...");
                }

                // Hook `kernel32.GetSystemTimeAsFileTime` if present
                // This is used to detect the CRT entry point for EXEs compiled
                // from C, C++ (or Deplhi) 
                const getSystemTimeAsFileTime = Module.findExportByName('kernel32', 'GetSystemTimeAsFileTime');
                if (getSystemTimeAsFileTime != null && !getSystemTimeAsFileTimeHooked) {
                    Interceptor.attach(getSystemTimeAsFileTime, {
                        onEnter: function (_args) {
                            let oepCandidate = walk_back_stack_for_oep(this.context, dumpedModule);
                            if (oepCandidate != null) {
                                oepCandidate = compute_real_oep_msvcrt(oepCandidate, isDll);
                                log(`Potential OEP (thread #${this.threadId}): ${oepCandidate}`);
                                send({ 'event': 'oep_reached', 'OEP': oepCandidate, 'BASE': dumpedModule.base, 'DOTNET': false })
                                let sync_op = recv('block_on_oep', function (_value) { });
                                sync_op.wait();
                            }
                        }
                    });
                    getSystemTimeAsFileTimeHooked = true;
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
