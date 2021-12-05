"use strict";

let allocated_buffers = [];

function log(message) {
    console.log(`frida-agent: ${message}`);
}

function walk_back_stack_for_oep(context, module) {
    const backtrace = Thread.backtrace(context, Backtracer.FUZZY);
    if (backtrace.length == 0) {
        return null;
    }

    const original_text_section = Process.findRangeByAddress(backtrace[0]);
    if (original_text_section == null) {
        return null;
    }

    const module_start = module.base;
    const module_end = module.base.add(module.size);
    if (module_start.compare(original_text_section.base) > 0 || module_end.compare(original_text_section.base) <= 0) {
        return null;
    }

    let oep_candidate = null;
    const text_section_start = original_text_section.base;
    const text_section_end = original_text_section.base.add(original_text_section.size);
    backtrace.forEach(addr => {
        if (text_section_start.compare(addr) <= 0 && text_section_end.compare(addr) > 0) {
            oep_candidate = addr;
        }
    });
    return oep_candidate;
}

function compute_real_oep(oep_candidate) {
    if (Process.arch == "ia32") {
        // Note: This assumes the OEP looks like this (MSVC) and `oep_candidate`
        // is located after the call:
        //   call __security_init_cookie
        //   jmp __tmainCRTStartup
        return oep_candidate.sub(5);
    } else if (Process.arch == "x64") {
        // Note: This assumes the OEP looks like this (MSVC) and `oep_candidate`
        // is located after the call:
        //   sub rsp, 0x28
        //   call __security_init_cookie
        //   add rsp, 0x28
        //   jmp __tmainCRTStartup
        return oep_candidate.sub(9);
    } else {
        // FIXME
        return oep_candidate;
    }
}

// Define available RPCs
rpc.exports = {
    setupOepTracing: function (module_name) {
        const dumped_module = Process.findModuleByName(module_name);
        if (dumped_module == null) {
            log('Invalid module specified');
            return;
        }

        log(`Setting up OEP tracing for "${module_name}"`);
        const RtlQueryPerformanceCounter = Module.findExportByName('ntdll', 'RtlQueryPerformanceCounter')
        Interceptor.attach(RtlQueryPerformanceCounter, {
            onEnter: function (_args) {
                let oep_candidate = walk_back_stack_for_oep(this.context, dumped_module);
                if (oep_candidate != null) {
                    oep_candidate = compute_real_oep(oep_candidate);
                    log(`Possible OEP (thread #${this.threadId}): ${oep_candidate}`);
                    send({ 'event': 'oep_reached', 'OEP': oep_candidate, 'BASE': dumped_module.base })
                    let sync_op = recv('block_on_oep', function (_value) { });
                    sync_op.wait();
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
        let module_names = [];
        modules.forEach(module => {
            module_names = module_names.concat(module.name);
        });
        return module_names;
    },
    enumerateModuleRanges: function (module_name) {
        let ranges = Process.enumerateRangesSync("r--");
        return ranges.filter(range => {
            const module = Process.findModuleByAddress(range.base);
            return module != null && module.name.toUpperCase() == module_name.toUpperCase();
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
        let size_rounded = size + (Process.pageSize - size % Process.pageSize);
        let addr = Memory.alloc(size_rounded, { near: ptr(near), maxDistance: 0xff000000 });
        allocated_buffers.push(addr)
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
