"use strict";

let allocated_buffers = [];

function log(message) {
    console.log(`frida-agent: ${message}`);
}

function walk_back_stack_for_oep(context, module) {
    const module_image_start = module.base;
    const module_image_end = module.base.add(module.size);
    let backtrace = Thread.backtrace(context, Backtracer.ACCURATE);
    let oep_candidate = null;
    backtrace.forEach(addr => {
        if (module_image_start.compare(addr) <= 0 && module_image_end.compare(addr) > 0) {
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
    enumerateModuleRanges: function (module_name) {
        let ranges = Process.enumerateRangesSync("r--");
        return ranges.filter(range => {
            const module = Process.findModuleByAddress(range.base);
            return module != null && module.name.localeCompare(module_name) == 0;
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
    readProcessMemory: function (address, size) {
        return Memory.readByteArray(ptr(address), size);
    },
    writeProcessMemory: function (address, bytes) {
        return Memory.writeByteArray(ptr(address), bytes);
    }
};
