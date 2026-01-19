-- cpu_stepper.lua (MAME compatible, 1 step/sec)
-- Usage:
--   mame area51 -debug -log -window -script cpu_stepper.lua

local machine = manager.machine
local debugger = manager.machine.debugger
local cpu     = machine.devices[":maincpu"]
local log_file = assert(io.open("cpu_log.txt", "w"))
local step_count = 0
local log_buffer = {}
local buffer_size = 1000 -- flush every 1000 lines

local function read_cpu_state()
    local s = cpu.state
    local regs = {}
    for i = 0, 7 do regs[#regs+1] = string.format("D%d=%08X", i, s["D"..i].value) end
    for i = 0, 7 do regs[#regs+1] = string.format("A%d=%08X", i, s["A"..i].value) end
    regs[#regs+1] = string.format("SR=%04X", s["SR"].value)
    return table.concat(regs, " ")
end

local last_time = os.time()

local function log_disasm(pc)
    -- Try to get disassembly for the current PC
    local disasm = ""
    if cpu.debug and cpu.debug.disassemble then
        disasm = cpu.debug:disassemble(pc)
    end
    return disasm
end

local function log_mem(addr, len)
    -- Log a memory region (hex dump)
    local mem = {}
    for i = 0, len-1 do
        local byte = cpu.spaces["program"]:read_u8(addr + i)
        mem[#mem+1] = string.format("%02X", byte)
    end
    return table.concat(mem, " ")
end

local function flush_log()
    if #log_buffer > 0 then
        log_file:write(table.concat(log_buffer, "\n").."\n")
        log_file:flush()
        print(string.format("[cpu_stepper] Flushed %d log lines", #log_buffer))
        log_buffer = {}
    end
end

local function step_instruction()
    step_count = step_count + 1
    manager.machine.debugger:command('step')
    local s = cpu.state
    local pc = s["PC"].value
    local disasm = log_disasm(pc)
    local memdump = log_mem(pc, 16)
    local line = string.format("[STEP %d] PC=%08X %s\nDISASM: %s\nMEM: %s", step_count, pc, read_cpu_state(), disasm, memdump)
    log_buffer[#log_buffer+1] = line
    if #log_buffer >= buffer_size or step_count % 100 == 0 then
        flush_log()
    end
end

for tag, device in pairs(manager.machine.devices) do
    local has_debug = device.debug and " (debug available)" or ""
    print(tag .. has_debug)
end


emu.register_periodic(function()
    if not machine.paused then
        step_instruction()
    end
end)


-- No register_exit_callback; flush buffer if needed in periodic