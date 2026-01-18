--

-- cpu_stepper.lua (MAME compatible)
-- Usage:
--   mame area51 -debug -log -window -script cpu_stepper.lua

local machine = manager.machine
local cpu     = machine.devices["maincpu"]
local space   = cpu.spaces["program"]

local MAX_STEPS = 200000
local step_count = 0

-- Helper: read all D and A registers + SR
local function read_cpu_state()
    local s = cpu.state
    local regs = {}
    for i = 0, 7 do
        regs[#regs+1] = string.format("D%d=%08X", i, s["D"..i].value)
    end
    for i = 0, 7 do
        regs[#regs+1] = string.format("A%d=%08X", i, s["A"..i].value)
    end
    regs[#regs+1] = string.format("SR=%04X", s["SR"].value)
    return table.concat(regs, " ")
end

-- Optional: log all memory writes (comment out if not needed)
--[[
space:install_write_tap(0x000000, 0xFFFFFF, "trace_writes", function(offset, data, mask)
    local addr = offset
    local pc = cpu.state["PC"]
    print(string.format(
        "[MEM WRITE] PC=%08X ADDR=%08X DATA=%08X MASK=%08X",
        pc, addr, data, mask
    ))
end)
]]

emu.register_periodic(function()
    if not machine.paused then
        emu.step()
        step_count = step_count + 1
        local s = cpu.state
        local pc = s["PC"]
        print(string.format(
            "[STEP %d] PC=%08X %s",
            step_count, pc, read_cpu_state()
        ))
        if step_count >= MAX_STEPS then
            print(string.format("[TRACE COMPLETE] Reached %d steps, pausing.", MAX_STEPS))
            machine:pause()
        end
    end
end)
-- Adjust "system name" (area51) as needed.
--

-- (Removed duplicate and incorrect manager:machine() usage)
local space   = cpu.spaces["program"]

-- How many instructions to trace before auto-stop (tune as needed)
local MAX_STEPS = 200000

local step_count = 0

-- Helper: read all D and A registers + SR
local function read_cpu_state()
    local s = cpu.state

    local regs = {}

    for i = 0, 7 do
        regs[#regs+1] = string.format("D%d=%08X", i, s["D"..i])
    end
    for i = 0, 7 do
        regs[#regs+1] = string.format("A%d=%08X", i, s["A"..i])
    end

    regs[#regs+1] = string.format("SR=%04X", s["SR"])

    return table.concat(regs, " ")
end

-- Helper: detect writes to Tom register space (0x800000–0x80FFFF)
local function is_tom_addr(addr)
    return addr >= 0x800000 and addr <= 0x80FFFF
end

-- Install a memory write tap on the main CPU program space
space:install_write_tap(0x000000, 0xFFFFFF, "trace_writes", function(offset, data, mask)
    local addr = offset

    if is_tom_addr(addr) then
        local pc = cpu.state["PC"]
        print(string.format(
            "[TOM WRITE] PC=%08X ADDR=%08X DATA=%08X MASK=%08X",
            pc, addr, data, mask
        ))
    end
end)

-- (Removed duplicate per-instruction hook)