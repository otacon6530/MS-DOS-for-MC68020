import struct
import sys
from capstone import Cs, CS_ARCH_M68K, CS_MODE_BIG_ENDIAN

def disassemble_m68k(data, pc, count=64):
    md = Cs(CS_ARCH_M68K, CS_MODE_BIG_ENDIAN)
    code = data[pc:pc+count*2]
    for i, insn in enumerate(md.disasm(code, pc)):
        print(f"0x{insn.address:08X}: {insn.mnemonic} {insn.op_str}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python disassemble_init_more.py <combined.bin>")
        sys.exit(1)
    with open(sys.argv[1], 'rb') as f:
        data = f.read()
    pc = struct.unpack_from('>I', data, 4)[0]
    print(f"Reset vector (PC): 0x{pc:08X}")
    disassemble_m68k(data, pc, count=64)
