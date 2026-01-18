import struct
import sys
from capstone import Cs, CS_ARCH_M68K, CS_MODE_BIG_ENDIAN

def disassemble_m68k(data, out_file, step=0x10000):
        md = Cs(CS_ARCH_M68K, CS_MODE_BIG_ENDIAN)
        size = len(data)
        with open(out_file, 'w') as f:
            last_addr = 0
            decoded = set()
            for insn in md.disasm(data, 0):
                # Dump undecoded bytes before this instruction
                if insn.address > last_addr:
                    undecoded = data[last_addr:insn.address]
                    for i in range(0, len(undecoded), 16):
                        hexline = ' '.join(f'{b:02X}' for b in undecoded[i:i+16])
                        f.write(f"0x{last_addr+i:08X}: {hexline}\n")
                f.write(f"0x{insn.address:08X}: {insn.mnemonic} {insn.op_str}\n")
                last_addr = insn.address + insn.size
            # Dump any remaining undecoded bytes at the end
            if last_addr < size:
                undecoded = data[last_addr:]
                for i in range(0, len(undecoded), 16):
                    hexline = ' '.join(f'{b:02X}' for b in undecoded[i:i+16])
                    f.write(f"0x{last_addr+i:08X}: {hexline}\n")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python full_disassemble.py <combined.bin> <output.txt>")
        sys.exit(1)
    with open(sys.argv[1], 'rb') as f:
        data = f.read()
    disassemble_m68k(data, sys.argv[2])
