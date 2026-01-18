import struct
import sys

# Usage: python dump_init.py a51_2-c.hh
# Dumps the 68k reset vector and first instructions

def dump_init(filename):
    with open(filename, 'rb') as f:
        data = f.read()
    size = len(data)
    print(f"ROM size: {size} bytes")

    # 68k vectors: first 8 bytes (SP, PC)
    sp = struct.unpack_from('>I', data, 0)[0]
    pc = struct.unpack_from('>I', data, 4)[0]
    print(f"Initial SP: 0x{sp:08X}")
    print(f"Reset vector (PC): 0x{pc:08X}")

    # Dump first 32 bytes of code at PC
    code_off = pc & (size - 1)  # mask for ROM size
    print(f"Code at PC (offset 0x{code_off:X}):")
    for i in range(0, 32, 2):
        if code_off + i + 2 > size:
            break
        word = struct.unpack_from('>H', data, code_off + i)[0]
        print(f"0x{pc + i:08X}: 0x{word:04X}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python dump_init.py <romfile>")
        sys.exit(1)
    dump_init(sys.argv[1])
