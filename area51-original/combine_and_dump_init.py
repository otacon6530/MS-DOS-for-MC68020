import struct
import sys
import os

# Usage: python combine_and_dump_init.py a51_2-c.hh a51_2-c.hl a51_2-c.lh a51_2-c.ll
# Combines 4 split ROMs into one 32-bit binary and dumps 68k init code

def combine_roms(rom_files, out_file=None):
    if len(rom_files) != 4:
        raise ValueError("Exactly 4 ROM files are required.")
    rom_datas = [open(f, 'rb').read() for f in rom_files]
    min_len = min(len(d) for d in rom_datas)
    combined = bytearray()
    for i in range(min_len):
        # Each output word: [h, p, m, k] (big endian)
        combined += bytes([
            rom_datas[0][i],
            rom_datas[1][i],
            rom_datas[2][i],
            rom_datas[3][i]
        ])
    if out_file:
        with open(out_file, 'wb') as f:
            f.write(combined)
    return combined

def dump_init(data):
    size = len(data)
    print(f"Combined ROM size: {size} bytes")
    # 68k vectors: first 8 bytes (SP, PC)
    sp = struct.unpack_from('>I', data, 0)[0]
    pc = struct.unpack_from('>I', data, 4)[0]
    print(f"Initial SP: 0x{sp:08X}")
    print(f"Reset vector (PC): 0x{pc:08X}")
    code_off = pc & (size - 1)
    print(f"Code at PC (offset 0x{code_off:X}):")
    for i in range(0, 32, 2):
        if code_off + i + 2 > size:
            break
        word = struct.unpack_from('>H', data, code_off + i)[0]
        print(f"0x{pc + i:08X}: 0x{word:04X}")

if __name__ == "__main__":
    if len(sys.argv) < 5:
        print("Usage: python combine_and_dump_init.py <hh> <hl> <lh> <ll> [out.bin]")
        sys.exit(1)
    rom_files = sys.argv[1:5]
    out_file = sys.argv[5] if len(sys.argv) > 5 else None
    data = combine_roms(rom_files, out_file)
    dump_init(data)
