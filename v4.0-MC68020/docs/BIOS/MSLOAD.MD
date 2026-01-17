# MSLOAD.ASM Analysis (MS-DOS v4.0 BIOS)

## Purpose
MSLOAD.ASM is the loader for IBMBIO.COM, responsible for loading the BIOS and DOS kernel into memory during the boot process. It handles reading the boot sector, FAT sectors, and error handling during boot.

## Key Features
- Loads BIOS and DOS kernel from disk into memory.
- Handles boot sector and FAT sector reading.
- Provides boot error messages and recovery logic.

## Porting Considerations for MC68020
- All x86-specific disk and memory access must be rewritten for MC68020.
- Boot sector and FAT handling must be adapted to the MC68020 memory model.
- Error handling and messaging must be updated for 68k conventions.

---
This document summarizes the main routines and porting notes for MSLOAD.ASM.