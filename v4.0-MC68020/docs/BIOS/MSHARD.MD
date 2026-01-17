# MSHARD.ASM Analysis (MS-DOS v4.0 BIOS)

## Purpose
MSHARD.ASM provides routines for handling hard disk I/O, especially for working around bugs in some IBM AT ROM BIOS implementations. It intercepts INT 13h calls and manages read operations for hard disks.

## Key Features
- Intercepts and handles hard disk read calls.
- Passes other functions to the original ROM BIOS routine.
- Defines data structures for command blocks and disk status.

## Porting Considerations for MC68020
- All x86-specific interrupt and port I/O logic must be rewritten for MC68020.
- Hard disk controller access and error handling must be adapted to the target hardware.
- Data structures and calling conventions must be updated for 68k.

---
This document summarizes the main routines and porting notes for MSHARD.ASM.