# MSCON.ASM Analysis (MS-DOS v4.0 BIOS)

## Purpose
MSCON.ASM implements the console device driver for MS-DOS, handling keyboard input and screen output. It provides routines for reading characters, managing input buffers, and supporting extended keyboard features.

## Key Routines
- CON$READ: Read characters from the console.
- CHRIN: Input a single character (with extended keyboard support).
- Handles compatibility for extended keyboards and special character cases.

## Porting Considerations for MC68020
- Keyboard and display I/O must be rewritten for MC68020 hardware.
- All x86-specific register and interrupt logic must be updated for 68k.
- Input buffer and character handling must be adapted for 68k conventions.

---
This document summarizes the main routines and porting notes for MSCON.ASM.