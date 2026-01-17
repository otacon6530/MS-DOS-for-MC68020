# MSBIO1.ASM Analysis (MS-DOS v4.0 BIOS)

## Purpose
MSBIO1.ASM is the main BIOS module for MS-DOS, responsible for low-level hardware initialization, device driver setup, and providing system services to the DOS kernel. It links together various device drivers and BIOS routines.

## Key Features
- Includes and links device drivers: console, auxiliary, printer, clock, disk, etc.
- Provides macros and segment definitions for BIOS code organization.
- Contains entry points and initialization logic for BIOS services.

## Porting Considerations for MC68020
- All x86-specific macros, segment, and linking logic must be adapted for 68k.
- Device driver initialization and hardware access must be rewritten for MC68020 hardware.
- Entry points and calling conventions must be updated for 68k assembly.

---
This document summarizes the main purpose and structure of MSBIO1.ASM for porting to MC68020.