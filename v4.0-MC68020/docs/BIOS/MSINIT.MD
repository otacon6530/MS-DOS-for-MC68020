# MSINIT.ASM Analysis (MS-DOS v4.0 BIOS)

## Purpose
MSINIT.ASM is responsible for system and hardware initialization during the boot process. It sets up the real-time clock, manages date/time conversion, and handles system resume from suspension. It also includes routines for converting days since 1-1-1980 to a date, and for converting binary values to BCD (Binary Coded Decimal).

## Key Functions
- **Daycnt_to_day**: Converts a day count (days since 1-1-1980) to BCD date (century, year, month, day).
- **Bin_to_bcd**: Converts a binary value (in AL) to BCD format.
- **INT6C**: Handles system resume, reads the real-time clock, updates system date/time, and returns to the interrupted code.

## Includes
- MSGROUP.INC, MSDSKPR.INC, MSEQU.INC, MSMACRO.INC, MSEXTRN.INC, BIOSTRUC.INC, CMOSEQU.INC, cputype.inc: Various include files for segment definitions, macros, external references, and hardware structures.
- READCLOC.INC, CLOCKSUB.INC: Additional clock-related routines.

## Notable Details
- The code is written for x86 assembly and uses instructions and conventions specific to that architecture (e.g., segment registers, INT instructions, x86 register names).
- The code is designed to be dynamically relocated by MSINIT at runtime.
- There are many revision history comments, indicating ongoing maintenance and bug fixes.

## Porting Considerations for MC68020
- All x86-specific instructions (e.g., segment manipulation, INT, x86 register usage) must be rewritten for MC68020 assembly.
- Hardware access (RTC, interrupts, etc.) must be adapted to the MC68020 platform.
- Data structures and calling conventions will need to be updated for 68k architecture.

---
This document summarizes the first part of MSINIT.ASM. Further analysis may be needed for the rest of the file and its dependencies.
