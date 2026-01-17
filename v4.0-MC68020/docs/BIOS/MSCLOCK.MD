# MSCLOCK.ASM Analysis (MS-DOS v4.0 BIOS)

## Purpose
MSCLOCK.ASM implements the clock device driver for MS-DOS, providing routines to read and set the system time, convert time to clock ticks, and manage the real-time clock (RTC).

## Key Routines
- TIM$WRIT: Set the current time.
- TIM$READ: Read the current time.
- Time_To_Ticks: Convert time to clock ticks (18.2 ticks/sec typical).
- Manages day count since 1-1-1980 and BCD conversions.

## Porting Considerations for MC68020
- RTC access and timekeeping must be rewritten for MC68020 hardware.
- All x86-specific register and memory access must be updated for 68k.
- Indirect call addresses and data structures must be adapted for 68k conventions.

---
This document summarizes the main routines and porting notes for MSCLOCK.ASM.