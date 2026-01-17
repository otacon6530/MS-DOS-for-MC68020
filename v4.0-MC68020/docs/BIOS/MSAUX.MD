# MSAUX.ASM Analysis (MS-DOS v4.0 BIOS)

## Purpose
MSAUX.ASM implements the auxiliary device driver for serial (RS-232) ports. It handles communication for AUX, COM1, and COM2 devices, providing routines for reading, writing, flushing, and status checking of the serial ports.

## Key Routines
- AUX$READ: Read characters from the specified device.
- AUX$RDND: Non-destructive read (no waiting).
- AUX$FLSH: Flush device input buffer.
- AUX$WRIT: Write characters to the device.
- AUX$WRST: Get device status.

## Data Structures
- AUXBUF: Two-byte buffer for zero and one RS-232 cards.
- Uses GETDX to select which card to access.

## Porting Considerations for MC68020
- All x86-specific device and interrupt handling must be rewritten for MC68020.
- Serial port access and buffer management must be adapted to the target hardware.
- Calling conventions and register usage must be updated for 68k.

---
This document summarizes the main purpose and routines of MSAUX.ASM for porting to MC68020.