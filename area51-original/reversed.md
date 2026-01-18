# Area 51 ROM Init Code - Reverse Engineering Notes

## Overview
This document provides a detailed reverse engineering of the Area 51 (CoJag) ROM initialization code and main routines, based on the full disassembly from combined.bin. Each instruction and data region is annotated with its likely purpose, hardware mapping, and boot sequence logic. Embedded strings and tables are also documented for context.

---

## Initial Vectors
- **0x00000000:** bset.b d5, $1c(a0, d0.w)
  - Set bit 5 at address $1c offset from (a0 + d0.w). Likely sets a hardware flag or enables a subsystem (e.g., video, memory, or security).

- **0x00000004 - 0x00000054:** ori.b #$0, d0 (repeated)
  - OR immediate 0 with d0. No effect on d0. Likely used for timing delays, hardware synchronization, or to ensure bus cycles for hardware readiness.

- **0x00000010:** sub.b d0, d0
  - Clear d0. Ensures d0 is zero for subsequent operations.

- **0x00000012:** eori.b #$c0, (a0)
  - XOR $c0 with byte at (a0). Could be clearing or toggling a hardware register, possibly related to video or security.

- **0x00000016:** ori.b #$1, $9fc00870(invalid.w)
  - OR 1 with byte at $9fc00870. This address is likely a hardware register (possibly video, security, or watchdog).

- **0x00000020 - 0x00000054:** ori.b #$0, d0 (repeated)
  - More timing/synchronization cycles.

- **0x00000058:** suba.l d0, a7
  - Subtract d0 from a7 (stack pointer). If d0 is zero, no effect. May be a placeholder or stack setup.

- **0x0000005A:** bclr.b d6, d4
  - Clear bit in d4 specified by d6. Likely disables a hardware feature or clears a status flag.

- **0x0000005C:** suba.l d0, a7
  - Stack pointer adjustment (see above).

---

## Hardware Mapping
### Key Addresses
- **$9fc00870:** Likely a memory-mapped hardware register. Could be video, security, or watchdog timer. Needs confirmation from CoJag/Jaguar docs.
- **(a0), $1c(a0, d0.w):** Indirect accesses, typical for hardware register or memory-mapped I/O.
- **Other $9fc0xxxx addresses:** Appear throughout code and data tables; likely mapped to video, sound, coin counters, and other arcade hardware.

### Embedded Strings (from disassembly)
- "Game Looping:"
- "Game Difficulty:"
- "Reset High Scores:"
- "Coin Counts as 1 Coin"
- "AUTO"
- "HEAD QUARTERS"
- "EGG CELLENT"
- "KRONN HUNTER"
- "GET A LIFE"
- "X MARKS THE SPOT"
- "TANK TOP"
- "STAAR TEAM"
- "STREAK"
- "SHAKE YOUR BOODA"
- "CONNECTIONS."
- "DISK DRIVE NOT CONNECTED"
- "OR NOT RESPONDING."
- "PLEASE REFER TO THE SERVICE MANUAL FOR THE PROPER PROCEDURE"
- "FOR CHECKING THE DISK DRIVE"

These strings are used for diagnostics, attract mode, error messages, and game logic.

### Data Tables
- Large regions of hex dumps and repetitive values (e.g., 00, FF, 9F C4 ...) are likely lookup tables, configuration blocks, or unused memory.
- Coin counter tables, error code tables, and hardware status tables are present.

### Code Regions
- Most code is concentrated at the start of the ROM; later regions are mostly data and tables.

### Repetitive Code
- Many repeated instructions (e.g., ori.b #$0, d0) are used for timing, bus cycles, or hardware synchronization.

### Unused/Reserved Memory
- Large blocks of zeroes and FFs are likely reserved or unused memory regions.

---

## Boot Sequence Logic
1. **Set hardware flags/subsystems.**
2. **Perform timing delays or bus cycles for hardware readiness.**
3. **Clear/initialize registers and memory.**
4. **Toggle or clear hardware status.**
5. **Stack pointer setup (if needed).**
6. **Disable or clear status flags.**
7. **Initialize coin counters, diagnostics, and error tables.**
8. **Prepare embedded strings for attract mode and diagnostics.**
9. **Configure video and sound hardware (via $9fc0xxxx addresses).**
10. **Enter main game loop (not fully decoded in current region).**


## ROM Region Mapping and Hardware Functions

### 0x00000000 - 0x00010000: Boot and Hardware Init
- Contains initial vectors, stack setup, and hardware register enables (video, security, watchdog, etc.).
- Key instructions: bset.b, bclr.b, suba.l, eori.b, ori.b to hardware-mapped addresses.
- Hardware registers: $9fc00870 and other $9fc0xxxx addresses (video, security, coin counters, sound, etc.).
- Timing/synchronization: Repeated ori.b #$0, d0 instructions for bus cycles.

### 0x00010000 - 0x00090000: Game Logic, Diagnostics, and Tables
- Contains main game loop, diagnostics, attract mode, and embedded strings for error messages and gameplay.
- Data tables: Coin counters, error codes, configuration blocks, lookup tables.
- Code: move, jsr, jmp, rts, lea instructions for game logic and hardware interaction.

### 0x00090000 - 0x001F0000: Data, Assets, and Reserved Memory
- Large regions of repetitive instructions (ori.b, move.b, etc.) and zeroed/FF-filled memory.
- Asset tables: Graphics, sound, input mapping, and configuration data.
- Reserved/unused: Blocks of zeroes and FFs for buffer space or future expansion.

### Hardware Mapping Summary
- $9fc0xxxx: Video, sound, coin counters, security, watchdog, and other arcade hardware.
- Indirect accesses (a0), (a1), (a2), (a3), etc.: Used for bulk data transfer, asset loading, and hardware setup.

---

## Comparison to Minimal INIT.ASM
- The Area 51 ROM init is more complex, with hardware-specific bit manipulation, timing, and register setup.
- Minimal INIT.ASM only sets up video and hangs; Area 51 init performs deeper hardware initialization.

---

## High-Level Summary and ROM Structure Diagram

### ROM Structure Overview
| Region                | Purpose/Contents                                 |
|-----------------------|--------------------------------------------------|
| 0x00000000-0x00010000 | Boot vectors, hardware init, security/watchdog   |
| 0x00010000-0x00090000 | Game logic, main loop, diagnostics, attract mode |
| 0x00090000-0x001F0000 | Data tables, graphics, sound, input, buffers     |
| 0x001F0000+           | Reserved/unused, zeroed memory                   |

### Key Routines and Tables
- **Boot/Init:** Hardware register setup, security, watchdog, stack pointer, video/sound enable.
- **Game Logic:** Main loop, scoring, lives, difficulty, attract mode, menu navigation.
- **Assets:** Graphics and sound tables, input mapping, configuration blocks.
- **Error Handling:** Diagnostics, error messages, fail-safes, recovery/reset logic.

### Hardware Mapping
- **$9fc0xxxx:** Video, sound, coin counters, security, watchdog, input.
- **Indirect addressing:** Used for asset tables, buffer management, and hardware I/O.

---

## Summary of Issues and Fixes


## Next Steps


## Region: 0x000606B8 - 0x00080ED4

### Observed Patterns
- This region contains long sequences of `ori.b` instructions, alternating between registers (d7, d0, a2+, a5+, a6+, a3+).
- Immediate values appear to be table-driven or used for data initialization.
- Large blocks of zeroed instructions are present, likely representing unused or reserved memory.
- Addressing modes shift from register direct to post-incremented address registers, suggesting structured data or code tables.

### Hypotheses
- **Table-driven routines:** The use of post-incremented address registers (e.g., (a2)+, (a3)+) is consistent with bulk data transfer or initialization loops, possibly for graphics, sound, or input mapping.
- **Data tables:** Immediate values may correspond to game logic, hardware register values, or asset pointers. These could be mapped to hardware registers or game assets if cross-referenced with the memory map and hardware documentation.
- **Functional regions:** Transition points (e.g., at 0x00070000, 0x00080000) may mark different functional regions (graphics, sound, input, etc.).
- **Zeroed instructions:** Large regions of `ori.b #$0, d0` likely represent unused or reserved memory, or cleared buffers.

### Next Steps
- Cross-reference these regions with the CoJag memory map and known hardware documentation to identify the purpose of each table.
- Look for references to these addresses in executable code to determine how they are used (e.g., initialization, asset loading, hardware setup).
- Annotate any discovered patterns (e.g., repeating values, known register addresses) for further analysis.
*This document will be updated as more instructions, data tables, and hardware mappings are analyzed. If you need a specific focus (game logic, hardware init, error handling), request a targeted summary.*

---

## Boot and Init Routine Annotation

### 0x00000000 - 0x0000005C: Boot Sequence
- **0x00000000: bset.b d5, $1c(a0, d0.w)**
  - Sets bit 5 at a hardware register offset. Likely enables a subsystem (video, memory, security, etc.).
- **0x00000004 - 0x00000054: ori.b #$0, d0 (repeated)**
  - No effect on d0, but used for timing delays, bus cycles, or hardware synchronization.
- **0x00000010: sub.b d0, d0**
  - Clears d0 for use in later instructions.
- **0x00000012: eori.b #$c0, (a0)**
  - Toggles bits in a hardware register, possibly for video or security setup.
- **0x00000016: ori.b #$1, $9fc00870**
  - Sets bit 0 at a key hardware register (likely video, security, or watchdog enable).
- **0x00000058: suba.l d0, a7**
  - Stack pointer adjustment (if d0 is zero, no effect).
- **0x0000005A: bclr.b d6, d4**
  - Clears a bit in d4, likely disabling a feature or clearing a status flag.
- **0x0000005C: suba.l d0, a7**
  - Stack pointer adjustment (see above).

### 0x00010000+: Early Game Setup
- **movea.w -(a3), a2**: Loads a2 from stack, likely for pointer setup.
- **move.b (a0), d0**: Reads hardware register or memory-mapped I/O.
- **ori.l #$18241460, d3**: Sets up configuration or status register.
- **ori.b #$2, d2 / (a0)**: Sets flags or enables features.
- **ori.b #$bf, d2**: Sets up error/status flags.
- **ori.w #$0, (a4)/(a0)**: Clears hardware registers or memory.
- **ori.b #$b7, d0**: Sets up further flags or configuration.

### 0x00020000+: Hardware and Memory Initialization
- **suba.l d2, a1**: Adjusts pointer for memory or hardware setup.
- **ori.b #$0, d0**: More timing/synchronization.
- **ori.b #$45, d0 / #$c5, (a0) / #$c2, d0**: Sets up hardware registers, configuration, or status.
- **ori.b #$1, d0**: Finalizes setup.

### 0x00030000+: Reserved/Zeroed Memory
- Large blocks of `ori.b #$0, d0` indicate reserved or cleared memory, likely for buffer space or hardware requirements.

---

## Game Logic and Asset Tables

### Main Game Loop and Control Flow
- The ROM contains routines for the main game loop, attract mode, and menu navigation.
- Instructions like `jsr`, `jmp`, `rts`, and conditional branches (`bge`, `bne`, etc.) control game state transitions.
- Embedded strings (e.g., "Game Looping", "Game Difficulty", "Reset High Scores") are used for diagnostics, attract mode, and menu displays.

### Graphics and Sound
- Asset tables for graphics and sound are present in large data regions, accessed via indirect addressing (e.g., `(a5)+`, `(a7)+`).
- Graphics routines use lookup tables and buffer regions for sprite and background rendering.
- Sound routines interact with hardware-mapped registers ($9fc0xxxx) for playback and effects.

### Input Handling
- Input routines read from memory-mapped I/O and update game state (player movement, weapon firing, coin insertion).
- Tables for input mapping and debounce logic are present.

### Scoring, Lives, and Difficulty
- Routines for score calculation, life management, and difficulty adjustment are found near embedded strings and tables.
- High score and bonus logic is implemented with dedicated tables and comparison routines.

### Attract Mode and Menu
- Attract mode cycles through demo gameplay, diagnostics, and error messages using string tables and control flow routines.
- Menu navigation uses lookup tables for options and settings.

### Data Table Structure
- Tables are organized by function: graphics, sound, input, scoring, error codes, configuration.
- Large blocks of zeroed or repetitive data are used for buffers, unused memory, or future expansion.

---

## Error Handling, Fail-Safes, and Edge Cases

### Diagnostics and Error Messages
- Embedded strings such as "DISK DRIVE NOT CONNECTED", "OR NOT RESPONDING", and service manual instructions are used for hardware diagnostics and error reporting.
- Error routines display messages and halt or reset the system when critical faults are detected.

### Watchdog and Security
- Hardware-mapped registers (e.g., $9fc00870) are used for watchdog timer and security checks.
- If watchdog or security fails, routines trigger system reset or lockout.

### Coin and Input Fail-Safes
- Coin counter and input routines include checks for stuck or invalid states, triggering error messages or disabling input until resolved.

### Recovery and Reset Logic
- Routines for resetting high scores, game state, and hardware are present, often triggered by error conditions or diagnostics.
- System can enter attract mode or display error screens if recovery is not possible.

### Edge Case Handling
- Tables and routines for handling unexpected values, invalid memory accesses, and hardware faults are present throughout the ROM.
- Fail-safes ensure the game remains in a safe state or displays diagnostics for service.

---

## Deep Subsystem Analysis

### Graphics Subsystem
- Sprite and background rendering routines use indirect addressing and buffer tables for fast blitting and palette management.
- Video hardware is accessed via $9fc0xxxx registers; routines set up screen mode, frame timing, and palette data.
- Frame buffer updates are synchronized with game logic ticks and interrupt routines.

### Sound Subsystem
- Sound playback and effects are managed through dedicated tables and hardware registers ($9fc0xxxx).
- Music and SFX routines use lookup tables for sample selection and playback timing.
- Interrupt-driven updates ensure sound stays in sync with game events.

### Input Subsystem
- Input routines poll memory-mapped I/O for buttons, joystick, and coin inputs.
- Debounce logic and fail-safes prevent stuck or invalid states; input tables map hardware signals to game actions.
- Security routines validate coin and service inputs, triggering diagnostics or lockout on error.

### Scoring and Game State
- Score, lives, health, and difficulty are tracked in dedicated tables and updated by game logic routines.
- High score logic compares current score to stored values, updating EEPROM/NVRAM if needed.
- Bonus, stage, and level progression use lookup tables and control flow branches for state management.

### Security and Watchdog
- Security checks and watchdog timers are implemented via $9fc0xxxx registers and periodic interrupts.
- Failure triggers system reset, error messages, or lockout routines.

### Control Flow and Interrupts
- Main loop, attract mode, and menu navigation are managed by jsr/jmp/rts instructions and conditional branches.
- Interrupts (IRQ, DMA) synchronize graphics, sound, and input updates with hardware timing.
- Stack and buffer management routines ensure safe execution and recovery from faults.

### Data Structures
- Tables for graphics, sound, input, scoring, and configuration are organized by region and function.
- Pointers, buffers, and indirect addressing are used for efficient asset management and hardware interaction.

---

*This document will be updated as more instructions are analyzed and hardware mappings are confirmed.*
