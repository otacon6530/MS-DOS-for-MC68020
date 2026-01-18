# VASM Assembler Reference (STD Syntax)

## Overview
VASM is a portable assembler supporting multiple CPU architectures and syntax modules. This reference summarizes the STD syntax module, directives, expressions, error messages, output modules, backend CPU features, interface/internals, and module development for LLM and developer use.

---

## STD Syntax Module

### General Syntax
- **Labels**: Start at the first column or end with a colon (:). Local labels use a dot prefix (.) or dollar suffix ($).
- **Operands**: Separated by commas. Whitespace separates mnemonic/directive from operands.
- **Comments**: Introduced by `;` or `*`. Everything after is ignored.
- **Numbers**:
  - Hex: `$` (e.g., `$FF`)
  - Binary: `%` (e.g., `%1010`)
  - Octal: `@` (e.g., `@77`)
  - Decimal: digits (e.g., `123`)
- **Immediate Values**: Use `#` (e.g., `#10`, `#$FF`). For 68k, use `#$` for hex immediates even in STD syntax.

---

## Expressions
- Support arithmetic, bitwise, and logical operators.
- Parentheses for grouping.
- Symbolic expressions allowed.

---

## Directives (STD Syntax)
- `.align <bits>`: Align to next boundary (e.g., `.align 2` for 32-bit).
- `.byte <exp1>[,<exp2>...]`: Store bytes.
- `.word <exp1>[,<exp2>...]`: Store 16-bit words.
- `.long <exp1>[,<exp2>...]`: Store 32-bit words.
- `.quad <exp1>[,<exp2>...]`: Store 64-bit words.
- `.single <exp1>[,<exp2>...]`: Store IEEE single-precision floats.
- `.double <exp1>[,<exp2>...]`: Store IEEE double-precision floats.
- `.string "text"[,"text2"...]`: Store null-terminated strings.
- `.space <exp>[,<fill>]`: Reserve bytes (default fill=0).
- `.skip <exp>[,<fill>]`: Reserve bytes (default fill=0).
- `.section <name>[,"<attributes>"][[,@<type>]|[,%<type>]|[,<mem_flags>]]`: Start or switch section.
- `.set <symbol>,<exp>`: Assign value to symbol.
- `.size <symbol>,<size>`: Set symbol size (for ELF).
- `.global <symbol>[,<symbol>...]`: Make symbol externally visible.
- `.weak <symbol>[,<symbol>...]`: Weak symbol (can be replaced by global).
- `.rept <exp>`: Repeat block (terminated by `.endr`).
- `.if <exp>`: Conditional assembly (terminated by `.endif`).
- `.include <file>`: Include another source file.
- `.incbin <file>[,<offset>[,<length>]]`: Include binary data.
- `.pushsection` / `.popsection`: Save/restore section context.
- `.p2align <bits>[,<fill>][,<maxpad>]`: Align to power-of-2 boundary.
- `.p2alignw`, `.p2alignl`: Like `.p2align` but fill with word/long.
- `.short <exp1>[,<exp2>...]`: Store 16-bit words.
- `.ualong`, `.uashort`, `.uaword`, `.uaquad`: Store values regardless of alignment.
- `.zero <exp>[,<fill>]`: Reserve zeroed bytes.
- `.stabs`, `.stabn`, `.stabd`: Debug info.
- `.type <symbol>,<type>`: Set symbol type (ELF).
- `.fail <exp>`: Abort assembly with error.
- `.size <symbol>,<size>`: Set symbol size (ELF).
- `.global <symbol>[,<symbol>...]`: Export symbol.
- `.weak <symbol>[,<symbol>...]`: Weak symbol.
- `.end`: End assembly.

#### Predefined Section Directives
- `.bss`, `.data`, `.rodata`, `.text`, etc. map to `.section` with attributes.

---

## Error Messages (STD Syntax)
- 1001: mnemonic expected
- 1002: invalid extension
- 1003: no space before operands
- 1004: too many closing parentheses
- 1005: missing closing parentheses
- 1006: missing operand
- 1007: scratch/garbage at end of line
- 1008: section flags expected
- 1009: invalid data operand
- 1010: memory flags expected
- 1011: identifier expected
- 1012: assembly aborted
- 1013: unexpected "%s" without "%s"
- 1014: pointless default value for required parameter <%s>
- 1015: invalid section type ignored, assuming progbits
- 1019: syntax error
- 1021: section name expected
- 1022: .fail %lld encountered
- 1023: .fail %lld encountered
- 1024: alignment too big

---

## Output Modules (Summary)
- **ELF**: -Felf, supports multiple architectures, relocations, and section attributes.
- **a.out**: -Faout, older Unix format, limited relocations.
- **COFF**: -Fcoff, Unix System V, supports ARM, m68k, ppc, x86.
- **TOS/DRI**: -Ftos/-Fdri, Atari formats, single code/data/bss section, symbol length limits.
- **Hunk**: -Fhunk, AmigaOS, supports multiple sections and relocations.
- **Xfile**: -Fxfile, Sharp X68000, single code/data/bss section.
- **O65**: -Fo65, 6502-family, supports relocations, section start addresses.
- **VOBJ**: -Fvobj, simple portable object format.
- **BIN**: -Fbin, raw binary output, optional headers for various platforms.
- **SREC**: -Fsrec, Motorola S-Record ASCII format.
- **IHEX**: -Fihex, Intel Hex ASCII format.
- **CDEF**: -Fcdef, C #define output for absolute symbols.
- **WOZMON**: -Fwoz, Wozmon monitor commands for serial transfer.
- **PAP**: -Fpap, MOS paper tape format.

---

## Backend CPU Modules (Summary)
VASM supports many CPU backends, each with specific options, extensions, optimizations, and error messages. Below are highlights relevant for MC68020/STD syntax, but see vasm.txt for full details on other CPUs.

### M68k (MC68020, etc.)
- Select CPU: `-m68000`, `-m68020`, `-m68030`, etc.
- FPU/MMU: `-m68881`, `-m68882`, `-m68851`
- ColdFire: `-mcf5...`, `-mcfv2`, `-mcfv3`, `-mcfv4`, `-mcfv4e`
- Apollo Core: `-m68080`
- Optimizations: Use `-opt-*` flags for instruction/data optimizations (see vasm.txt for full list).
- Extensions: Directives for small data, base registers, FPU, MMU, etc.
- Error messages: Range from unsupported instructions, illegal addressing modes, register errors, operand out of range, etc.

### Hans & TR3200 Modules
- **Hans**: 32-bit instructions/data, custom error messages for data size, immediate range, jump distance.
- **TR3200**: 32-bit, TR3200 syntax (destination left, source right), register names prefixed by `%`, example code provided in vasm.txt.

### Other CPU Backends (Summary)
- **PowerPC**: Options for endianness, Altivec, model selection, small data registers, branch optimizations.
- **c16x/st10**: Options for jump translation, pseudo-instructions, SFR declaration, segment/offset extraction.
- **6502/65816**: Options for CPU model, illegal instructions, direct/zero page, bitstream selectors, addressing mode hints, accumulator/index width.
- **SPC700**: Direct/direct page, bitstream selectors, addressing mode enforcement.
- **ARM**: Options for architecture, CPU model, endianness, Thumb mode, ADR/LDR optimizations.
- **80x86**: Options for CPU model, AT&T syntax, code size, register prefixes, operand size optimizations.
- **Z80/8080**: Compatibility modes, syntax selection, index register handling, lo/hi modifiers.
- **6800/6809/6309/68HC12**: CPU selection, addressing mode enforcement, direct/extended/PC-relative modes.
- **Jaguar RISC**: GPU/DSP selection, register/condition code definition, instruction set selection.
- **PDP11, unSP, HANS, and others**: Each with unique options, extensions, and error messages.

### Error Messages (Backend Examples)
- Each backend defines its own error codes for unsupported instructions, operand errors, addressing mode issues, register problems, and more. See vasm.txt for details.

---

## VASM Interface & Internals

### Building VASM
- Source tree: `vasm/`, `vasm/syntax/<syntax-module>/`, `vasm/cpus/<cpu-module>/`, `vasm/obj/`
- Build: `make CPU=<cpu> SYNTAX=<syntax>` (e.g., `make CPU=m68k SYNTAX=std`)
- Makefile options: `TARGET`, `TARGETEXTENSION`, `CC`, `COPTS`, `CCOUT`, `LD`, `LDOUT`, `LDFLAGS`, `RM`
- Supported CPUs: 6502, 6800, 6809, arm, c16x, hans, jagrisc, m68k, pdp11, ppc, qnice, spc700, test, tr3200, unsp, vidcore, x86, z80
- Supported Syntax: std, mot, madmac, oldstyle, test

### Global Variables
- `cur_src`: Current source text instance
- `defsectname`, `defsectorg`, `defsecttype`: Default section name, org, type
- `exec_out`: Non-zero for executable output
- `filename`, `inname`, `outname`: File names
- `octetsperbyte`, `output_bitsperbyte`: Byte size info

### Data Structures
- **Source**: Tracks source text, macros, repetition, arguments, line numbers
- **Section**: Linked list of memory blocks, name, attributes, alignment, flags
- **Symbol**: Linked list, type, flags, name, expression, section, address, alignment
- **Register Symbol**: Name, type, flags, number
- **Atom**: Linked list of indivisible code/data units, type, alignment, content (instruction, data, label, space, etc.)
- **Relocation**: List describing how data must be modified for linking/relocation

### Support Functions
- Memory: `mymalloc`, `myfree`, `readval`, `setval`, `readbits`, `setbits`, `readbyte`, `writebyte`, `OCTETS(n)`
- Expressions: `parse_expr`, `eval_expr`, `simplify_expr`, `number_expr`, etc.
- Symbols: `new_abs`, `new_equate`, `new_import`, `new_labsym`, etc.
- Atoms: `new_inst_atom`, `new_data_atom`, `new_label_atom`, etc.

---

## Advanced Module Development

### Syntax Modules
- Key macros for syntax modules:
  - `ISIDSTART(x)`, `ISIDCHAR(x)`, `ISBADID(p,l)`, `ISEOL(x)`, `CHKIDEND(s,e)`, `BOOLEAN(x)`, `NARGSYM`, `CARGSYM`, `REPTNSYM`, `EXPSKIP()`, `IGNORE_FIRST_EXTRA_OP`, `MAXMACPARAMS`, `SKIP_MACRO_ARGNAME(p)`, `MACRO_ARG_OPTS(m,n,a,p)`, `MACRO_ARG_SEP(p)`, `MACRO_PARAM_SEP(p)`, `EXEC_MACRO(s)`
- Required elements in syntax.c:
  - `syntax_copyright`, `dirhash`, `commentchar`, `dotdirs`, `init_syntax()`, `syntax_args()`, `syntax_defsect()`, `skip()`, `eol()`, `const_prefix()`, `const_suffix()`, `parse()`, `parse_macro_arg()`, `expand_macro()`, `get_local_label()`
- Optional features: e.g., `SYNTAX_STD_COMMENTCHAR_HASH` to allow `#` as comment.

### CPU Modules
- Required elements in cpu.h:
  - Endianness defines, CPU macro, bits per byte, max operands/qualifiers, operand/mnemonic types, instruction alignment, data alignment, operand classes, optional features (FLOAT_PARSER, HAVE_INSTRUCTION_EXTENSION, etc.)
- Required elements in cpu.c:
  - `bytespertaddr`, `mnemonics[]`, `cpu_copyright`, `cpuname`, `init_cpu()`, `cpu_args()`, `parse_cpu_special()`, `new_operand()`, `parse_operand()`, `instruction_size()`, `eval_instruction()`, `eval_data()`, and extension/option handling if needed.
- Operand parsing must handle matching, skipping, combining, and optional operands.
- Support for custom unary operations and base symbol finding via macros.

### Output Modules
- Output modules are runtime-selectable and must export `init_output_<fmt>()`.
- Required pointers: copyright string, write_object function, output_args function.
- May set global variables: `asciiout`, `unnamed_sections`, `secname_attr`, `output_bitsperbyte`, `output_indirect`.
- Data writing support functions: `fw8`, `fw16`, `fw24`, `fw32`, `fwdata`, `fwspace`, `fwbytes`, `fwdblock`, `fwsblock`, `fwalign`, `fwpattern`, `fwpcalign`.
- Output modules must handle section/atom traversal, alignment, and data writing.
- Error/warning messages via `output_error` and `output_atom_error`.
- Relocation handling: Prefer standard relocations, extend with CPU-specific only if needed.

---

## Notes
- For MC68020/Area 51 BIOS, use STD syntax with `#$` for immediate hex values.
- VASM is highly extensible; see vasm.txt for details on writing modules and using internals.
- Always check error messages for syntax, directive, or backend issues.
- Refer to vasm.txt for advanced options and backend-specific features.

---

## References
- [vasm.txt](vasm.txt): Full assembler manual.
- [vasm.pdf](vasm.pdf): Official documentation.

---

This reference is tailored for STD syntax and MC68020 development. For other syntax modules, CPU backends, output formats, and internals, see corresponding chapters in vasm.txt.
