        ; ================================
        ; CoJag 68020 minimal INIT (STD)
        ; Visible border color test
        ; ================================

        .org    0
        .long   0x00100000          ; initial SP (DRAM0)
        .long   INIT_START          ; initial PC

INIT_START:
        move.l  #0xDEADBEEF, d0     ; sanity marker

        ; ----------------------------
        ; Tom video init (minimal)
        ; ----------------------------

        ; VMODE: enable video, RGB16
        move.w  #0x0051, 0x800000

        ; Basic timing (safe defaults)
        move.w  #0x0200, 0x800008 ; HP
        move.w  #0x0010, 0x80000A ; HBB
        move.w  #0x00F0, 0x80000C ; HBE
        move.w  #0x0200, 0x80000E ; VP
        move.w  #0x0010, 0x800010 ; VBB
        move.w  #0x01F0, 0x800012 ; VBE

        ; Enable overlay/video
        move.w  #0x0001, 0x800058 ; OCTRL

        ; ----------------------------
        ; BORDER COLOR TEST
        ; ----------------------------
        ; BORD1 = bright white
        move.w  #0x0FFF, 0x80003A

hang:
        move.w  #0x0FFF, 0x80003A
        bra.s   hang