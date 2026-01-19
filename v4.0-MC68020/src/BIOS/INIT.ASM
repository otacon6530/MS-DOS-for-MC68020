        .text

; ============================================================================
; CoJag / Area 51 MX – 68020 + GPU startup with bitmap object
; Ported from Jaguar console code to CoJag memory map
; ============================================================================

; -----------------------------
; CoJag Tom/Jerry base addresses
; -----------------------------
TOM_BASE    .equ    $00800000
JERRY_BASE  .equ    $00810000
GPU_BASE    .equ    $00802000

; Tom registers (offsets from TOM_BASE)
VMODE       .equ    TOM_BASE+$00
BG          .equ    TOM_BASE+$28
BORD1       .equ    TOM_BASE+$3A
OLP         .equ    TOM_BASE+$40
HDB1        .equ    TOM_BASE+$04
HDB2        .equ    TOM_BASE+$06
HDE         .equ    TOM_BASE+$08
VDB         .equ    TOM_BASE+$0A
VDE         .equ    TOM_BASE+$0C
CONFIG      .equ    TOM_BASE+$E0      ; still used as video/NTSC/PAL flag on CoJag

; GPU control regs (offsets from GPU_BASE)
G_CTRL      .equ    GPU_BASE+$00
G_PC        .equ    GPU_BASE+$04

; Interrupt controller (Jerry side – still at Jerry base window)
INT1        .equ    JERRY_BASE+$10
INT2        .equ    JERRY_BASE+$12
LEVEL0      .equ    $00000064         ; 68020 vector table in RAM (copied by BIOS)

; Video interrupt register (Tom)
VI          .equ    TOM_BASE+$E2

; CoJag: we’ll assume NTSC‑like timings as a starting point
VIDTYPE     .equ    $0001             ; bit in CONFIG: 1 = NTSC, 0 = PAL

; These are *approximate* and may need tuning for Area 51 MX
NTSC_HMID   .equ    320
NTSC_WIDTH  .equ    320
NTSC_VMID   .equ    240
NTSC_HEIGHT .equ    200

PAL_HMID    .equ    320
PAL_WIDTH   .equ    320
PAL_VMID    .equ    256
PAL_HEIGHT  .equ    200

C_VIDENA    .equ    $0001             ; enable video interrupts

; ============================================================================
; STARTUP PICTURE CONFIGURATION
; ============================================================================

PPP         .equ    8                 ; Pixels per Phrase (1-bit model kept)
BMP_WIDTH   .equ    320
BMP_HEIGHT  .equ    200

BMP_PHRASES .equ    (BMP_WIDTH/PPP)
BMP_LINES   .equ    (BMP_HEIGHT*2)
BITMAP_OFF  .equ    (2*8)             ; Two phrases into list
LISTSIZE    .equ    5                 ; phrases

; ============================================================================
; Globals / externals
; ============================================================================

        .globl  gSetOLP
        .globl  olp2set
        .globl  ticks

        .globl  a_vdb
        .globl  a_vde
        .globl  a_hdb
        .globl  a_hde
        .globl  width
        .globl  height
        .globl  _vidmem

        .extern ___main
        .extern _SetPallete

; ============================================================================
; Entry point
; ============================================================================

        .text

START:
        ; CoJag 68020 starts with vectors in RAM; assume we’re already running
        ; in RAM and just bring up video.

        move.w  #$2700,sr             ; disable interrupts

        ; Disable video interrupts
        move.w  #$FFFF,VI

        ; Setup a stack (pick something safe in DRAM)
INITSTACK   .equ    $0003FFFC
        move.l  #INITSTACK,a7

        bsr     InitVideo             ; Setup video registers
        bsr     InitLister            ; Initialize Object Display List
        bsr     InitVBint             ; Install VBL handler

        ; Sneaky trick to cause display to popup at first VB
        move.l  #$0,listbuf+BITMAP_OFF
        move.l  #$C,listbuf+BITMAP_OFF+4

        ; D0 gets swapped OLP from InitLister
        move.l  d0,olp2set

        ; Start GPU at gSetOLP
        move.l  #gSetOLP,G_PC
        move.l  #1,G_CTRL             ; GO

waitforset:
        move.l  G_CTRL,d0
        andi.l  #$1,d0
        bne     waitforset

        ; Configure video mode – CoJag Tom at 0x800000
        ; 0x06C7 is a common Jaguar NTSC mode; may need tuning
        move.w  #$06C7,VMODE

        jmp     ___main

; ============================================================================
; GPU code: gSetOLP – set OLP and stop GPU
; ============================================================================

        .long
        .gpu

gSetOLP:
        movei   #olp2set,r0
        load    (r0),r1

        movei   #OLP,r0
        store   r1,(r0)

        moveq   #0,r0
        movei   #G_CTRL,r1
        store   r0,(r1)
        nop
        nop

        .68000
        .bss
        .long

olp2set: .ds.l   1

        .text

; ============================================================================
; InitVBint – install vertical blank handler and enable interrupts
; ============================================================================

InitVBint:
        move.l  d0,-(sp)

        move.l  #UpdateList,LEVEL0    ; install level 0 handler

        move.w  a_vde,d0
        ori.w   #1,d0
        move.w  d0,VI                 ; video interrupt line

        move.w  #C_VIDENA,INT1        ; enable video interrupts

        move.w  sr,d0
        and.w   #$F8FF,d0             ; lower IPL
        move.w  d0,sr

        move.l  (sp)+,d0
        rts

; ============================================================================
; InitVideo – build HDB/HDE/VDB/VDE and store them (CoJag Tom @ 0x800000)
; ============================================================================

InitVideo:
        movem.l d0-d6,-(sp)

        move.w  CONFIG,d0
        andi.w  #VIDTYPE,d0
        beq     palvals

        move.w  #NTSC_HMID,d2
        move.w  #NTSC_WIDTH,d0

        move.w  #NTSC_VMID,d6
        move.w  #NTSC_HEIGHT,d4

        bra     calc_vals

palvals:
        move.w  #PAL_HMID,d2
        move.w  #PAL_WIDTH,d0

        move.w  #PAL_VMID,d6
        move.w  #PAL_HEIGHT,d4

calc_vals:
        move.w  d0,width
        move.w  d4,height

        move.w  d0,d1
        asr     #1,d1                 ; width/2

        sub.w   d1,d2
        add.w   #4,d2

        sub.w   #1,d1
        ori.w   #$400,d1

        move.w  d1,a_hde
        move.w  d1,HDE

        move.w  d2,a_hdb
        move.w  d2,HDB1
        move.w  d2,HDB2

        move.w  d6,d5
        sub.w   d4,d5

        move.w  d5,a_vdb

        add.w   d4,d6
        move.w  d6,a_vde
        move.w  a_vdb,VDB
        move.w  #$FFFF,VDE

        move.l  #0,BORD1              ; black border
        move.w  #0,BG                 ; line buffer black

        movem.l (sp)+,d0-d6
        rts

; ============================================================================
; InitLister – initialize object list
; Returns: pre-swapped list pointer in D0
; ============================================================================

InitLister:
        movem.l d1-d4/a0,-(sp)

        lea     listbuf,a0
        move.l  a0,d2

        add.l   #(LISTSIZE-1)*8,d2
        move.l  d2,d3

        lsr.l   #8,d2
        lsr.l   #3,d2

        swap    d3
        clr.w   d3
        lsl.l   #5,d3

        ; First BRANCH object (YPOS > a_vde)
        clr.l   d0
        move.l  #( $4000 ),d1         ; BRANCHOBJ|O_BRLT – you’ll want real flags here
        or.l    d2,d0
        or.l    d3,d1

        move.w  a_vde,d4
        lsl.w   #3,d4
        or.w    d4,d1

        move.l  d0,(a0)+
        move.l  d1,(a0)+

        ; Second BRANCH object (YPOS < a_vdb)
        andi.l  #$FF000007,d1
        ori.l   #$8000,d1             ; O_BRGT
        move.w  a_vdb,d4
        lsl.w   #3,d4
        or.w    d4,d1

        move.l  d0,(a0)+
        move.l  d1,(a0)+

        ; Bitmap object
        move.l  d2,d0
        move.l  d3,d1

        ori.l   #BMP_HEIGHT<<14,d1

        move.w  height,d4
        sub.w   #BMP_HEIGHT,d4
        add.w   a_vdb,d4
        andi.w  #$FFFE,d4
        lsl.w   #3,d4
        or.w    d4,d1

        move.l  #_vidmem,d4
        lsl.l   #8,d4
        or.l    d4,d0

        move.l  d0,(a0)+
        move.l  d1,(a0)+
        movem.l d0-d1,bmpupdate

        ; Second phrase of bitmap
        move.l  #BMP_PHRASES>>4,d0
        move.l  #$00000000,d1         ; O_DEPTH8|O_NOGAP etc – fill in as needed

        move.w  width,d4
        lsr.w   #2,d4
        sub.w   #BMP_WIDTH,d4
        lsr.w   #1,d4
        or.w    d4,d1

        ori.l   #(BMP_PHRASES<<18)|(BMP_PHRASES<<28),d1

        move.l  d0,(a0)+
        move.l  d1,(a0)+

        ; STOP object
        clr.l   (a0)+
        move.l  #$80000000,(a0)+      ; STOPOBJ|O_STOPINTS – fill in real flags

        ; Return swapped list pointer
        move.l  #listbuf,d0
        swap    d0

        movem.l (sp)+,d1-d4/a0
        rts

; ============================================================================
; UpdateList – VBL handler
; ============================================================================

UpdateList:
        move.l  a0,-(sp)

        lea     listbuf+BITMAP_OFF,a0

        move.l  bmpupdate,(a0)
        move.l  bmpupdate+4,4(a0)

        add.l   #1,ticks

        move.w  #$0101,INT1
        move.w  #$0000,INT2

        move.l  (sp)+,a0
        rte

; ============================================================================
; Data / BSS
; ============================================================================

        .data
        .phrase

        .bss
        .dphrase

listbuf:    .ds.l   LISTSIZE*2
bmpupdate:  .ds.l   2
ticks:      .ds.l   1
a_hdb:      .ds.w   1
a_hde:      .ds.w   1
a_vdb:      .ds.w   1
a_vde:      .ds.w   1
width:      .ds.w   1
height:     .ds.w   1

_vidmem:
        .ds.b   64000
vidend:

        .end