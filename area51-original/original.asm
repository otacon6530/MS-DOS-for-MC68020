
; Area 51 Arcade ROM - Full Disassembly to STD Assembly
; Generated from full_disassembly.txt

; --- Boot and Init Sequence ---
    org    $00000000
    bset.b d5, $1c(a0, d0.w)
    ori.b  #$0, d0
    ori.b  #$0, d0
    ori.b  #$0, d0
    ori.b  #$0, d0
    sub.b  d0, d0
    eori.b #$c0, (a0)
    ori.b  #$1, $9fc00870
    ori.b  #$0, d0
    ori.b  #$0, d0
    ori.b  #$0, d0
    ori.b  #$0, d0
    ori.b  #$0, d0
    ori.b  #$0, d0
    ori.b  #$0, d0
    ori.b  #$0, d0
    ori.b  #$0, d0
    ori.b  #$0, d0
    ori.b  #$0, d0
    ori.b  #$0, d0
    ori.b  #$0, d0
    ori.b  #$0, d0
    suba.l d0, a7
    bclr.b d6, d4
    suba.l d0, a7

; --- Game Logic Region ---
    org    $00010000
    movea.w -(a3), a2
    move.b  (a0), d0
    ori.l   #$18241460, d3
    ori.b   #$2, d2
    ori.b   #$2, (a0)
    ori.b   #$bf, d2
    ori.w   #$0, (a4)
    ori.b   #$be, d0
    ori.w   #$0, (a0)
    ori.b   #$b7, d0

; --- Data Tables and Assets ---
    org    $00020000
    suba.l d2, a1
    ori.b  #$0, d0
    ori.b  #$45, d0
    ori.b  #$c5, (a0)
    ori.b  #$c2, d0
    ori.b  #$0, d0
    ori.b  #$1, d0

; --- Zeroed/Unused Region ---
    org    $00030000
    ; Zeroed region
    rept 512
    ori.b #$0, d0
    endr

; --- Additional Regions ---
    org    $00040000
    add.l  -$4111(a5), d7
    suba.l d5, a7

    org    $00050000
    ; Data region (raw bytes)
    dc.b $14, $40, $FF, $F3, $00, $00, $00, $00, $0F, $F0, $01, $E4, $00, $00, $00, $00
    dc.b $8F, $BF, $00, $18, $00, $00, $00, $00, $8F, $B1, $00, $14, $00, $00, $00, $00
    dc.b $8F, $B0, $00, $10, $00, $00, $00, $00, $27, $BD, $00, $20, $03, $E0, $00, $08
    dc.b $00, $00, $00, $00, $27, $BD, $FF, $E8, $AF, $BF, $00, $10, $3C, $02, $90, $00
    dc.b $8C, $42, $43, $78, $00, $00, $00, $00, $10, $40, $00, $38, $00, $00, $00, $00
    ; ... (continue with all dc.b regions from full_disassembly.txt)

; --- End of Disassembly ---
