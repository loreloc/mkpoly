
extern getpagesize
extern mprotect

; protection mode flags
%define PROT_NONE  0x0
%define PROT_READ  0x1
%define PROT_WRITE 0x2
%define PROT_EXEC  0x4

; prefixes and opcodes of 8 invertible instructions:
;   instructions |   inverted instructions
; - add reg, reg | - sub reg, reg
; - sub reg, reg | - add reg, reg
; - xor reg, reg | - xor reg, reg
; - add reg, i32 | - sub reg, i32
; - sub reg, i32 | - add reg, i32
; - xor reg, i32 | - xor reg, i32
; - rol reg, i8  | - ror reg, i8
; - ror reg, i8  | - rol reg, i8
; - inc reg
; - dec reg
; - not reg
; - neg reg
%define OPCODE_ADD_RM  0x01
%define OPCODE_SUB_RM  0x29
%define OPCODE_XOR_RM  0x31
%define PREFIX_ASX_IMM 0x81
%define OPCODE_ADD_RI  0xC0
%define OPCODE_SUB_RI  0xE8
%define OPCODE_XOR_RI  0xF0
%define PREFIX_ROT_IMM 0xC1
%define OPCODE_ROL_RI  0xC0
%define OPCODE_ROR_RI  0xC8
%define PREFIX_INC_DEC 0xFF
%define OPCODE_INC_R   0xC0
%define OPCODE_DEC_R   0xC8
%define PREFIX_NOT_NEG 0xF7
%define OPCODE_NOT_R   0xD0
%define OPCODE_NEG_R   0xD8

; no operation x86 opcode
%define OPCODE_NOP 0x90

; the size of the encryption/decryption functions
%define POLY_FUNC_SIZE 0x100

; %1 the label of the section to decrypt
; %2 the size of the section to decrypt
%macro DECRYPTOR_SECTION 2
	push    r12
	push    r13
	call    getpagesize
	mov     rcx, rax
	sub     rcx, 1
	mov     rdi, %1
	mov     rsi, %2
	mov     rax, rdi
	add     rsi, rcx
	not     rcx
	and     rdi, rcx
	sub     rax, rdi
	add     rsi, rax
	and     rsi, rcx
	mov     r12, rdi
	mov     r13, rsi
	mov     edx, (PROT_READ | PROT_WRITE | PROT_EXEC)
	call    mprotect
	mov     rdi, %1
	lea     rsi, [rdi+%2]
.mkpoly_loop:
	mov     eax, [rdi    ]
	mov     ecx, [rdi+0x4]
	mov     edx, [rdi+0x8]
	mov     ebx, [rdi+0xC]
.mkpoly_func:
	times POLY_FUNC_SIZE db OPCODE_NOP
	mov     [rdi    ], eax
	mov     [rdi+0x4], ecx
	mov     [rdi+0x8], edx
	mov     [rdi+0xC], ebx
	add     rdi, 0x10
	cmp     rdi, rsi
	jne     .mkpoly_loop
	mov     rdi, r12
	mov     rsi, r13
	mov     edx, (PROT_READ | PROT_EXEC)
	call    mprotect
	pop     r13
	pop     r12
%endmacro

