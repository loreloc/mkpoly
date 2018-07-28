
; cpu x86-64

%include "makepoly.inc"

extern rand

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

global poly_engine

section .data
	; the table of all the possible ModRegRM fields allowed
	; Note that all the instructions are not-distructive
	;
	; Mod is always 0b11 because the aren't memory references
	; Reg denotes the source register
	; RM denotes the destination register
	;
	; Mod | Reg | RM
	;  11 | xxx | yyy
	;
	; eax | ecx
	; eax | edx
	; eax | ebx
	; ecx | eax
	; ecx | edx
	; ecx | ebx
	; edx | eax
	; edx | ecx
	; edx | ebx
	; ebx | eax
	; ebx | ecx
	; ebx | edx
	align 4
	mod_reg_rm: db 0xC8, 0xD0, 0xD8, 0xC1, 0xD1, 0xD9, 0xC2, 0xCA, 0xDA, 0xC3, 0xCB, 0xD3

section .text

; [in]  rdi : the executable data to modify
; [in]  rsi : the offset of the section to encrypt
; [in]  rdx : the size of the section to encrypt
; [in]  rcx : the offset of the section in which to place the decrypt function
; 
; [out] rax : 0 if everything went fine
;
poly_engine:
	push    rbp
	mov     rbp, rsp
	and     rsp, -0x10
	sub     rsp, 0x30
	push    r12
	push    r13
	push    r14
	push    r15
	; save the input arguments
	mov     [rbp-0x30], rdi
	mov     [rbp-0x28], rsi
	mov     [rbp-0x20], rdx
	mov     [rbp-0x18], rcx 
	; unprotect the encryption function buffer from write operations
	call    getpagesize
	mov     rcx, rax
	sub     rcx, 1
	mov     rdi, .encrypt_func
	mov     rsi, POLY_FUNC_SIZE
	mov     rax, rdi
	add     rsi, rcx
	not     rcx
	and     rdi, rcx
	sub     rax, rdi
	add     rsi, rax
	and     rsi, rcx
	mov     [rbp-0x10], rdi
	mov     [rbp-0x8 ], rsi
	mov     edx, (PROT_READ | PROT_WRITE | PROT_EXEC)
	call    mprotect
	test    rax, rax
	jnz     .quit
	; generate the encryption and decryption functions
	lea     r14, [rel mod_reg_rm]
	mov     r15d, 0xC
	mov     r12, .encrypt_func
	lea     rbx, [r12+POLY_FUNC_SIZE-0x6]
	mov     r13, [rbp-0x30]
	add     r13, [rbp-0x18]
	add     r13, POLY_FUNC_SIZE
.encrypt_func_gen_loop:
	cmp     r12, rbx
	ja      .encrypt_func_gen_end
	call    rand
	xor     edx, edx
	div     r15d
	jmp     [.instr_jump_table+rdx*8]
	; the jump table of the possible instructions
	align 8
	.instr_jump_table: dq .add_reg_reg,
	                   dq .sub_reg_reg,
	                   dq .xor_reg_reg,
	                   dq .add_reg_i32,
	                   dq .sub_reg_i32,
	                   dq .xor_reg_i32,
	                   dq .rol_reg_i8,
	                   dq .ror_reg_i8,
	                   dq .inc_reg,
	                   dq .dec_reg,
	                   dq .not_reg,
	                   dq .neg_reg
.add_reg_reg:
	sub     r13, 0x2
	call    rand
	xor     edx, edx
	div     r15d
	mov     al, [r14+rdx]
	mov     dh, al
	mov     ah, OPCODE_ADD_RM
	mov     dl, OPCODE_SUB_RM
	xchg    al, ah
	mov     [r12], ax
	mov     [r13], dx
	add     r12, 0x2
	jmp     .encrypt_func_gen_loop
.sub_reg_reg:
	sub     r13, 0x2
	call    rand
	xor     edx, edx
	div     r15d
	mov     al, [r14+rdx]
	mov     dh, al
	mov     ah, OPCODE_SUB_RM
	mov     dl, OPCODE_ADD_RM
	xchg    al, ah
	mov     [r12], ax
	mov     [r13], dx
	add     r12, 0x2
	jmp     .encrypt_func_gen_loop
.xor_reg_reg:
	sub     r13, 0x2
	call    rand
	xor     edx, edx
	div     r15d
	mov     al, [r14+rdx]
	mov     ah, OPCODE_XOR_RM
	xchg    al, ah
	mov     [r12], ax
	mov     [r13], ax
	add     r12, 0x2
	jmp     .encrypt_func_gen_loop
.add_reg_i32:
	sub     r13, 0x6
	call    rand
	mov     ecx, eax
	mov     al, PREFIX_ASX_IMM
	and     ah, 0x3
	mov     dx, ax
	or      ah, OPCODE_ADD_RI
	or      dh, OPCODE_SUB_RI
	mov     [r12    ], ax
	mov     [r13    ], dx
	mov     [r12+0x2], ecx
	mov     [r13+0x2], ecx
	add     r12, 0x6
	jmp     .encrypt_func_gen_loop
.sub_reg_i32:
	sub     r13, 0x6
	call    rand
	mov     ecx, eax
	mov     al, PREFIX_ASX_IMM
	and     ah, 0x3
	mov     dx, ax
	or      ah, OPCODE_SUB_RI
	or      dh, OPCODE_ADD_RI
	mov     [r12    ], ax
	mov     [r13    ], dx
	mov     [r12+0x2], ecx
	mov     [r13+0x2], ecx
	add     r12, 0x6
	jmp     .encrypt_func_gen_loop
.xor_reg_i32:
	sub     r13, 0x6
	call    rand
	mov     ecx, eax
	mov     al, PREFIX_ASX_IMM
	and     ah, 0x3
	or      ah, OPCODE_XOR_RI
	mov     [r12    ], ax
	mov     [r13    ], ax
	mov     [r12+0x2], ecx
	mov     [r13+0x2], ecx
	add     r12, 0x6
	jmp     .encrypt_func_gen_loop
.rol_reg_i8:
	sub     r13, 0x3
	call    rand
	mov     ecx, eax
	shr     ecx, 16
	mov     al, PREFIX_ROT_IMM
	and     ah, 0x3
	mov     dx, ax
	or      ah, OPCODE_ROL_RI
	or      dh, OPCODE_ROR_RI
	and     cl, 0x1F
	or      cl, 0x01
	mov     [r12    ], ax
	mov     [r13    ], dx
	mov     [r12+0x2], cl
	mov     [r13+0x2], cl
	add     r12, 0x3
	jmp     .encrypt_func_gen_loop
.ror_reg_i8:
	sub     r13, 0x3
	call    rand
	mov     ecx, eax
	shr     ecx, 16
	mov     al, PREFIX_ROT_IMM
	and     ah, 0x3
	mov     dx, ax
	or      ah, OPCODE_ROR_RI
	or      dh, OPCODE_ROL_RI
	and     cl, 0x1F
	or      cl, 0x01
	mov     [r12    ], ax
	mov     [r13    ], dx
	mov     [r12+0x2], cl
	mov     [r13+0x2], cl
	add     r12, 0x3
	jmp     .encrypt_func_gen_loop
.inc_reg:
	sub     r13, 0x2
	call    rand
	mov     al, PREFIX_INC_DEC
	and     ah, 0x3
	mov     dx, ax
	or      ah, OPCODE_INC_R
	or      dh, OPCODE_DEC_R
	mov     [r12], ax
	mov     [r13], dx
	add     r12, 0x2
	jmp     .encrypt_func_gen_loop
.dec_reg:
	sub     r13, 0x2
	call    rand
	mov     al, PREFIX_INC_DEC
	and     ah, 0x3
	mov     dx, ax
	or      ah, OPCODE_DEC_R
	or      dh, OPCODE_INC_R
	mov     [r12], ax
	mov     [r13], dx
	add     r12, 0x2
	jmp     .encrypt_func_gen_loop
.not_reg:
	sub     r13, 0x2
	call    rand
	mov     al, PREFIX_NOT_NEG
	and     ah, 0x3
	or      ah, OPCODE_NOT_R
	mov     [r12], ax
	mov     [r13], ax
	add     r12, 0x2
	jmp     .encrypt_func_gen_loop
.neg_reg:
	sub     r13, 0x2
	call    rand
	mov     al, PREFIX_NOT_NEG
	and     ah, 0x3
	or      ah, OPCODE_NEG_R
	mov     [r12], ax
	mov     [r13], ax
	add     r12, 0x2
	jmp     .encrypt_func_gen_loop
.encrypt_func_gen_end:
	; protect the encryption function buffer from write operations
	mov     rdi, [rbp-0x10]
	mov     rsi, [rbp-0x8 ]
	mov     edx, (PROT_READ | PROT_EXEC)
	call    mprotect
	test    rax, rax
	jnz     .quit
	; encrypt the executable data
	mov     rdi, [rbp-0x30]
	add     rdi, [rbp-0x28]
	mov     rcx, [rbp-0x20]
	lea     rsi, [rdi+rcx]
.encrypt_loop:
	mov     eax, [rdi    ]
	mov     ecx, [rdi+0x4]
	mov     edx, [rdi+0x8]
	mov     ebx, [rdi+0xC]
.encrypt_func:
	times POLY_FUNC_SIZE db OPCODE_NOP
	mov     [rdi    ], eax
	mov     [rdi+0x4], ecx
	mov     [rdi+0x8], edx
	mov     [rdi+0xC], ebx
	add     rdi, 0x10
	cmp     rdi, rsi
	jne     .encrypt_loop
	xor     rax, rax
.quit:
	pop     r15
	pop     r14
	pop     r13
	pop     r12
	mov     rsp, rbp
	pop     rbp
	ret

