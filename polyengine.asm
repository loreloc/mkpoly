
; cpu x86-64

%include "makepoly.inc"

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
	lea     r8, [rel mod_reg_rm]
	mov     r9d, 0xC
	mov     rdi, .encrypt_func
	lea     rbx, [rdi+POLY_FUNC_SIZE-0x6]
	mov     rsi, [rbp-0x30]
	add     rsi, [rbp-0x18]
	add     rsi, POLY_FUNC_SIZE
.encrypt_func_gen_loop:
	cmp     rdi, rbx
	ja      .encrypt_func_gen_end
	rdrand  eax
	and     eax, 0x7
	jmp     [.instr_jump_table+rax*8]
	; the jump table of the possible instructions
	align 8
	.instr_jump_table: dq .add_reg_reg,
	                   dq .sub_reg_reg,
	                   dq .xor_reg_reg,
	                   dq .add_reg_i32,
	                   dq .sub_reg_i32,
	                   dq .xor_reg_i32,
	                   dq .rol_reg_i8,
	                   dq .ror_reg_i8
.add_reg_reg:
	sub     rsi, 0x2
	rdrand  eax
	xor     edx, edx
	div     r9d
	mov     al, [r8+rdx]
	mov     dh, al
	mov     ah, OPCODE_ADD_RM
	mov     dl, OPCODE_SUB_RM
	xchg    al, ah
	mov     [rdi], ax
	mov     [rsi], dx
	add     rdi, 0x2
	jmp     .encrypt_func_gen_loop
.sub_reg_reg:
	sub     rsi, 0x2
	rdrand  eax
	xor     edx, edx
	div     r9d
	mov     al, [r8+rdx]
	mov     dh, al
	mov     ah, OPCODE_SUB_RM
	mov     dl, OPCODE_ADD_RM
	xchg    al, ah
	mov     [rdi], ax
	mov     [rsi], dx
	add     rdi, 0x2
	jmp     .encrypt_func_gen_loop
.xor_reg_reg:
	sub     rsi, 0x2
	rdrand  eax
	xor     edx, edx
	div     r9d
	mov     al, [r8+rdx]
	mov     ah, OPCODE_XOR_RM
	xchg    al, ah
	mov     [rdi], ax
	mov     [rsi], ax
	add     rdi, 0x2
	jmp     .encrypt_func_gen_loop
.add_reg_i32:
	sub     rsi, 0x6
	rdrand  ax
	mov     al, PREFIX_ASX_IMM
	and     ah, 0x3
	mov     dx, ax
	or      ah, OPCODE_ADD_RI
	or      dh, OPCODE_SUB_RI
	rdrand  ecx
	mov     [rdi    ], ax
	mov     [rsi    ], dx
	mov     [rdi+0x2], ecx
	mov     [rsi+0x2], ecx
	add     rdi, 0x6
	jmp     .encrypt_func_gen_loop
.sub_reg_i32:
	sub     rsi, 0x6
	rdrand  ax
	mov     al, PREFIX_ASX_IMM
	and     ah, 0x3
	mov     dx, ax
	or      ah, OPCODE_SUB_RI
	or      dh, OPCODE_ADD_RI
	rdrand  ecx
	mov     [rdi    ], ax
	mov     [rsi    ], dx
	mov     [rdi+0x2], ecx
	mov     [rsi+0x2], ecx
	add     rdi, 0x6
	jmp     .encrypt_func_gen_loop
.xor_reg_i32:
	sub     rsi, 0x6
	rdrand  ax
	mov     al, PREFIX_ASX_IMM
	and     ah, 0x3
	or      ah, OPCODE_XOR_RI
	rdrand  ecx
	mov     [rdi    ], ax
	mov     [rsi    ], ax
	mov     [rdi+0x2], ecx
	mov     [rsi+0x2], ecx
	add     rdi, 0x6
	jmp     .encrypt_func_gen_loop
.rol_reg_i8:
	sub     rsi, 0x3
	rdrand  ax
	mov     al, PREFIX_ROT_IMM
	and     ah, 0x3
	mov     dx, ax
	or      ah, OPCODE_ROL_RI
	or      dh, OPCODE_ROR_RI
	rdrand  cx
	and     cl, 0x1F
	or      cl, 0x01
	mov     [rdi    ], ax
	mov     [rsi    ], dx
	mov     [rdi+0x2], cl
	mov     [rsi+0x2], cl
	add     rdi, 0x3
	jmp     .encrypt_func_gen_loop
.ror_reg_i8:
	sub     rsi, 0x3
	rdrand  ax
	mov     al, PREFIX_ROT_IMM
	and     ah, 0x3
	mov     dx, ax
	or      ah, OPCODE_ROR_RI
	or      dh, OPCODE_ROL_RI
	rdrand  cx
	and     cl, 0x1F
	or      cl, 0x01
	mov     [rdi    ], ax
	mov     [rsi    ], dx
	mov     [rdi+0x2], cl
	mov     [rsi+0x2], cl
	add     rdi, 0x3
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
	mov     rsp, rbp
	pop     rbp
	ret

