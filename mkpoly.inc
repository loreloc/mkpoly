
extern getpagesize
extern mprotect

; protection mode flags
%define PROT_NONE  0x0
%define PROT_READ  0x1
%define PROT_WRITE 0x2
%define PROT_EXEC  0x4

; no operation x86 opcode
%define OPCODE_NOP 0x90

; the size of the encryption/decryption functions
%define MKPOLY_FUNC_SIZE 0x100

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
	times MKPOLY_FUNC_SIZE db OPCODE_NOP
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

