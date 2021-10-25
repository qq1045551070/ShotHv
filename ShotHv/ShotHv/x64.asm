
VmxExitHandler PROTO

.CODE
ALIGN 16

; 宏定义
SAVESTATE MACRO
	push r15
	mov r15,rsp  ;先保存原始的栈顶(进入接管函数之前的RSP)
	add r15,8
	push r14
	push r13
	push r12
	push r11
	push r10
	push r9
	push r8
	push rdi
	push rsi
	push rbp
	push r15    ;rsp
	push rbx
	push rdx
	push rcx
	push rax
ENDM

LOADSTATE MACRO
	pop rax
	pop rcx
	pop rdx
	pop rbx
	add rsp, 8
	pop rbp
	pop rsi
	pop rdi
	pop r8
	pop r9
	pop r10
	pop r11
	pop r12
	pop r13
	pop r14
	pop r15
ENDM

public AsmVmxCall
AsmVmxCall PROC
	push rax
	push rcx
	push rdx
	push rbx
	push rsi
	push rdi
	push r8
	push r9
	push r10
	push r11
	push r12
	push r13
	push r14
	push r15 ;pushaq

	pushfq

	mov rax,rcx
	vmcall ; 调用 VMCALL
	
	popfq
	
	pop r15
	pop r14
	pop r13
	pop r12
	pop r11
	pop r10
	pop r9
	pop r8
	pop rdi
	pop rsi
	pop rbx
	pop rdx
	pop rcx
	pop rax ;popaq
	
	ret
AsmVmxCall ENDP

public AsmStackPointer;
AsmStackPointer PROC
	mov rax, rsp
	add rax, sizeof(QWORD)
	mov [rcx], rax;
	ret
AsmStackPointer ENDP

public AsmNextInstructionPointer;
AsmNextInstructionPointer PROC
	mov rax, [rsp];
	mov [rcx], rax;
	ret
AsmNextInstructionPointer ENDP

public AsmCallVmxExitHandler;
AsmCallVmxExitHandler PROC
	cli
	SAVESTATE		;保存现场
	mov   rcx,rsp   ;把栈顶给rcx

	sub   rsp,0100h			; 开辟缓冲空间
	call  VmxExitHandler	; 调用 VmxExitHandler
	add   rsp,0100h

	LOADSTATE		;恢复现场
	sti
__do_resume:
	vmresume;   返回到VM non-root(返回到Guest环境里继续执行)
	ret
AsmCallVmxExitHandler ENDP

public __readcs;
__readcs PROC
	xor rax, rax;
	mov rax, cs;
	ret;
__readcs ENDP

public __readds;
__readds PROC
	xor rax, rax;
	mov rax, ds;
	ret;
__readds ENDP

public __readss;
__readss PROC
	xor rax, rax;
	mov rax, ss;
	ret;
__readss ENDP

public __reades;
__reades PROC
	xor rax, rax;
	mov rax, es;
	ret;
__reades ENDP

public __readfs;
__readfs PROC
	xor rax, rax;
	mov rax, fs;
	ret;
__readfs ENDP

public __readgs;
__readgs PROC
	xor rax, rax;
	mov rax, gs;
	ret;
__readgs ENDP

public __sldt;
__sldt PROC
	xor rax, rax;
	sldt rax;
	ret;
__sldt ENDP

public __sgdt;
__sgdt PROC
	xor rax, rax;
	mov rax, rcx;
	sgdt [rax];
	ret;
__sgdt ENDP

public __str;
__str PROC
	xor rax, rax;
	str rax;
	ret;
__str ENDP

public __writecr2;
__writecr2 PROC
	mov cr2, rcx;
	ret;
__writecr2 ENDP

public __writeds;
__writeds PROC
	mov ds, cx;
	ret;
__writeds ENDP

public __writees;
__writees PROC
	mov es, cx;
	ret;
__writees ENDP

public __writefs;
__writefs PROC
	mov fs, cx;
	ret;
__writefs ENDP

public AsmUpdateRspAndRip;
AsmUpdateRspAndRip PROC
	mov rsp,rcx
	jmp rdx
	ret
AsmUpdateRspAndRip ENDP

; AsmReloadGdtr (PVOID GdtBase (rcx), ULONG GdtLimit (rdx) );
public AsmReloadGdtr
AsmReloadGdtr PROC
	push	rcx
	shl		rdx, 48
	push	rdx
	lgdt	fword ptr [rsp+6]	; do not try to modify stack selector with this ;)
	pop		rax
	pop		rax
	ret
AsmReloadGdtr ENDP

; AsmReloadIdtr (PVOID IdtBase (rcx), ULONG IdtLimit (rdx) );
public AsmReloadIdtr
AsmReloadIdtr PROC
	push	rcx
	shl		rdx, 48
	push	rdx
	lidt	fword ptr [rsp+6]
	pop		rax
	pop		rax
	ret
AsmReloadIdtr ENDP

public __invept;
__invept PROC
    invept rcx, OWORD PTR [rdx]
    ret
__invept ENDP

public __invvpid;
__invvpid PROC
    invvpid rcx, OWORD PTR [rdx]
    ret
__invvpid ENDP

END