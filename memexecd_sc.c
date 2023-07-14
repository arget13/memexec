/* Compile with -fno-stack-protector -nostdlib */
#include <elf.h>
// #include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>

#if defined(__x86_64__)
    #define JMP(addr) asm volatile("jmp *%0;" : : "r"(addr))
    #define SP           "rsp"
#elif defined(__aarch64__)
    #define JMP(addr) asm volatile("br   %0;" : : "r"(addr))
    #define SP           "sp"
#endif

#define O_RDONLY 0
#define AT_FDCWD -100
int        openat(int, const char*, int);
void*      load(void*, Elf64_Addr, int*);
Elf64_Addr search_section(void*, char*, int);
void*      read_elf(size_t);
void*      map_file(const char*, size_t*);
void       alloca_free(size_t);

int clone(unsigned long, unsigned long, int*, int*, unsigned long);
int wait4(pid_t, int*, int, void*);

#define IS_PIE    (1 << 0)
#define IS_STATIC (1 << 1)

#define AUXV_ENTRIES 8
#define PIE_BASE     0x400000
#define LD_BASE      0x40400000 // 1GiB distance wrt binary

int _start()
{
    Elf64_auxv_t* auxv;
    char* stack;
    void** newsp;
    Elf64_Addr base, ldbase;
    uint64_t ldentry, entry, phnum, phentsize, phaddr;
    int info;
    void* elf_addr, * self_addr;
    size_t flen, self_flen;
    off_t off = 0;

    self_addr = map_file("/proc/self/exe", &flen);
    elf_addr  = map_file(self_addr + search_section(self_addr, ".interp", 1), &flen);
    ldbase    = (Elf64_Addr) load(elf_addr, LD_BASE, NULL);
    munmap(self_addr, self_flen);
    munmap(elf_addr , flen);

    int filesz;
    int argsz;
    while(read(0, &argsz, sizeof(int)) == sizeof(int))
    {
        char** argv, *args;
        char* p;
        int argc, i;
        if(argsz != 0)
        {
            args = alloca(argsz);
            memset(args, '\0', argsz);
            read(0, args, argsz);
            for(argc = 1, p = args; (p += strlen(p) + 1) < &args[argsz]; ++argc);

            argv = alloca(sizeof(void*) * (argc + 1));
            for(i = 0, p = args; i < argc; ++i)
            {
                argv[i] = p;
                p += strlen(p) + 1;
            }
            argv[argc] = NULL;
        }
        read(0, &filesz, sizeof(int));

        if(!clone(SIGCHLD, 0, NULL, NULL, 0))
        {
            elf_addr  = read_elf(filesz);
            base      = (Elf64_Addr) load(elf_addr, PIE_BASE, &info);
            ldentry   = ((Elf64_Ehdr*) ldbase  )->e_entry + ldbase;
            entry     = ((Elf64_Ehdr*) elf_addr)->e_entry + base * !!(info & IS_PIE);
            phnum     = ((Elf64_Ehdr*) elf_addr)->e_phnum;
            phentsize = ((Elf64_Ehdr*) elf_addr)->e_phentsize;
            phaddr    = ((Elf64_Ehdr*) elf_addr)->e_phoff + base;
            munmap(elf_addr, filesz);

            stack = (void*) mmap(NULL, 0x21000, PROT_READ | PROT_WRITE,
                                 MAP_ANONYMOUS | MAP_PRIVATE | MAP_STACK, -1, 0);
            newsp = (void**) &stack[0x21000];
            *--newsp = NULL; // End of stack

            if(argc % 2)
                *--newsp = NULL; // Keep stack aligned

            i = 0;
            newsp -= sizeof(*auxv) * AUXV_ENTRIES;
            auxv = (Elf64_auxv_t*) newsp;
            auxv[i].a_type = AT_PAGESZ; auxv[i++].a_un.a_val = 0x1000;
            auxv[i].a_type = AT_RANDOM; auxv[i++].a_un.a_val = entry;
            auxv[i].a_type = AT_ENTRY ; auxv[i++].a_un.a_val = entry;
            auxv[i].a_type = AT_BASE  ; auxv[i++].a_un.a_val = ldbase * !(info & IS_STATIC);
            auxv[i].a_type = AT_PHNUM ; auxv[i++].a_un.a_val = phnum;
            auxv[i].a_type = AT_PHENT ; auxv[i++].a_un.a_val = phentsize;
            auxv[i].a_type = AT_PHDR  ; auxv[i++].a_un.a_val = phaddr;
            auxv[i].a_type = AT_NULL  ; auxv[i++].a_un.a_val = 0;
            *--newsp = NULL; // End of envp
            *--newsp = NULL; // End of argv
            newsp -= argc; memcpy(newsp, argv, argc * sizeof(*argv));
            *(size_t*) --newsp = argc;

            dup2(3, 0);
            register volatile void* sp asm(SP);
            sp = newsp;
            if(info & IS_STATIC)
                JMP(entry);
            else
                JMP(ldentry);
            __builtin_unreachable();
        }
        // Without this we may eventually run out of stack
        // alloca() isn't magic ;)
        alloca_free(argsz);
        alloca_free(sizeof(void*) * (argc + 1));

        wait4(-1, NULL, 0, NULL);
        kill(getppid(), SIGCONT);
    }
    exit(0);
}

void* load(void* elf, Elf64_Addr rebase_pie, int* info)
{
    Elf64_Addr base = 0;
    void* rebase = NULL;
    Elf64_Ehdr* ehdr = elf;
    Elf64_Phdr* phdr = elf + ehdr->e_phoff;
    uint16_t phnum = ehdr->e_phnum;
    Elf64_Addr bss = search_section(elf, ".bss", 0);
    if(info != NULL)
        *info |= IS_STATIC;

    if(ehdr->e_type == ET_DYN) // PIE
    {
        if(info != NULL) *info |= IS_PIE;
        rebase = (void*) rebase_pie;
    }

    for(int i = 0; i < phnum; ++i)
    {
        if(phdr[i].p_type == PT_INTERP && info != NULL) *info &= ~IS_STATIC;
        if(phdr[i].p_type != PT_LOAD) continue;

        uint32_t   flags   = phdr[i].p_flags;
        Elf64_Off  offset  = phdr[i].p_offset;
        Elf64_Addr vaddr   = phdr[i].p_vaddr;
        uint64_t   filesz  = phdr[i].p_filesz;
        uint64_t   memsz   = phdr[i].p_memsz;
        Elf64_Addr aligned = vaddr & ~0xfff;

        uint32_t prot = ((flags & PF_R) ? PROT_READ  : 0) |
                        ((flags & PF_W) ? PROT_WRITE : 0) |
                        ((flags & PF_X) ? PROT_EXEC  : 0);

        filesz += vaddr - aligned;
        memsz  += vaddr - aligned;
        offset -= vaddr - aligned;
        mmap(rebase + aligned, memsz, PROT_READ | PROT_WRITE,
             MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);
        if(offset == 0) base = aligned;

        if(bss != 0 && (bss >= aligned && bss < (aligned + filesz)))
            filesz = bss - aligned;
        memcpy(rebase + aligned, elf + offset, filesz);

        mprotect(rebase + aligned, filesz, prot);
    }

    return rebase + base;
}

void* map_file(const char* path, size_t* sz)
{
    int f;
    void* addr;

    f = openat(AT_FDCWD, path, O_RDONLY);
    *sz = lseek(f, 0, SEEK_END);
    addr = mmap(NULL, *sz, PROT_READ, MAP_PRIVATE, f, 0);
    close(f);
    return addr;
}

Elf64_Addr search_section(void* elf, char* section, int offset)
{
    Elf64_Ehdr* ehdr = elf;
    Elf64_Shdr* shdr = elf + ehdr->e_shoff;
    uint16_t shnum = ehdr->e_shnum;
    uint16_t shstrndx = ehdr->e_shstrndx;
    char* shstrtab = elf + shdr[shstrndx].sh_offset;

    for(int i = 0; i < shnum; ++i)
        if(!strcmp(&shstrtab[shdr[i].sh_name], section))
        {
            if(offset)
                return shdr[i].sh_offset;
            return shdr[i].sh_addr;
        }
    return 0;
}

void* read_elf(size_t size)
{
    size_t r = 0, idx = 0;
    uint8_t* addr = (void*) mmap(NULL, size, PROT_READ | PROT_WRITE,
                                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    do
    {
        r = read(0, &addr[idx], size);
        idx  += r;
        size -= r;
    }
    while(size);

    return addr;
}

#include <sys/types.h>
#include <sys/syscall.h>

#if defined(__x86_64__)
    #define SYSCALL_ARG0 "rdi"
    #define SYSCALL_ARG1 "rsi"
    #define SYSCALL_ARG2 "rdx"
    #define SYSCALL_ARG3 "r10"
    #define SYSCALL_ARG4 "r8"
    #define SYSCALL_ARG5 "r9"
    #define SYSCALL_NR   "rax"
    #define SYSCALL_RET  "rax"
    #define NAKED        __attribute__((naked))
    #define NAKED_RET    "ret;"
    #define SYSCALL_INST "syscall;"
    #define XCHG_RCX_R10 asm volatile("xchg %rcx, %r10;")
#elif defined(__aarch64__)
    #define SYSCALL_ARG0 "x0"
    #define SYSCALL_ARG1 "x1"
    #define SYSCALL_ARG2 "x2"
    #define SYSCALL_ARG3 "x3"
    #define SYSCALL_ARG4 "x4"
    #define SYSCALL_ARG5 "x5"
    #define SYSCALL_NR   "x8"
    #define SYSCALL_RET  "x0"
    #define NAKED
    #define NAKED_RET
    #define SYSCALL_INST "svc #0;"
    #define XCHG_RCX_R10
#endif

inline __attribute__((always_inline))
void* alloca(size_t s)
{
    register void* sp asm(SP);
    s += 0xf;
    s &= ~0xf;
    sp -= s;
    return sp;
}
inline __attribute__((always_inline))
void alloca_free(size_t s)
{
    register void* sp asm(SP);
    s += 0xf;
    s &= ~0xf;
    sp += s;
}
size_t strlen(const char* str)
{
    size_t i;
    for(i = 0; str[i]; ++i);
    return i;
}
int strcmp(const char* str1, const char* str2)
{
    volatile int r;
    for(size_t i = 0; !(r = (str1[i] - str2[i])) && str1[i] && str2[i]; ++i);
    return r;
}
void* memset(void* p, int c, size_t n)
{
    for(volatile size_t i = 0; i < n; ++i)
        ((char*) p)[i] = c;
    return p;
}
void* memcpy(void* dest, const void* src, size_t n)
{
    for(volatile size_t i = 0; i < n; ++i)
        ((char*) dest)[i] = ((char*) src)[i];
    return dest;
}

inline __attribute__((always_inline))
int mprotect(void* addr, size_t len, int prot)
{
    register volatile unsigned long nr asm(SYSCALL_NR);
    register volatile void*         a0 asm(SYSCALL_ARG0);
    register volatile unsigned long a1 asm(SYSCALL_ARG1);
    register volatile unsigned long a2 asm(SYSCALL_ARG2);
    register volatile unsigned long r  asm(SYSCALL_RET);
    a1 = len;
    a2 = prot;
    a0 = addr;
    nr = SYS_mprotect;
    asm volatile(SYSCALL_INST);
    return (long) r;
}
inline __attribute__((always_inline))
long lseek(int fd, off_t off, int whence)
{
    register volatile unsigned long nr asm(SYSCALL_NR);
    register volatile unsigned long a0 asm(SYSCALL_ARG0);
    register volatile unsigned long a1 asm(SYSCALL_ARG1);
    register volatile unsigned long a2 asm(SYSCALL_ARG2);
    register volatile unsigned long r  asm(SYSCALL_RET);
    a1 = off;
    a2 = whence;
    a0 = fd;
    nr = SYS_lseek;
    asm volatile(SYSCALL_INST);
    return r;
}
inline __attribute__((always_inline))
int dup2(int fd1, int fd2)
{
    register volatile unsigned long nr asm(SYSCALL_NR);
    register volatile unsigned long a0 asm(SYSCALL_ARG0);
    register volatile unsigned long a1 asm(SYSCALL_ARG1);
    register volatile unsigned long a2 asm(SYSCALL_ARG2);
    register volatile unsigned long r  asm(SYSCALL_RET);
    a1 = fd2;
    a2 = 0;
    a0 = fd1;
    nr = SYS_dup3;
    asm volatile(SYSCALL_INST);
    return r;
}
inline __attribute__((always_inline))
int kill(pid_t pid, int sig)
{
    register volatile unsigned long nr asm(SYSCALL_NR);
    register volatile unsigned long a0 asm(SYSCALL_ARG0);
    register volatile unsigned long a1 asm(SYSCALL_ARG1);
    register volatile unsigned long r  asm(SYSCALL_RET);
    a1 = sig;
    a0 = pid;
    nr = SYS_kill;
    asm volatile(SYSCALL_INST);
    return r;
}
inline __attribute__((always_inline))
int wait4(pid_t pid, int* wstatus, int options, void* rusage)
{
    register volatile unsigned long nr asm(SYSCALL_NR);
    register volatile unsigned long a0 asm(SYSCALL_ARG0);
    register volatile int*          a1 asm(SYSCALL_ARG1);
    register volatile unsigned long a2 asm(SYSCALL_ARG2);
    register volatile void*         a3 asm(SYSCALL_ARG3);
    register volatile unsigned long r  asm(SYSCALL_RET);
    a1 = wstatus;
    a2 = options;
    a3 = rusage;
    a0 = pid;
    nr = SYS_wait4;
    asm volatile(SYSCALL_INST);
    return r;
}
inline __attribute__((always_inline))
int clone(unsigned long a, unsigned long b, int* c, int* d, unsigned long e)
{
    register volatile unsigned long nr asm(SYSCALL_NR);
    register volatile unsigned long a0 asm(SYSCALL_ARG0);
    register volatile unsigned long a1 asm(SYSCALL_ARG1);
    register volatile int*          a2 asm(SYSCALL_ARG2);
    register volatile int*          a3 asm(SYSCALL_ARG3);
    register volatile unsigned long a4 asm(SYSCALL_ARG4);
    register volatile unsigned long r  asm(SYSCALL_RET);
    a1 = b;
    a2 = c;
    a3 = d;
    a4 = e;
    a0 = a;
    nr = SYS_clone;
    asm volatile(SYSCALL_INST);
    return r;
}
inline __attribute__((always_inline))
void exit(int s)
{
    register volatile unsigned long nr asm(SYSCALL_NR);
    register volatile unsigned long a0 asm(SYSCALL_ARG0);
    register volatile unsigned long r  asm(SYSCALL_RET);
    a0 = s;
    nr = SYS_exit;
    asm volatile(SYSCALL_INST);
    __builtin_unreachable();
}
inline __attribute__((always_inline))
pid_t getppid()
{
    register volatile unsigned long nr asm(SYSCALL_NR);
    register volatile unsigned long a0 asm(SYSCALL_ARG0);
    register volatile unsigned long r  asm(SYSCALL_RET);
    nr = SYS_getppid;
    asm volatile(SYSCALL_INST);
    return r;
}

NAKED
int openat(int fd, const char* path, int flags)
{
    register volatile unsigned long nr asm(SYSCALL_NR);
    nr = SYS_openat;
    asm volatile(SYSCALL_INST NAKED_RET);
}
NAKED
int close(int fd)
{
    register volatile unsigned long nr asm(SYSCALL_NR);
    nr = SYS_close;
    asm volatile(SYSCALL_INST NAKED_RET);
}
NAKED
int munmap(void* addr, size_t len)
{
    register volatile unsigned long nr asm(SYSCALL_NR);
    nr = SYS_munmap;
    asm volatile(SYSCALL_INST NAKED_RET);
}
NAKED
void* mmap(void* addr, size_t len, int prot, int flag, int fd, off_t off)
{
    register volatile unsigned long nr asm(SYSCALL_NR);
    XCHG_RCX_R10;
    nr = SYS_mmap;
    asm volatile(SYSCALL_INST NAKED_RET);
}
NAKED
ssize_t read(int fd, void* addr, size_t count)
{
    register volatile unsigned long nr asm(SYSCALL_NR);
    nr = SYS_read;
    asm volatile(SYSCALL_INST NAKED_RET);
}
NAKED
ssize_t pread(int fd, void* addr, size_t count, off_t off)
{
    register volatile unsigned long nr asm(SYSCALL_NR);
    XCHG_RCX_R10;
    nr = SYS_pread64;
    asm volatile(SYSCALL_INST NAKED_RET);
}
