/* Compile with -znow */
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <elf.h>
#include <libgen.h>
#include <signal.h>
#include <syscall.h>

Elf64_Addr search_section(void* elf, char* section);
Elf64_Addr search_section_file(int f, char* section);

void* load(void* elf)
{
    Elf64_Addr base = 0;
    void* rebase = NULL;
    Elf64_Ehdr* ehdr = elf;
    Elf64_Phdr* phdr = elf + ehdr->e_phoff;
    uint16_t phnum = ehdr->e_phnum;
    Elf64_Addr bss = search_section(elf, ".bss");

    if(ehdr->e_type == ET_DYN) // PIE
        rebase = (void*) 0x800000;

    for(int i = 0; i < phnum; ++i)
    {
        if(phdr[i].p_type != PT_LOAD) continue;

        uint32_t   flags   = phdr[i].p_flags;
        Elf64_Off  offset  = phdr[i].p_offset;
        Elf64_Addr vaddr   = phdr[i].p_vaddr;
        uint64_t   filesz  = phdr[i].p_filesz;
        uint64_t   memsz   = phdr[i].p_memsz;
        Elf64_Addr aligned = vaddr & (~0xfff);

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

void loadfile(char* path, Elf64_Addr rebase)
{
    Elf64_Ehdr ehdr;
    Elf64_Phdr* phdr;
    uint16_t phnum;
    Elf64_Addr bss;
    uint64_t flen;
    Elf64_Addr highest = 0;

    int f = open(path, O_RDONLY);
    read(f, &ehdr, sizeof(ehdr));
    phnum = ehdr.e_phnum;
    phdr = malloc(sizeof(*phdr) * phnum);
    pread(f, phdr, sizeof(*phdr) * phnum, ehdr.e_phoff);
    flen = lseek(f, 0, SEEK_END);
    bss = search_section_file(f, ".bss");

    for(int i = 0; i < phnum; ++i)
    {
        if(phdr[i].p_type != PT_LOAD) continue;

        uint32_t   flags   = phdr[i].p_flags;
        Elf64_Off  offset  = phdr[i].p_offset;
        Elf64_Addr vaddr   = phdr[i].p_vaddr;
        uint64_t   filesz  = phdr[i].p_filesz;
        void*      aligned = (void*) (vaddr & (~0xfff));

        uint32_t prot = ((flags & PF_R) ? PROT_READ  : 0) |
                        ((flags & PF_W) ? PROT_WRITE : 0) |
                        ((flags & PF_X) ? PROT_EXEC  : 0);

        filesz += vaddr - (Elf64_Addr) aligned;
        offset -= vaddr - (Elf64_Addr) aligned;

        mmap(rebase + aligned, filesz, prot, MAP_PRIVATE | MAP_FIXED, f, offset);

        if(bss != 0 && (bss >= vaddr && bss < (vaddr + filesz)))
        {
            uint64_t bss_size = ((filesz + 0xfff) & (~0xfff)) - (bss - (Elf64_Addr) aligned);
            memset((void*) rebase + bss, '\0', bss_size);
        }
    }
    close(f);
}

Elf64_Addr search_section(void* elf, char* section)
{
    Elf64_Ehdr* ehdr = elf;
    Elf64_Shdr* shdr = elf + ehdr->e_shoff;
    uint16_t shnum = ehdr->e_shnum;
    uint16_t shstrndx = ehdr->e_shstrndx;
    char* shstrtab = elf + shdr[shstrndx].sh_offset;

    for(int i = 0; i < shnum; ++i)
        if(!strcmp(&shstrtab[shdr[i].sh_name], section))
            return shdr[i].sh_addr;
    return 0;
}

Elf64_Addr search_section_file(int f, char* section)
{
    Elf64_Ehdr ehdr;
    Elf64_Shdr* shdr;
    uint16_t shnum;
    uint16_t shstrndx;
    char* shstrtab;

    pread(f, &ehdr, sizeof(ehdr), 0);
    shnum = ehdr.e_shnum;
    shdr = malloc(sizeof(*shdr) * shnum);
    shstrndx = ehdr.e_shstrndx;
    pread(f, shdr, sizeof(*shdr) * shnum, ehdr.e_shoff);

    shstrtab = malloc(shdr[shstrndx].sh_size);
    pread(f, shstrtab, shdr[shstrndx].sh_size, shdr[shstrndx].sh_offset);

    for(int i = 0; i < shnum; ++i)
        if(!strcmp(&shstrtab[shdr[i].sh_name], section))
        {
            free(shstrtab);
            free(shdr);
            return shdr[i].sh_addr;
        }

    free(shstrtab);
    free(shdr);
    return 0;
}

void* read_elf(size_t size)
{
    size_t r = 0, idx = 0;
    uint8_t* addr = mmap(NULL, size, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);;
    do
    {
        r = read(0, &addr[idx], size);
        idx  += r;
        size -= r;
    }
    while(size);

    return addr;
}

void* ld_addr()
{
    FILE* f = fopen("/proc/self/maps", "rb");
    char buf[1024];
    void* p;
    while(fgets(buf, sizeof buf, f))
    {
        if(strncmp(basename(strchr(buf, '/')), "ld", 2)) continue;
        sscanf(buf, "%lx", &p);
        fclose(f);
        return p;
    }
    fclose(f);
    return NULL;
}

int main()
{
    int argc = 0;
    char** argv, *args;

    uint64_t auxv[8 * 2];
    char interp[128];
    char* stack;
    void** sp;
    void* elf_addr;
    Elf64_Addr base;
    uint64_t ldentry, entry, phnum, phentsize, phaddr;
    Elf64_Addr ldbase = (Elf64_Addr) ld_addr();

    int self = open("/proc/self/exe", O_RDONLY);
    interp[pread(self, interp, sizeof(interp) - 1,
                 search_section_file(self, ".interp"))] = '\0';
    close(self);
    loadfile(interp, ldbase);

    int filesz;
    int argsz;
    while(argc = 0, read(0, &argsz, sizeof(int)) == sizeof(int))
    {
        if(argsz != 0)
        {
            args = calloc(argsz, sizeof(char));
            read(0, args, argsz);
            argv = malloc(16);
            argv[argc++] = args;
            while((argv[argc++] = strchr(argv[argc - 1], '\0') + 1) < &args[argsz])
                argv = realloc(argv, sizeof(void*) * (argc + 1));
            argc--;
        }
        read(0, &filesz, sizeof(int));

        if(!syscall(SYS_clone, SIGCHLD, NULL, NULL, NULL, NULL))
        {
            elf_addr = read_elf(filesz);
            base = (Elf64_Addr) load(elf_addr);

            ldentry   = ((Elf64_Ehdr*) ldbase)  ->e_entry + ldbase;
            entry     = ((Elf64_Ehdr*) elf_addr)->e_entry + base;
            phnum     = ((Elf64_Ehdr*) elf_addr)->e_phnum;
            phentsize = ((Elf64_Ehdr*) elf_addr)->e_phentsize;
            phaddr    = ((Elf64_Ehdr*) elf_addr)->e_phoff + base;
            munmap(elf_addr, filesz);

            stack = mmap(NULL, 0x21000, PROT_READ | PROT_WRITE,
                         MAP_ANONYMOUS | MAP_PRIVATE | MAP_STACK, -1, 0);
            sp = (void**) &stack[0x21000];
            *--sp = NULL; // End of stack

            if(argc % 2)
                *--sp = NULL; // Keep stack aligned
            auxv[ 0] = 0x06; auxv[ 1] = 0x1000;    // AT_PAGESZ
            auxv[ 2] = 0x19; auxv[ 3] = ldentry;   // AT_RANDOM (whatever)
            auxv[ 4] = 0x09; auxv[ 5] = entry;     // AT_ENTRY
            auxv[ 6] = 0x07; auxv[ 7] = ldbase;    // AT_BASE
            auxv[ 8] = 0x05; auxv[ 9] = phnum;     // AT_PHNUM
            auxv[10] = 0x04; auxv[11] = phentsize; // AT_PHENT
            auxv[12] = 0x03; auxv[13] = phaddr;    // AT_PHDR
            auxv[14] =    0; auxv[15] = 0;         // End of auxv
            sp -= sizeof(auxv) / sizeof(*auxv); memcpy(sp, auxv, sizeof(auxv));
            *--sp = NULL; // End of envp
            *--sp = NULL; // End of argv
            sp -= argc; memcpy(sp, argv, argc * 8);
            *(size_t*) --sp = argc;

            if(argsz)
                free(argv);
            dup2(3, 0);
            #if defined(__x86_64__)
            asm volatile("mov %0, %%rsp;"
                         "jmp *%1;"
                         : : "r"(sp), "r"(ldentry));
            #elif defined(__aarch64__)
            asm volatile("mov x0, sp;"
                         "sub sp, sp, x0;"
                         "add sp, sp, %0;"
                         "br  %1;"
                         : : "r"(sp), "r"(ldentry) : "x0");
            #endif
            __builtin_unreachable();
        }
        wait(NULL);
        kill(getppid(), SIGCONT);

        if(argsz)
        {
            free(args);
            free(argv);
        }
        continue;
    }
    _exit(0);
}
