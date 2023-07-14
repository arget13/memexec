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

// This function receives the address of a raw ELF in memory and loads it into the expected memory location (or 0x800000 if PIE)
// It also loads all the headers in their offsets with the needed permissions
void* load(void* elf)
{
    Elf64_Addr base = 0;
    void* rebase = NULL;
    Elf64_Ehdr* ehdr = elf;
    Elf64_Phdr* phdr = elf + ehdr->e_phoff;
    uint16_t phnum = ehdr->e_phnum;
    Elf64_Addr bss = search_section(elf, ".bss");

    // If the ELF file is position-independent (PIE), set the rebase address to 0x800000
    if(ehdr->e_type == ET_DYN) // PIE
        rebase = (void*) 0x800000;

    // Loop over each program header
    for(int i = 0; i < phnum; ++i)
    {
        // If the program header is not of type PT_LOAD, skip it
        if(phdr[i].p_type != PT_LOAD) continue;

        // Extract necessary information from the program header
        uint32_t   flags   = phdr[i].p_flags;
        Elf64_Off  offset  = phdr[i].p_offset;
        Elf64_Addr vaddr   = phdr[i].p_vaddr;
        uint64_t   filesz  = phdr[i].p_filesz;
        uint64_t   memsz   = phdr[i].p_memsz;
        Elf64_Addr aligned = vaddr & (~0xfff);

        // Convert the ELF permissions to mmap permissions
        uint32_t prot = ((flags & PF_R) ? PROT_READ  : 0) |
                        ((flags & PF_W) ? PROT_WRITE : 0) |
                        ((flags & PF_X) ? PROT_EXEC  : 0);

        // Adjust the file size and memory size for alignment
        filesz += vaddr - aligned;
        memsz  += vaddr - aligned;
        offset -= vaddr - aligned;

        // Map the segment into memory
        mmap(rebase + aligned, memsz, PROT_READ | PROT_WRITE,
             MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);

        // If this is the first segment, set the base address
        if(offset == 0) base = aligned;

        // If the .bss section is within this segment, remove the size of bss to leave it with 0s
        if(bss != 0 && (bss >= aligned && bss < (aligned + filesz)))
            filesz = bss - aligned;

        // Copy the segment from the ELF file to the memory map
        memcpy(rebase + aligned, elf + offset, filesz);

        // Set the permissions of the memory map
        mprotect(rebase + aligned, filesz, prot);
    }

    // Return the base address of the loaded ELF file
    return rebase + base;
}

// This function receives the fs path of an ELF and a memory address and loads the ELF in that address
// It also loads all the headers in their offsets with the needed permissions
void loadfile(char* path, Elf64_Addr rebase)
{
    Elf64_Ehdr ehdr;
    Elf64_Phdr* phdr;
    uint16_t phnum;
    Elf64_Addr bss;
    uint64_t flen;
    Elf64_Addr highest = 0;

    // Open the ELF file
    int f = open(path, O_RDONLY);
    // Read the ELF header
    read(f, &ehdr, sizeof(ehdr));
    // Get the number of program headers
    phnum = ehdr.e_phnum;
    // Allocate memory for the program headers
    phdr = malloc(sizeof(*phdr) * phnum);
    // Read the program headers from the file
    pread(f, phdr, sizeof(*phdr) * phnum, ehdr.e_phoff);
    // Get the length of the file
    flen = lseek(f, 0, SEEK_END);
    // Find the .bss section in the file
    bss = search_section_file(f, ".bss");

    // Loop over each program header
    for(int i = 0; i < phnum; ++i)
    {
        // If the program header is not of type PT_LOAD, skip it
        if(phdr[i].p_type != PT_LOAD) continue;

        // Extract necessary information from the program header
        uint32_t   flags   = phdr[i].p_flags;
        Elf64_Off  offset  = phdr[i].p_offset;
        Elf64_Addr vaddr   = phdr[i].p_vaddr;
        uint64_t   filesz  = phdr[i].p_filesz;
        void*      aligned = (void*) (vaddr & (~0xfff));

        // Convert the ELF permissions to mmap permissions
        uint32_t prot = ((flags & PF_R) ? PROT_READ  : 0) |
                        ((flags & PF_W) ? PROT_WRITE : 0) |
                        ((flags & PF_X) ? PROT_EXEC  : 0);

        // Adjust the file size and offset for alignment
        filesz += vaddr - (Elf64_Addr) aligned;
        offset -= vaddr - (Elf64_Addr) aligned;

        // Map the segment into memory
        mmap(rebase + aligned, filesz, prot, MAP_PRIVATE | MAP_FIXED, f, offset);

        // If the .bss section is within this segment, zero it out
        if(bss != 0 && (bss >= vaddr && bss < (vaddr + filesz)))
        {
            uint64_t bss_size = ((filesz + 0xfff) & (~0xfff)) - (bss - (Elf64_Addr) aligned);
            memset((void*) rebase + bss, '\0', bss_size);
        }
    }
    close(f);
}

// Given the address of a raw ELF in memory and the name of a section, return the address of that section
Elf64_Addr search_section(void* elf, char* section)
{
    Elf64_Ehdr* ehdr = elf;
    Elf64_Shdr* shdr = elf + ehdr->e_shoff;
    uint16_t shnum = ehdr->e_shnum;
    uint16_t shstrndx = ehdr->e_shstrndx;

    // Get the section header string table, which holds the names of the sections
    char* shstrtab = elf + shdr[shstrndx].sh_offset;

    // Loop over each section header
    for(int i = 0; i < shnum; ++i)
        // If the name of the section matches the requested section, return its address
        if(!strcmp(&shstrtab[shdr[i].sh_name], section))
            return shdr[i].sh_addr;
    return 0;
}

// Given the file descriptor of an ELF file and the name of a section, return the address of that section
Elf64_Addr search_section_file(int f, char* section)
{
    Elf64_Ehdr ehdr;
    Elf64_Shdr* shdr;
    uint16_t shnum;
    uint16_t shstrndx;
    char* shstrtab;

    // Read the ELF header from the file
    pread(f, &ehdr, sizeof(ehdr), 0);
    // Get the number of section headers and allocate memory to hold them
    shnum = ehdr.e_shnum;
    shdr = malloc(sizeof(*shdr) * shnum);
    // Get the index of the section header string table
    shstrndx = ehdr.e_shstrndx;
    // Read the section headers from the file
    pread(f, shdr, sizeof(*shdr) * shnum, ehdr.e_shoff);

    // Allocate memory to hold the section header string table and read it from the file
    shstrtab = malloc(shdr[shstrndx].sh_size);
    pread(f, shstrtab, shdr[shstrndx].sh_size, shdr[shstrndx].sh_offset);

    // Loop over each section header
    for(int i = 0; i < shnum; ++i)
        // If the name of the section matches the requested section, free the allocated memory and return its address
        if(!strcmp(&shstrtab[shdr[i].sh_name], section))
        {
            free(shstrtab);
            free(shdr);
            return shdr[i].sh_addr;
        }

    // If the section was not found, free the allocated memory and return 0
    free(shstrtab);
    free(shdr);
    return 0;
}

// Given the size of an ELF file, read it from standard input into a buffer in memory
void* read_elf(size_t size)
{
    // Declare variables to hold the number of bytes read and the current index into the buffer
    size_t r = 0, idx = 0;
    // Allocate a buffer in memory to hold the ELF file
    uint8_t* addr = mmap(NULL, size, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    
    // Loop until the entire file has been read into the buffer (to avoid underflow: Reading faster than writing the file in the FD)
    do
    {
        // Read from standard input into the buffer
        // The number of bytes to read is the remaining size of the file
        r = read(0, &addr[idx], size);
        // Update the index and remaining size
        idx  += r;
        size -= r;
    }
    while(size);

    // Return the buffer containing the ELF file
    return addr;
}

// Find the base address of the dynamic linker (also known as ld-linux.so) in the memory space of the current process.
void* ld_addr()
{
    // Open the /proc/self/maps file for reading. This file contains the memory map of the process.
    FILE* f = fopen("/proc/self/maps", "rb");
    char buf[1024];
    void* p;

    // Read the file line by line
    while(fgets(buf, sizeof buf, f))
    {
        // Check if the current line refers to the dynamic linker (ld)
        // by comparing the filename to "ld"
        if(strncmp(basename(strchr(buf, '/')), "ld", 2)) continue;

        // If the current line refers to the dynamic linker, extract the base address
        // The base address is the first hexadecimal number in the line
        sscanf(buf, "%lx", &p);

        // Close the file and return the base address
        fclose(f);
        return p;
    }

    // If the dynamic linker was not found in the memory map, close the file and return NULL
    fclose(f);
    return NULL;
}


int main()
{
    // Initialize variables
    int argc = 0;
    char** argv, *args;

    // Auxiliary vector, a mechanism to transfer certain kernel-level information to user processes
    uint64_t auxv[8 * 2];
    char interp[128];
    char* stack;
    void** sp;
    void* elf_addr;
    Elf64_Addr base;
    uint64_t ldentry, entry, phnum, phentsize, phaddr;
    Elf64_Addr ldbase = (Elf64_Addr) ld_addr();

    // Open the current executable file
    int self = open("/proc/self/exe", O_RDONLY);
    // Read the interpreter path from the .interp section of the ELF file
    interp[pread(self, interp, sizeof(interp) - 1,
                 search_section_file(self, ".interp"))] = '\0';
    close(self);
    // Load the interpreter (dynamic linker) into the address where it is expected to be
    loadfile(interp, ldbase);

    int filesz;
    int argsz;
    // Start reading ELFs to be loaded from FD 0
    while(argc = 0, read(0, &argsz, sizeof(int)) == sizeof(int))
    {
        // If arguments are provided, read them and split into argv array
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

        // Create a new process using clone system call
        if(!syscall(SYS_clone, SIGCHLD, NULL, NULL, NULL, NULL))
        {
            // Read the ELF file into memory
            elf_addr = read_elf(filesz);
            // Load the ELF file positionning it in the needed position in memory & loading the headers
            base = (Elf64_Addr) load(elf_addr);

            // Extract necessary information from the ELF header
            ldentry   = ((Elf64_Ehdr*) ldbase)  ->e_entry + ldbase;
            entry     = ((Elf64_Ehdr*) elf_addr)->e_entry + base;
            phnum     = ((Elf64_Ehdr*) elf_addr)->e_phnum;
            phentsize = ((Elf64_Ehdr*) elf_addr)->e_phentsize;
            phaddr    = ((Elf64_Ehdr*) elf_addr)->e_phoff + base;
            munmap(elf_addr, filesz);

            // Allocate stack for the new process
            stack = mmap(NULL, 0x21000, PROT_READ | PROT_WRITE,
                         MAP_ANONYMOUS | MAP_PRIVATE | MAP_STACK, -1, 0);
            sp = (void**) &stack[0x21000];
            *--sp = NULL; // End of stack

            // Prepare auxiliary vector
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
            // Jump to the entry point of the interpreter
            #if defined(__x86_64__)
            asm volatile("mov %0, %%rsp;"
                         "jmp *%1;"
                         : : "r"(sp), "r"(ldentry));
            #elif defined(__aarch64__)
            asm volatile("mov sp, %0;"
                         "br  %1;"
                         : : "r"(sp), "r"(ldentry) : "x0");
            #endif
            __builtin_unreachable();
        }
        // Parent process waits for the child to finish and send a signal to wake up the parent process (in case it was stopped to leave stdin to the child)
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
