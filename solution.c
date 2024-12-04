#define _GNU_SOURCE
#include <endian.h>
#include <sys/ptrace.h>
#include <linux/ptrace.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>

#define PIPE_NAME "pipe"

unsigned long long get_rip(int server_pid)
{
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, server_pid, 0, &regs);
    return regs.rip;
}

#define WORD_SIZE sizeof(long)
/**
 * Print `count` words from the tracee's memory, starting at `location`.
 * Prints it all in one line, so it is easier to manipulate later.
 * Prints in hex.
 * Prints to `file`
 * */
void get_mem_at(int server_pid, unsigned long long location, int count, char *buffer)
{
    for (int i = 0; i < count; i++) {
        long word = ptrace(PTRACE_PEEKDATA, server_pid, location + (i * WORD_SIZE), 0);
        for (int j = 0; j < WORD_SIZE; j++) {
            *buffer = word & 0xff;
            buffer += 1;
            word = word >> 8;
        }
    }
}

void get_mem_at_words(int server_pid, unsigned long long location, int count, unsigned long *buffer)
{
    for (int i = 0; i < count; i++) {
        long word = ptrace(PTRACE_PEEKDATA, server_pid, location + (i * WORD_SIZE), 0);
        buffer[i] = word;
    }
}

char *read_file(char *filename, int *size)
{
    FILE *file = fopen(filename, "r");
    fseek(file, 0, SEEK_END);
    int filesize = ftell(file);
    fseek(file, 0, SEEK_SET);

    *size = filesize;

    char *buffer = malloc(filesize);
    fread(buffer, filesize, 1, file);
    fclose(file);
    return buffer;
}

#define CHECK_WORD_COUNT 20
unsigned long long get_check_password_location(int server_pid)
{
    int code_len;
    char *code = read_file("tracy-server", &code_len);

    unsigned long long check_password_code_offset = 0x82cf0;
    unsigned long long known_code_offset;
    unsigned long long known_rip_offset;

    while (1) {
        unsigned long long rip = get_rip(server_pid);
        printf("Checking %llx...\n", rip);

        char memory[CHECK_WORD_COUNT * WORD_SIZE];

        get_mem_at(server_pid, rip, CHECK_WORD_COUNT, memory);
        char *index = memmem(code, code_len, memory, sizeof(memory));
        if (index) {
            known_code_offset = (index - code);
            known_rip_offset = rip;
            break;
        }

        ptrace(PTRACE_SINGLESTEP, server_pid, 0, 0);
        waitpid(server_pid, 0, __WALL);
    }
    free(code);

    unsigned long long check_password_rip = known_rip_offset - known_code_offset + check_password_code_offset;

    return check_password_rip;
}

void print_mem_at(int server_pid, unsigned long long location, int count)
{
    printf("-- Code at %llx --\n", location);
    for (int i = 0; i < count; i++) {
        long word = ptrace(PTRACE_PEEKDATA, server_pid, location + (i * WORD_SIZE), 0);
        word = htobe64(word); // Big endian so it prints in the same order as objdump.
        printf("%016lx", word);
    }
    printf("\n-- END Code --\n");
}

void write_words_at(int server_pid, unsigned long long location, int count, unsigned long *words)
{
    for (int i = 0; i < count; i++) {
        ptrace(PTRACE_POKEDATA, server_pid, location + (i * sizeof(*words)), words[i]);
    }
}

void print_registers(int server_pid)
{
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, server_pid, 0, &regs);
    printf("ds: %llx\n", regs.ds);
    printf("es: %llx\n", regs.es);
    printf("cs: %llx\n", regs.cs);
}

/**
 * Mmaps a new page to do whatever I want in. Executes the `syscall` instruction at `where`,
 * so that should be mapped and executable (`rip` for example)
 * */
unsigned long long mmap_me(int server_pid, unsigned long long where)
{
    unsigned long mmap_code[] = {
        be64toh(0x0f05000000000000)
    };
#define MMAP_CODE_LEN sizeof(mmap_code) / sizeof(unsigned long)
    // Save state
    struct user_regs_struct original_regs;
    ptrace(PTRACE_GETREGS, server_pid, 0, &original_regs);
    unsigned long long rip = original_regs.rip;
    unsigned long original_code[MMAP_CODE_LEN];
    get_mem_at_words(server_pid, where, MMAP_CODE_LEN, original_code);

    // Set registers
    struct user_regs_struct call_regs;
    memcpy(&call_regs, &original_regs, sizeof(original_regs));
    call_regs.rdi = 0; // addr
    call_regs.rsi = 0x1000; // length
    call_regs.rdx = PROT_EXEC | PROT_READ | PROT_WRITE; // prot
    call_regs.r10 = MAP_PRIVATE | MAP_ANONYMOUS; // flags
    call_regs.r8 = 0; // fd
    call_regs.r9 = 0; // offset
    call_regs.rax = 9; // mmap syscall

    call_regs.rip = where;
    // Execute code
    write_words_at(server_pid, where, MMAP_CODE_LEN, mmap_code);
    ptrace(PTRACE_SETREGS, server_pid, 0, &call_regs);

    for (int i = 0; i < MMAP_CODE_LEN; i++) {
        ptrace(PTRACE_SINGLESTEP, server_pid, 0, 0);
        waitpid(server_pid, 0, __WALL);
    }

    // Get return value
    struct user_regs_struct new_regs;
    ptrace(PTRACE_GETREGS, server_pid, 0, &new_regs);
    unsigned long long ret_value = new_regs.rax;

    // Restore state
    ptrace(PTRACE_SETREGS, server_pid, 0, &original_regs);
    write_words_at(server_pid, where, MMAP_CODE_LEN, original_code);

    return ret_value;
}

void write_jump_code(int server_pid, unsigned long long func_location, unsigned long long jump_location)
{
    /*
     * we're replacing "415741564154534881ec480100004889"
     * The last instruction is cut in half, so we preserve the first 2 bytes of it,
     * and we need to jump back to `func_location + 13`, to pop rax and continue
     * */

    /*
     * this is:
     * push rax
     * movabs rax, `jump_location`
     * jmp rax
     * pop rax
     *
     * .byte 48
     * .byte 89
     * */
    unsigned long jump_code[2];
    jump_code[0] = 0xb84850 | jump_location << (8 * 3);
    jump_code[1] = jump_location >> (8 * 5) | 0x894858e0ffull << (8 * 3);
    printf("jump code 0 : %lx\n", htobe64(jump_code[0]));
    printf("jump code 1 : %lx\n", htobe64(jump_code[1]));

    write_words_at(server_pid, func_location, 2, jump_code);
}

void write_my_code(int server_pid, unsigned long long location, unsigned long long jump_back_location)
{
    /*
     * Code means:
        cmp rsi, 6
        jne END
        cmp byte ptr [rdi], 'a'
        jne END
        cmp byte ptr [rdi+1], 'r'
        jne END
        cmp byte ptr [rdi+2], 'a'
        jne END
        cmp byte ptr [rdi+3], 'z'
        jne END
        cmp byte ptr [rdi+4], 'i'
        jne END
        cmp byte ptr [rdi+5], 'm'
        jne END
        pop rax
        mov rax, 1
        ret
        END:
        nop // Pad to get a qword
        nop
        nop
        nop
        nop
        nop

     * and then:
     * Stuff we wrote over for the jump
     * and then:
     * mov rax, `jump_back_location`,
     * jmp rax
     * */
    unsigned long my_code[] = {
        be64toh(0x4883FE06752C803F),
        be64toh(0x617527807F017275),
        be64toh(0x21807F0261751B80),
        be64toh(0x7F037A7515807F04),
        be64toh(0x69750F807F056D75),
        be64toh(0x095848C7C0010000),
        be64toh(0x00C3909090909090),
        be64toh(0x4157415641545348),
        be64toh(0x81ec480100009090),
        0,
        0
    };
#define MY_CODE_LEN sizeof(my_code) / sizeof(unsigned long)

    my_code[MY_CODE_LEN - 2] = 0xb848 | jump_back_location << (8 * 2);
    my_code[MY_CODE_LEN - 1] = jump_back_location >> (8 * 6) | 0xe0ffull << (8 * 2);

    write_words_at(server_pid, location, MY_CODE_LEN, my_code);
}

void wait_upon_rip(int server_pid, unsigned long long goal)
{
    while (get_rip(server_pid) != goal) {
        ptrace(PTRACE_SINGLESTEP, server_pid, 0, 0);
        waitpid(server_pid, 0, __WALL);
    }
}

int main(int argc, char *argv[])
{
    int server_pid = atoi(argv[1]);
    printf("attaching to pid %d\n", server_pid);
    int result = ptrace(PTRACE_ATTACH, server_pid, 0, 0);
    if (result != 0) {
        perror("Failed to attach to server");
        return 1;
    }
    int status;
    waitpid(server_pid, &status, __WALL);

    unsigned long long mmap_location = mmap_me(server_pid, get_rip(server_pid));
    printf("mmap_location: %llx\n", mmap_location);

    unsigned long long func_location = get_check_password_location(server_pid);
    printf("check_password location: %llx\n", func_location);

    printf("writing jump to %llx at %llx...\n", mmap_location, func_location);
    write_jump_code(server_pid, func_location, mmap_location);

    write_my_code(server_pid, mmap_location, func_location + 13);

    print_mem_at(server_pid, func_location, 20);
    print_mem_at(server_pid, mmap_location, 20);
    ptrace(PTRACE_SYSCALL, server_pid, 0, 0);

    while (1) {
        int status;
        waitpid(server_pid, &status, __WALL);
        if (!WIFSTOPPED(status)) {
            // Not really stopped?
            ptrace(PTRACE_SYSCALL, server_pid, 0, 0);
            continue;
        }
        if (!(WSTOPSIG(status) == (SIGTRAP | 0x80) || WSTOPSIG(status) == SIGTRAP)) {
            // Not a syscall.
            ptrace(PTRACE_SYSCALL, server_pid, 0, 0);
            continue;
        }
        struct ptrace_syscall_info info;
        memset(&info, 0, sizeof(info));
        int syscall_get_res = ptrace(PTRACE_GET_SYSCALL_INFO, server_pid, sizeof(info), &info);
        if (info.op == PTRACE_SYSCALL_INFO_ENTRY) {
            // Entry into syscall
            printf("syscall entry, number: %lld\n", info.entry.nr);
            if (info.entry.nr == 201) {
                printf("got a time() call, rip: %llx\n", get_rip(server_pid));
            }
        }
        ptrace(PTRACE_SYSCALL, server_pid, 0, 0);
    }
    return 0;

    unsigned int check_password_code_offset = 0x82cf0;
    unsigned int file_size = 0x820440;
    unsigned int jump_offset = -check_password_code_offset;

    printf("jump offset: %x\n", jump_offset);
    unsigned long jump_code[] = { be64toh(0xe9fff7d310909048) };

    printf("jump code: %lx\n", htobe64(jump_code[0]));

    // Jump Overrides 4157415641545348
    // So I need to execute 41574156415453
    // afterwards
    // write_words_at(server_pid, func_location, sizeof(jump_code) / sizeof(unsigned long), jump_code);
    unsigned long my_code[] = { be64toh(0x9090909090909090) }; // Syscall, so I can catch it and look at stuff.
    printf("writing code to %llx\n", func_location + jump_offset + 5);
    write_words_at(server_pid, func_location + jump_offset + 5, sizeof(my_code) / sizeof(unsigned long), my_code);
    print_mem_at(server_pid, func_location + jump_offset + 5, 100);

    ptrace(PTRACE_CONT, server_pid, 0, 0);
    waitpid(server_pid, &status, __WALL);
    printf("rip %llx\n", get_rip(server_pid));
    print_mem_at(server_pid, get_rip(server_pid), 100);
    ptrace(PTRACE_CONT, server_pid, 0, 0);

    return 0;
}
