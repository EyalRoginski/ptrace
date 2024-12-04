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
        printf("%lx", word);
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

unsigned long long mmap_me(int server_pid)
{
    unsigned long mmap_code[] = {
        be64toh(0x48C7C70000000048),
        be64toh(0xC7C60010000048C7),
        be64toh(0xC20700000049C7C2),
        be64toh(0x2000000049C7C000),
        be64toh(0x00000049C7C10000),
        be64toh(0x000048C7C0090000),
        be64toh(0x000F050000000000),
    };
#define MMAP_CODE_LEN sizeof(mmap_code) / sizeof(unsigned long)
    // Save state
    struct user_regs_struct original_regs;
    ptrace(PTRACE_GETREGS, server_pid, 0, &original_regs);
    unsigned long long rip = original_regs.rip;
    unsigned long original_code[MMAP_CODE_LEN];
    get_mem_at_words(server_pid, rip, MMAP_CODE_LEN, original_code);

    // Execute code
    write_words_at(server_pid, rip, MMAP_CODE_LEN, mmap_code);

    print_mem_at(server_pid, rip, 10);

    for (int i = 0; i < MMAP_CODE_LEN - 1; i++) {
        ptrace(PTRACE_SINGLESTEP, server_pid, 0, 0);
        waitpid(server_pid, 0, __WALL);
        print_registers(server_pid);
    }

    // Get return value
    struct user_regs_struct new_regs;
    ptrace(PTRACE_GETREGS, server_pid, 0, &new_regs);
    unsigned long long ret_value = new_regs.rax;

    // Restore state
    ptrace(PTRACE_SETREGS, server_pid, 0, &original_regs);
    write_words_at(server_pid, rip, MMAP_CODE_LEN, original_code);

    return ret_value;
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

    unsigned long long mmap_location = mmap_me(server_pid);
    printf("mmap_location: %llx\n", mmap_location);
    print_mem_at(server_pid, mmap_location, 0x1000);

    ptrace(PTRACE_CONT, server_pid, 0, 0);

    return 0;

    unsigned long long func_location = get_check_password_location(server_pid);
    printf("check_password location: %llx\n", func_location);

    unsigned int check_password_code_offset = 0x82cf0;
    print_mem_at(server_pid, func_location - check_password_code_offset, 100);
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
