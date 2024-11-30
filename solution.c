#define _GNU_SOURCE
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

        // fprintf(fifo, "\n");
        //
        // unsigned long long answer = 0;
        // fscanf(fifo, "%llx", &answer);
        // printf("got answer: %llx\n", answer);
        // if (answer != 0) {
        //     known_code_offset = answer;
        //     known_rip_offset = rip;
        //     break;
        // }

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
    unsigned long long func_location = get_check_password_location(server_pid);
    printf("check_password location: %llx\n", func_location);
    printf("And I'll prove it!\n");
    print_mem_at(server_pid, func_location, 100);
    ptrace(PTRACE_CONT, server_pid, 0, 0);

    return 0;
}
