#include <sys/ptrace.h>
#include <string.h>
#include <linux/ptrace.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>

#define WORD_SIZE sizeof(long)
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

    unsigned long long check_password_offset = 0x82cf0;
    unsigned long long known_code_offset = 0x90e9d;
    unsigned long long known_rip_offset = 0x55cd2ec90e9d;

    unsigned long long check_password_rip = known_rip_offset - known_code_offset + check_password_offset;

    print_mem_at(server_pid, check_password_rip, 200);

    ptrace(PTRACE_CONT, server_pid, 0, 0);
    return 0;
}
