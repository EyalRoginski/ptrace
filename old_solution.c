#include <sys/ptrace.h>
#include <string.h>
#include <linux/ptrace.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>

void print_registers(int server_pid)
{
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, server_pid, 0, &regs);
    printf("rip: %llx\n", regs.rip);
    int peek = ptrace(PTRACE_PEEKTEXT, server_pid, regs.rip, 0);
    printf("at rip: %x\n", peek);
    printf("rsp: %llx\n", regs.rsp);
    int peek_rsp = ptrace(PTRACE_PEEKTEXT, server_pid, regs.rsp, 0);
    printf("at rsp: %x\n", peek_rsp);
}

void print_mem_at(int server_pid, unsigned long long location, int count)
{
    printf("-- Code at %llx --\n", location);
    for (int i = 0; i < count; i++) {
        long word = ptrace(PTRACE_PEEKDATA, server_pid, location + (i * sizeof(unsigned long)), 0);
        word = htobe64(word); // Big endian so it prints in the same order as objdump.
        printf("%016lx", word);
    }
    printf("\n-- END Code --\n");
}

void print_stack_to_stderr(int server_pid)
{
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, server_pid, 0, &regs);
    unsigned long long pointer = regs.rsp;
    int MAX = 1000;
    int STEP = 4;
    printf("STACK\n");
    for (int i = -MAX; i < MAX; i++) {
        int peek = ptrace(PTRACE_PEEKDATA, server_pid, pointer + i * STEP);
        fprintf(stderr, "%llx %x\n", pointer + i * STEP, peek);
    }
}

void user_area_things(int server_pid)
{
    struct user user;
    int start_code = ptrace(PTRACE_PEEKUSER, server_pid, (void *)(&user.start_code) - (void *)(&user), 0);
    printf("start_code: %d\n", start_code);
    int start_stack = ptrace(PTRACE_PEEKUSER, server_pid, (void *)(&user.start_stack) - (void *)(&user), 0);
    printf("start_stack: %d\n", start_stack);
}

unsigned long long get_check_password_location(int server_pid)
{
    unsigned long long check_password_code_offset = 0x82cf0;
    unsigned long long known_code_offset = 0x90e9d;
    unsigned long long known_rip_offset = 0x55cd2ec90e9d;

    unsigned long long check_password_rip = known_rip_offset - known_code_offset + check_password_code_offset;

    return check_password_rip;
}

int main(int argc, char *argv[])
{
    int server_pid = atoi(argv[1]);
    printf("attaching to pid %d\n", server_pid);
    int result = ptrace(PTRACE_ATTACH, server_pid, 0, 0);
    printf("result %d\n", result);
    if (result != 0) {
        return 1;
    }
    ptrace(PTRACE_SETOPTIONS, server_pid, 0, PTRACE_O_TRACESYSGOOD);
    int status;
    waitpid(server_pid, &status, __WALL);
    user_area_things(server_pid);
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, server_pid, 0, &regs);
    print_registers(server_pid);
    ptrace(PTRACE_SYSCALL, server_pid, 0, 0);
    while (1) {
        waitpid(server_pid, &status, __WALL);
        printf("Caught signal, status: %d\n", status);
        if (!WIFSTOPPED(status)) {
            // Not really stopped?
            printf("Not really stopped.\n");
            ptrace(PTRACE_SYSCALL, server_pid, 0, 0);
            continue;
        }
        printf("Signal that stopped server: %d\n", WSTOPSIG(status));
        if (!(WSTOPSIG(status) == (SIGTRAP | 0x80))) {
            // Not a syscall.
            printf("Stopped by signal, not syscall. Continuing...\n");
            ptrace(PTRACE_SYSCALL, server_pid, 0, 0);
            continue;
        }
        struct ptrace_syscall_info info;
        memset(&info, 0, sizeof(info));
        int syscall_get_res = ptrace(PTRACE_GET_SYSCALL_INFO, server_pid, sizeof(info), &info);
        if (info.op == PTRACE_SYSCALL_INFO_ENTRY) {
            // Entry into syscall
            printf("syscall entry, number: %lld\n", info.entry.nr);
            print_registers(server_pid);
            print_stack_to_stderr(server_pid);
        } else if (info.op == PTRACE_SYSCALL_INFO_EXIT) {
            // Exit from syscall, interesting!
            printf("syscall exit, return value: %lld\n", info.exit.rval);
        }
        printf("Stopped by syscall, continuing...\n");
        ptrace(PTRACE_SYSCALL, server_pid, 0, 0);
    }
    return 0;
}
