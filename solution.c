#include <sys/ptrace.h>
#include <linux/ptrace.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>

int main(int argc, char *argv[])
{
    int server_pid = atoi(argv[1]);
    printf("attaching to pid %d\n", server_pid);
    int result = ptrace(PTRACE_ATTACH, server_pid, 0, 0);
    printf("result %d\n", result);
    int status;
    while (1) {
        waitpid(server_pid, &status, __WALL);
        printf("waited: %d\n", status);
        ptrace(PTRACE_SYSCALL, server_pid, 0, 0);
        if (!WIFSTOPPED(status)) {
            // Not really stopped?
            ptrace(PTRACE_CONT, server_pid, 0, 0);
            continue;
        }
        if (!(WSTOPSIG(status) == SIGTRAP)) {
            // Not a syscall.
            ptrace(PTRACE_CONT, server_pid, 0, 0);
            continue;
        }
        struct ptrace_syscall_info info;
        ptrace(PTRACE_GET_SYSCALL_INFO, server_pid, sizeof(info), &info);
        if (info.op == PTRACE_SYSCALL_INFO_ENTRY) {
            // Entry into syscall
            printf("syscall entry, number: %lld", info.entry.nr);
        } else if (info.op == PTRACE_SYSCALL_INFO_EXIT) {
            // Exit from syscall, interesting!
            printf("syscall exit, return value: %lld", info.exit.rval);
        }
    }
    return 0;
}
