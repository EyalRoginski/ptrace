#include <endian.h>
#include <sys/ptrace.h>
#include <linux/ptrace.h>
#include <stdlib.h>
#include <stdio.h>
#include <wait.h>
#include <sys/user.h>

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
 * */
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

long get_current_instruction(int server_pid)
{
    unsigned long long rip = get_rip(server_pid);
    long current_instr = ptrace(PTRACE_PEEKTEXT, server_pid, rip, 0);
    current_instr = htobe64(current_instr);
    return current_instr;
}

void run_check(int server_pid)
{
    unsigned long long rip = get_rip(server_pid);
    long current_instr = get_current_instruction(server_pid);
    /*
       0000000000082cf0 <check_password>:
   82cf0:	41 57                	push   %r15
   82cf2:	41 56                	push   %r14
   82cf4:	41 54                	push   %r12
   82cf6:	53                   	push   %rbx
   82cf7:	48 81 ec 48 01 00 00 	sub    $0x148,%rsp
   82cfe:	48 89 f3             	mov    %rsi,%rbx
   82d01:	48 89 fe             	mov    %rdi,%rsi
     */

    // suspect_instruction = 0x4157415641545348;
    // gives a few matches, but none of the match
    // the rest of the function :(
    unsigned long suspect_instruction = 0x4881ec4801000048;
    // This gives no matches.
    if (current_instr == suspect_instruction) {
        printf("Suspected check_password at %llx\n", rip);
        print_mem_at(server_pid, rip, 1000);
    }
}

int main(int argc, char *argv[])
{
    int server_pid = atoi(argv[1]);
    printf("Attaching to pid %d...\n", server_pid);
    if (ptrace(PTRACE_ATTACH, server_pid, 0, 0) != 0) {
        perror("Failed to attach to server");
    }
    int step = 0;
    while (1) {
        int status;
        waitpid(server_pid, &status, __WALL);
        printf("Step %d -- rip: %llx ; current: %lx\n", step, get_rip(server_pid), get_current_instruction(server_pid));
        step++;
        run_check(server_pid);
        // Continue until next instruction.
        ptrace(PTRACE_SINGLESTEP, server_pid, 0, 0);
    }
}
