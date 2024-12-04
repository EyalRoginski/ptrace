#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>

int main()
{
    syscall(SYS_mmap);
    return 0;
}
