# Ptrace Exercise Documentation

## How Does it Work?
1. Use ptrace with PTRACE_ATTACH to attach to a process.
2. Use waitpid to wait until the tracee receives a signal (or syscall and maybe other things).
3. Use PTRACE_CONT to allow the process to continue (or PTRACE_SYSCALL, see below)

## How to Catch Syscall
When restarting (continuing) the process, use PTRACE_SYSCALL instead of PTRACE_CONT, in order
to catch the next syscall, on entry.

## How to Catch a function call?
I have no idea.
But I do catch syscalls! I caught, for example accept4 (accepting a socket connection).

I don't really know where it's executing things... Let's look at the instruction pointer.
`rip: 7f544f65b88d`
Seems like the instruction where it waits to get a connection.

Interesting things in USER area, like `code_start`.

## Idea
My input to the authentication probably appears on the stack... Try to find it?
Can't find it... It might be on the stack.

