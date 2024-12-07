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

Interesting things in USER area, like `start_code`.

Unfortunately, that is 0, and so is `start_stack`.

## Idea
My input to the authentication probably appears on the stack... Try to find it?
Can't find it... It might be on the heap.

## Trying a more systematic approach

In theory, how would I achieve the goal?

Inject a jump to my code at the start of `check_password`.
To achieve this, I need to know where `check_password` is located
inside the running code, and I need to be able to inject my own code elsewhere.

How to find this?

A good start is maybe single-stepping the program to see all of the locations of `rip`.
Check if this is consistent between different runs? Does it use ASLR?

Interesting discovery: the locations _are_ different! An excerpt from two different runs
of the server, with `rip` being traced:

First run:
```
Step 0 -- rip: 7f3c8b91688d
Step 1 -- rip: 7f3c8b91688d
Step 2 -- rip: 7f3c8b91688d
Step 3 -- rip: 7f3c8b916893
Step 4 -- rip: 7f3c8b916895
Step 5 -- rip: 56045fab3d21
Step 6 -- rip: 56045fab3d24
Step 7 -- rip: 56045fab3d2e
Step 8 -- rip: 56045fab3d33
Step 9 -- rip: 56045fab3d35
Step 10 -- rip: 56045fab3d39
```

Second run:
```
Step 0 -- rip: 7f280d5f388d
Step 1 -- rip: 7f280d5f388d
Step 2 -- rip: 7f280d5f3893
Step 3 -- rip: 7f280d5f3895
Step 4 -- rip: 55a82f8b3d21
Step 5 -- rip: 55a82f8b3d24
Step 6 -- rip: 55a82f8b3d2e
Step 7 -- rip: 55a82f8b3d33
Step 8 -- rip: 55a82f8b3d35
Step 9 -- rip: 55a82f8b3d39
Step 10 -- rip: 55a82f8b3d3b
```

It seems to executing the same code, but it's placed in different places!
The last 3-4 digits are the same, so the randomness is not very granular.

New idea: Look for the function using its actual bytes.
I'm finding things that are similar to the function, but not identical...
Not finding anything that is identical to the function, which is really weird.

New idea: Retrieve what's executing currently, and search for it in the source file,
and thus know the offset, and try using that!
Ok, it works I think... I'm doing it through python since it's more convenient to search
there, and I need to figure out how to route it back in. Maybe named pipe?

It works! Not automatically yet, but I managed to get the position of the function in the running
process and I checked and it did contain the actual code of `check_password`.
Struggling a bit with the IPC between python and my C code... So I'll try doing it in C.

Managed to do it in C! I can now officially obtain the location of check_password
on any running server.

Tests also confirm that it changes location each time I run the server.

Let's see if I can get it to jump to my own code.

Problem: Where do I put my code so that it can jump to it?
And also it needs not to get overwritten...

Seems that this is quite a hard problem... I can't think of anywhere to actually put it where it's
gonna be able to execute the code (needs to be allocated but not in use) maybe in the data segment?
How do I find that?

Idea: allocate memory and run the code there? It's kind of cumbersome, but it might work.

It did work! I managed to jump to it, and return 1 from there. I also managed to jump to it and
jump back, without causing problems to the program. I think.
Now just to write the final assembly to check if it's "arazim", and I'm done!

I managed a final POC before fully making it: It only accepts inputs that are 6 characters long.

**It works!**

To run, use: 

```
gcc solution.c -o backdoor && ./backdoor <pid of tracy-server>
```
