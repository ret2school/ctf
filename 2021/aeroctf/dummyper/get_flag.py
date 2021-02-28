#!/usr/bin/python
from ctypes import CDLL
from Crypto.Cipher import AES
libc = CDLL("libc.so.6")

blockoff = 0x5060

f = open("dump", "rb")
buf = f.read()

encflag = buf[blockoff:blockoff + 0x80]
ts = 1614211200
for i in range(0, 24*3660):
    blockpos = 0x80
    libc.srand(ts + i)
    for _ in range(0, 64):
        blockpos += libc.rand() % 2047
    aeskey = buf[blockoff + blockpos:blockoff + blockpos + 0x10]
    blockpos += 0x20
    for _ in range(0, 64):
        blockpos += libc.rand() % 2047
    aesiv = buf[blockoff + blockpos:blockoff + blockpos + 0x10]
    blockpos += 0x10
    for _ in range(0, 64):
        blockpos += libc.rand() % 2047
    blockpos += 0xc0
    for _ in range(0, 64):
        blockpos += libc.rand() % 2047
    if(blockoff + blockpos == 0x4ba74):
        print("Found candidate %d" % i)
        break

c = AES.new(aeskey, AES.MODE_CBC, aesiv)
print(i)
print(c.decrypt(encflag))