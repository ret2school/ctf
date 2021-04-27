from sympy import prevprime, nextprime, sqrt
from Crypto.Util.number import inverse, long_to_bytes, bytes_to_long
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES
import base64
import hashlib
import time
import pwn

def factor_int(modulus):
    lol = int("%d" % sqrt(modulus))

    next = lol
    nexts = []
    for i in range(10):
        next = nextprime(next)
        nexts.append(next)

    prev = lol
    for i in range(10):
        prev = prevprime(prev)
        for next in nexts:
            if prev * next == modulus:
                return (prev, next)


remote = pwn.remote('chall3.heroctf.fr', 9000)
mytime = time.time()
remote.recvuntil('modulus  : ')
modulus = int(remote.recvlineS().rstrip())
remote.recvuntil('input >> ')
prev, next = factor_int(modulus)        
e = 0x10001
n = prev*next
phi = (prev-1)*(next-1)
d = inverse(e, phi)
love = pow(bytes_to_long(hashlib.sha512(b"the_proof_of_your_love").digest()), d, n)
remote.sendline("%d" % love)
remote.recvuntil('vu.\n\n\t- ')
line = remote.recvlineS()[2:]
base = line[0:line.find("'")]

enc = base64.b64decode(base)
aes = AES.new(pad(b"None", AES.block_size), AES.MODE_CBC, pad(long_to_bytes(int(mytime)), AES.block_size))
print(aes.decrypt(enc))