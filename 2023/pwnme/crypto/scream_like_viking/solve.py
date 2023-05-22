from pwn import *
context.log_level='WARNING'

from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.Util.Padding import pad, unpad
from sympy.ntheory.modular import crt
from functools import reduce
import gmpy2

e = 17

def recover_n(pairs: list) -> int:
    '''
    Recovers N from pairs of (pt, ct).

    N = GCD(M1^e - C1, GCD(M2^e - C2, GCD(..., GCD(Mn-1^e - Cn-1, Mn^e - Cn))))
    '''
    return reduce(gmpy2.gcd, [gmpy2.mpz(pow(pt, e) - ct) for pt, ct in pairs])

C, N = [], []

while True:

    r = remote('51.68.95.78', 32773)
    #r = process(['python3', 'scream_like_viking.py'])

    # ---------------------- recover N ----------------------

    pairings = []


    for _ in range(10): # generate 10 pairs of (pt, ct)
                        # 10 is a perfectly arbitrary number

        r.recvuntil(b'> ')
        r.sendline(b'Encrypt')

        r.recvuntil(b'> ')
        m_ = os.urandom(64)

        r.sendline(str(bytes_to_long(m_)).encode())
        c_ = int(r.recvline())

        pairings.append([bytes_to_long(pad(m_, 50)), c_])

        n = recover_n(pairings) # recover n

    r.recvuntil(b'> ')
    r.sendline(b'Flag')

    r.recvuntil(b':')
    flag_ = int(r.recvline())   # recover flag

    C.append(flag_)
    N.append(n)

    r.close()

    # -------------- Håstad's broadcast attack --------------

    pt_17 = crt(N, C)[0]           # CRT to recover M^17
    pt, _ = gmpy2.iroot(pt_17, e)  # (M^17) ^ 1/17

    # checking for flag syntax is bloat, it'll be printed eventually anyway
    print(long_to_bytes(pt))

'''
$ python3 solve.py
b'\x11\xb6<\xe8\xbc#o\xbf'
b'\x01\n\xc5%\x00^\xd6[\x94/\x05\xb7\x89\xb4\xe5-'
b'\x15\xa1\xc8\x18\xbei\xf9\x03\xc58\x85\xe3qjV\x98\tav\xd843U'
b'\x01\x98\xd1\x83\xc1@\xcc\x96\x94\xa3\x00r\xa7+ok\xf5\x81\xb7\xc7\xc9}c\x148\xb5\x9d\x88A\x05m'
b'\x1a\x82{cC\x1b\x16\x0f\x0e\xd5e3o\xc7.\xf9\xc1\xf9z\x93\x1b+s<\xacLW\xbf\xbe\xf8\xa1\xfa\xb6BN\xaan\xaa'
b'\x02\x07\xd9\x83_\xf7\x11\xc7\x8d\x1c=\xee\x98mo\xf5v\x8c\x07\xdd\xbc\xab\xbf\xff\xa7\x8fG\x95\t\xb2\xec\xe2\xd7b9[\x8a%;c\x1a!\x91\xa3\x1e\t'
b'PWNME{3e851a6cc5525581446cad5694185b99}\n\n\n\n\n\n\n\n\n\n\n'
^C
'''
