# [pwnme 2023 - crypto] Scream Like Viking

> Our protagonist John is in a room, he hears some kind of noise, like something resonating.
> But he doesn't understand it...
> Perhaps he could play with his own echoes to guess what the meaning of this famous resonance could be...
> 
> `nc 51.68.95.78 32773`

<p align="center">
<img alt="Shout Like Dovahkiin > Scream Like Viking" src="https://media.tenor.com/O8zaeaYI8NkAAAAd/fus-roh-dah-skyrim.gif">
</p>

This article is a write-up for "Scream Like Viking", a cryptography challenge from PwnMe 2023.

# TL;DR

- Get pairs of `(C, N)` where `N` is recovered by taking GCD of multiple `M^e - C`
- Håstad's broadcast attack (CRT + `e`-th root) on the pairs of `(C, N)`

# Code review

The following source code is given:

```py
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes
from Crypto.Util.Padding import pad

e = 17
p = getPrime(512)
q = getPrime(512)
N = p * q

def encrypt(m):
    assert 0 <= m < N    
    c = pow(bytes_to_long(pad(long_to_bytes(m), 50)), e, N)
    return int(c)

def encrypt_flag():
    with open("/flag.txt", "rb") as f:
        flag = f.read()
    c = pow(bytes_to_long(pad(flag, 50)), e, N)
    return c

def main():
    try:
        while True:
            print("Enter your option (Encrypt or Flag) > ", end='')
            cmd = (input().strip())
            if cmd == "Encrypt":
                print("Enter your integer to encrypt > ", end='')
                m = int(input())
                c = encrypt(m)
                print(str(c) + '\n')
            elif cmd == "Flag":
                c = encrypt_flag()
                print("Flag cipher for you: " + str(c) + '\n')
                return
    except Exception as e:
        print("An error occured:\n", e)

if __name__ == "__main__":
    main()
```

The challenge is a classical RSA encryption oracle, we can either ask for the encrypted flag or encrypt a plaintext of our choosing. The twists here are that the modulus `N` isn't given and the exponent `e` is 17 (pretty smol). When a small `e` is used to encrypt a message `M` it's possible that `M^e < N`, sidestepping the modulo operation and making it possible to recover `M` by taking the `e`-th root of `C` (the ciphertext). This can be remediated by padding `M` to make it large enough that the modulo operation happens all the time.

We can't take the `17-th` root of `C` here because `M` is padded, thus the modulo operation has taken place, but we could use Håstad's broadcast attack (hinted at in the challenge title and description) since the flag is encrypted with a different modulus each time. Before that, however, we'll need to find a way to recover `N`.

# Recovering N

This part is based on [this page](https://cryptohack.gitbook.io/cryptobook/untitled/recovering-the-modulus) from CryptoBook, the CryptoHack gitbook. We can't send `-1` to recover `N-1` as the message is padded server-side but we can still recover `N` by using pairs of messages and encrypted messages.
The general idea is the following:

```python
C = M^e [N] <=> C + kN = M^e (with k in Z)
            <=> kN = M^e - C
```

Thus:

```python
GCD(M1^e - C1, M2^e - C2) = GCD(k1 * N, k2 * N) = aN
```

`a = 1` if `k1` and `k2` are coprime but if they aren't we can repeat the operation with new pairs of `(M, C)` until they are. The following function implements this part of the solution.

```py
def recover_n(pairs):
    return reduce(gmpy2.gcd, [gmpy2.mpz(pow(pt, e) - ct) for pt, ct in pairs])
```

# Håstad's broadcast attack

NB: Håstad's broadcast attack is a Coppersmith's attack (based on the Coppersmith method, used to find zeros of polynomials) and its general case uses the LLL algorithm. Latices are completely out of the scope of this write-up so the "simple version" of the algorithm is preferred.

The simple version has two key parts: first, using the Chinese Remainder Theorem to recover `flag^e` and second, taking its `e`-th root to recover the flag. The fact that the flag is padded changes nothing as the padding is deterministic.

This write-up won't explain in detail the Chinese Remainder Theorem (a good explanation can be found [here](https://brilliant.org/wiki/chinese-remainder-theorem/)) but the gist of it is that given the following, we can recover `x`:

```python
c1 = x [n1]
c2 = x [n2]
    ...
ck = x [nk]
```

In our case `x` is `flag^e`, no more moduli to deal with. All that's left now is to take the `e`-th root of `flage^e` to recover the flag.


```py
pt_17 = crt(N, C)[0]   # N is an array of moduli and C is an array of corresponding ciphertexts
pt, _ = gmpy2.iroot(pt_17, e)
```

# Conclusion

Below is the final commented solve script.

```py
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
```
