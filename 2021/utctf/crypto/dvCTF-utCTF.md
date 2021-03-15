# DaVinciCTF and utCTF

Welcome to those two write-up about the DaVinci CTF and the utCTF.
I participated to the both CTF at the same time and the challenge that i flagged are pretty small so i put the wu in only one paper.
The first one is about an RSA issue on the public exponent and the second one about a easy exponent to brute-force with Diffie-Hellmann.


## DaVinci CTF - Bootless_RSA:

So in this challenge we have a big modulus (N) but with a small public exponent (e).
The issue is simple: if e is small whereas n is big, pow(m,e) is inferior to n. So c, which is pow(m,e,n) would probably be pow(m,e)=pow(m,3) and so m = pow(c,1/3) which is the cube root of c.
The following script solved this challenge:

```py
from gmpy2 import iroot #I used gmpy2 for the function iroot: https://gmpy2.readthedocs.io/en/latest/mpz.html

def bootless_RSA():
    n = 148818474926605063920889194160313225216327492347368329952620222220173505969004341728021623813340175402441807560635794342531823708335067243413446678485411066531733814714571491348985375389581214154895499404668547123130986872208497176485731000235899479072455273651103419116166704826517589143262273754343465721499
    e = 3
    ct = 4207289555943423943347752283361812551010483368240079114775648492647342981294466041851391508960558500182259304840957212211627194015260673748342757900843998300352612100260598133752360374373
    m = iroot(ct, 3)
    print (long_to_bytes(m[0]))

>>> dvCTF{RS4_m0dul0_inf1nity}
```

## utCTF - small P problem:

This one was pretty easy at the condition to know the key exchange of Diffie-Hellmann ! If you dont know well DH, go look at this: https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange

So the challenge is simple: we need to find the secret number a and b. In theory, it's impossible to find them if they are big enought !
In this case, they not, so we can easily test all the possibilities and find out a and b.
This is what this python script do:

```py
def samll_p():
    p = 69691
    g = 1001
    A = 17016
    B = 47643

    for a in range(p):
        if pow(g, a, p) == A:   #A = g**a%p
            break
    
    for b in range(p):
        if pow(g, b, p) == B:   #B = g**b%p
            break

    print (B**a%p)
    print (A**b%p)

>>>53919
>>>53919    #We find the commun secret !
```