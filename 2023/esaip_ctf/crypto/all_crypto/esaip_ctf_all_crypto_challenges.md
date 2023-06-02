+++
title= "[ESAIP CTF 2023] All crypto challenges"
tags = ["ctf", "ret2school", "ESAIP CTF", "2023", "Alol" "crypto"]
date = "2022-05-27"
+++

This article contains write-ups for all cryptography challenges from ESAIP CTF 2023. All challenge files, prompts and solves are available [here](https://github.com/ESAIP-CTF/public-esaip-ctf-2023/tree/master/challenges/crypto).

The event was nice and I had a great time competing with my friends. *However*, I'd like to quickly rant before diving into the write-ups.

\<rant>
- I can't believe this has to be said but before giving source code, *please make sure that it works*.
- Added bonus: publish the Dockerfiles you use so players don't have to waste time debugging.
- I was tired and didn't notice I had solved a challenge locally because no flag was printed ... turns out the challenge file didn't contain a placeholder flag :)

\</rant>

# Bowser's Box

> Bowser wants to get the ultime lucky box !
> You new to find it before him !

Probably my favourite challenge, not too hard but an interesting concept nonetheless. The following Python source code is given:

```py
from Crypto.Util.number import bytes_to_long
from multiprocessing import Process
from os import urandom
import socket

BANNER = b"""
__________                                /\        __________              
\______   \ ______  _  ________ __________)/ ______ \______   \ _______  ___
 |    |  _//  _ \ \/ \/ /  ___// __ \_  __ \/  ___/  |    |  _//  _ \  \/  /
 |    |   (  <_> )     /\___ \\\\  ___/|  | \/\___ \   |    |   (  <_> >    < 
 |______  /\____/ \/\_//____  >\___  >__|  /____  >  |______  /\____/__/\_ \\
        \/                  \/     \/           \/          \/            \/
"""

def read_line(s):
    body = b""
    while True:
        ch = s.recv(1)
        if ch == b"\n":
            break
        body = body + ch
    return body

def challenge(s):
    s.send(BANNER)
    s.send(b"What's the SBox you want to use for the encryption?\n")
    s.send(b"Example : 1,2,3,4,5,6...\n")

    try:
        sbox = read_line(s).decode()
        sbox = sbox.split(",")
        sbox = tuple([int(x) for x in sbox])
        assert len(sbox) == 256
    except:
        s.send(b"SBox is invalid!\n")
        exit()

    # N.B: modified version of https://github.com/bozhu/AES-Python to work with
    #      python3 and where SBOX is passed to constructor and set before
    #      change_key is called
    from aes import AES
    master_key = bytes_to_long(b"ECTF{??????????}")
    AES = AES(master_key, sbox)
    ciphertext = AES.encrypt(bytes_to_long(urandom(120)))

    s.send(b"Cipher text: " + str(ciphertext).encode() + b"\n")
    return

if __name__ == '__main__':
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", 55555))
    s.listen(10)
    while True:
        client, addr = s.accept()
        print("Got connect from " + str(addr))
        p = Process(target=challenge, args=(client,))
        p.daemon = True
        p.start()
        client.close()
```
We can control the `SBOX` for the encryption of a single random message and we have to leak the key. I originally thought of doing something like in [this StackOverflow post](https://crypto.stackexchange.com/questions/67612/aes-oracle-with-bad-s-box#67614) where the `SBOX` is set to an identity mapping (`[0x0, 0x1, ..., 0xff] => [0x0, 0x1, ..., 0xff]`) so that no substitution actually takes place but it wouldn't have worked as we need to leak the encryption key, not the plaintext.

What I chose to do instead was to send an empty/null `SBOX` (256 zeros). The commented `encrypt` function below explains this choice.

```py
def encrypt(self, plaintext):
    # convert plaintext to 4 x 4 matrix
    self.plain_state = text2matrix(plaintext)

    # plaintext ^= round_keys[:4]
    self.__add_round_key(self.plain_state, self.round_keys[:4])

    # useless, we'll see why below
    for i in range(1, 10):
        self.__round_encrypt(self.plain_state, self.round_keys[4 * i : 4 * (i + 1)])

    # perform substitution but since the SBOX is all 0s the resulting plain_state
    # will also be all 0s, thus rendering entirely useless every operation done
    # until now
    self.__sub_bytes(self.plain_state)

    # shift the rows (useless as all the values are 0)
    self.__shift_rows(self.plain_state)

    # plain_state ^= xor round_keys[40:]
    # but as the plain_state is all 0s we have
    # plain_state = round_keys[40:]
    self.__add_round_key(self.plain_state, self.round_keys[40:])

    # return plain_state (round_keys[40:]) as an int
    return matrix2text(self.plain_state)
```

Basically, by using a null `SBOX`, we've turned the encryption function into the following:
```py
def encrypt(self, plaintext):
    return matrix2text(self.round_keys[40:])
```
Since the `round_keys` are derived from the "master key" (via the key scheduling algorithm) and each byte of the master key affects the same byte of each round key we can bruteforce the master key character by character.

This can be done with the following Python script:

```py
from aes import AES, text2matrix, matrix2text
from Crypto.Util.number import long_to_bytes, bytes_to_long
import string

# Got this value by sending a null sbox to the remote server
ct = long_to_bytes(201063020592992157563690216943176785208)
pt = b''

for i in range(16): # 16 byte key
    for c in string.printable:
        test_key = pt + c.encode() + b'\x00' * (15 - len(pt))
        cipher = AES(bytes_to_long(test_key), [0]*256)

        if long_to_bytes(matrix2text(cipher.round_keys[40:]))[i] == ct[i]:
            pt += c.encode()
            break
print(pt)
# b'ECTF{AEEES_SBOX}'
```


# Mario Chest

> Mario wanted to hide his deepest secret in a chest to defeat Bowser.
> He shared part of the chest code with some of his friends, but now Mario is gone and the code is incomplete...
> You need to retrieve this secret !


We're given the following Python source code:

```py
import random
from decimal import Decimal,getcontext
from multiprocessing import Process
import socket

getcontext().prec = 80

FLAG = ""

# Menu
menu_options = {
    "1": 'Get the secret',
    "2": 'Create new share',
    "3": 'Exit',
}

banner = b"""
                     _                              
 _____         _    | |       _____ _           _   
|     |___ ___|_|___|_|___   |     | |_ ___ ___| |_ 
| | | | .'|  _| | . | |_ -|  |   --|   | -_|_ -|  _|
|_|_|_|__,|_| |_|___| |___|  |_____|_|_|___|___|_|  
                                                                                                                                                                  
"""

# Print menu
def print_menu(s):
    for key in menu_options.keys():
        menu = key+ '--'+menu_options[key] 
        s.send(menu.encode()+b"\n")

# Get user input
def read_line(s):
    body = b""
    while True:
        ch = s.recv(1)
        if ch == b"\n":
            break
        body = body + ch
    return body

def str_to_int(secret):
    return sum([ord(c) * (256 ** i) for i, c in enumerate(secret)])

def int_to_str(secret_int):
    secret_str = []
    while secret_int > 0:
        secret_str.append(chr(secret_int % 256))
        secret_int //= 256
    return ''.join(secret_str)

def create_point(x):
    a = int(str(6**3)[1:] + str(5**4)[:2])
    b = int(str(3**3)[1:] + str(4**4)[1:])
    c = a * b
    return x - c

def create_share(x,m,secret):
    coefficients = coeff(m, secret)
    shares.append((x, polynom(x, coefficients)))     

def reconstruct_secret(shares):
    sums = 0
 
    for j, share_j in enumerate(shares):
        xj, yj = share_j
        prod = Decimal(1)
 
        for i, share_i in enumerate(shares):
            xi, _ = share_i
            if i != j:
                prod *= Decimal(Decimal(xi)/(xi-xj))
 
        prod *= yj
        sums += Decimal(prod)
 
    return int(round(Decimal(sums), 0))
 
def polynom(x, coefficients):
    point = 0

    for coefficient_index, coefficient_value in enumerate(coefficients[::-1]):
        point += x ** coefficient_index * coefficient_value
    return point
 
def coeff(t, secret):
    coeff = [random.randrange(0, 10**5) for _ in range(t - 1)]
    coeff.append(secret)
    return coeff
 
def generate_shares(n, m, secret):
    coefficients = coeff(m, secret)
    shares = []
 
    for _ in range(1, n+1):
        x = random.randrange(1, 10**5)
        shares.append((x, polynom(x, coefficients)))
 
    return shares

def verify_secret(generated_secret):
    if generated_secret == FLAG:

        return f"Okey, I'll share my secret with you : {FLAG}"
    else :
        return "I won't share my secret if you won't share yours ( ͡° ͜ʖ ͡°)"

# Challenge
def challenge(s):
    s.send(banner)
    while (True):
        print_menu(s)
        choice = read_line(s)
        if choice.decode("utf-8") == "1":
            pool = []
            pool.append(shares[-1])
            pool.append(shares[-2])
            reconstructed = int_to_str(reconstruct_secret(pool))
            result =  verify_secret(reconstructed)
            s.send(result.encode()+b"\n")

        elif choice.decode("utf-8") == "2":
            s.send(b"Enter your new share ID number : \n")
            ID = read_line(s)
            point = int(ID)
            create_share(create_point(point),t,secret_int)
            
        elif choice.decode("utf-8") == "3":
            break
        else:
            s.send(b"Wrong choice: send 1,2 or 3\n")

 
# Main
if __name__ == '__main__':

    t, n = 5, 10
    secret_int = str_to_int(FLAG)
    shares = generate_shares(n, t, secret_int)

    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", 55555))
    s.listen(10)
    
    while True:
        client, addr = s.accept()
        print(f"Got connect from {addr}")
        p = Process(target=challenge, args=(client,))
        p.daemon = True
        p.start()
        client.close()
```

The program seems to erronously implement a SSSS (Shamir's Secret Sharing Scheme) in which we can either create a new share or recover the secret (if the reconstructed secret is equal to the original secret). Two functions from the original source code have been rewritten below to highlight the implentation errors.

```py
def create_point(x):
    # This function should make it so we can't chose the value
    # of the resulting point, thankfully for us that's not the case
    return x - 1256472

def reconstruct_secret(shares):
    # Only the last 2 shares (instead of all 5) are used to recover
    # the secret so we can rewrite the function as follows:
    (xj,yj), (xi,yi) = shares

    sums = Decimal(Decimal(xi) / (xi-xj)) * yj \
         + Decimal(Decimal(xj) / (xj-xi)) * yi

    return int(round(Decimal(sums), 0))
```

From the rewritten version of the `reconstruct_secret` function it's obvious that, for each part of the equation, if either `x` or `y` are equal to `0` then that part of the equation will be equal to `0`.
Thus if we can create a share `(0, f(0))`, the function will always return `f(0)` (ie. the secret) and we can recover the flag. The demonstration for this is given below, where `s` is the share created by the program and `u` is the share we've created.
```
xi / (xi-xj) * yj + xj / (xj-xi) * yi <=> s / (s - u) * f(u) + u / (u - s) * f(s)
                                      <=> s / (s - 0) * f(0) + 0 / (0 - s) * f(s)
                                      <=> 1 * f(0) + 0 * f(s)
                                      <=> f(0)
```
To do this, we can simply create a new share with an ID of `1256472` (which will create the share `(0, secret)`).

```
$ nc AAA.BBB.CCC.DDD 55555
# [...]
1--Get the secret
2--Create new share
3--Exit
2
Enter your new share ID number :
1256472
1--Get the secret
2--Create new share
3--Exit
1
Okey, I'll share my secret with you : ECTF{WhEn_Mari0_W4nTs_To_Share}
```

# Square Mario

> While your were playing mario you found those 2 files, please find a way to decrypt them!

We're given the following Python source code and output.

```py
from Cryptodome.Util.number import bytes_to_long, getPrime

FLAG = open("flag.txt", "rb").read()

def square(x, m, n=5):
    for _ in range(n):
        x = pow(x, 2, m)
    return x

def encrypt(flag):
    p = getPrime(1024)
    x = square(bytes_to_long(flag), p)
    return (x, p)

(X, P) = encrypt(FLAG)

print("X =", X)
print("P =", P)

#X = 65567906504707001412451629380105920336765646875361267702392177389975788601105395041727677960531694075172671673825534663404646697891108703571487714370157822718820383082425198093895770956243411362693772945081793898878903728208012455412074768926681046872056914503511397246233621635857399405920045067524154745070
#P = 126419363563553215091646637314497854198261588036382180640893319022541659598027100223880826774071842687403022731516037083359599621020514054284689589273154786802636897124000251303336410620757242551598664334914370563254424053331496101404625326501881265007678722518697084930349838815078675100361385273502712083087
```

The flag is converted to a `long` before being squared 5 times modulo `P` (so `X = flag ** 32 % P`).
Thus we can simply recursively take the modular square root of `X` (and `-X % P`, as there are two roots) using the Tonneli-Shanks algorithm.

```py
from libnum import n2s

def mod_sqrt(a, p):

    def legendre_symbol(a, p):
        ls = pow(a, (p - 1) // 2, p)
        return -1 if ls == p - 1 else ls

    if legendre_symbol(a, p) != 1:
        return 0
    elif a == 0:
        return 0
    elif p == 2:
        return p
    elif p % 4 == 3:
        return pow(a, (p + 1) // 4, p)

    s = p - 1
    e = 0
    while s % 2 == 0:
        s //= 2
        e += 1

    n = 2
    while legendre_symbol(n, p) != -1:
        n += 1

    x = pow(a, (s + 1) // 2, p)
    b = pow(a, s, p)
    g = pow(n, s, p)
    r = e

    while True:
        t = b
        m = 0
        for m in range(r):
            if t == 1:
                break
            t = pow(t, 2, p)

        if m == 0:
            return x

        gs = pow(g, 2 ** (r - m - 1), p)
        g = (gs * gs) % p
        x = (x * gs) % p
        b = (b * g) % p
        r = m

X = 65567906504707001412451629380105920336765646875361267702392177389975788601105395041727677960531694075172671673825534663404646697891108703571487714370157822718820383082425198093895770956243411362693772945081793898878903728208012455412074768926681046872056914503511397246233621635857399405920045067524154745070
P = 126419363563553215091646637314497854198261588036382180640893319022541659598027100223880826774071842687403022731516037083359599621020514054284689589273154786802636897124000251303336410620757242551598664334914370563254424053331496101404625326501881265007678722518697084930349838815078675100361385273502712083087

X = [X]
for _ in range(5):
    X = [mod_sqrt(x, P) for x in X] + [(-mod_sqrt(x, P))%P for x in X]

for x in X:
    if n2s(x).startswith(b'ECTF'):
        print(n2s(x))
# b'ECTF{7c2fc5155efcebd7264625c8f4e4db1aea7d489515368cf1626b3d6dffc01e63}'
```

# Toad Sauce

```
README.md:
It's not a surprise, Toad loves *censored* sauce !

He tried to create his own *censored* sauce by mixing 6 of his favorite ingredients.

Retrieve the secret recipe !

flag.enc:
QVWQ{M0lP_Ld_MUj1gj_Fh_Na0n}
```

From the challenge prompt, we can guess that the flag was encrypted with a Cesar cipher with 6 different and repeating shifts. Since we have the crib '`ECTF`' we can calculate the first 4 shifts (out of 6).

```py
from string import ascii_uppercase as up
from string import ascii_lowercase as lo

a = 'QVWQ{M0lP_Ld_MUj1gj_Fh_Na0n}'
b = 'ECTF'

key = [ord(a_) - ord(b_) for a_,b_ in zip(a,b)] + [0, 0]

def cesar(a, key):
    arr = []
    for a_,k in zip(a,key):
        if a_ in up:
            arr.append(up[ (up.index(a_) - k) % 26])
        elif a_ in lo:
            arr.append(lo[ (lo.index(a_) - k) % 26])
        else:
            arr.append(a_)
    return arr

print(''.join(cesar(a, key * 100)))
# ECTF{M0sM_Ld_TRy1gx_Cw_No0k}
```

As I have no respect for crypto challenges where we're only given a `flag.enc` file, we can guess the rest of the flag: `ECTF{T0aD_Is_TRy1ng_To_Co0k}`.

# Luigi Ascent

```
README.md:
I heard that Luigi wanted to touch the Scy !

flag.enc:
ELgU0l}C30cm0~Tt_Heu~FsT__d~{_oSCs~
```

"`Scy`" hints that the flag was encrypted with a scytale cipher. Using an [online decryptor](https://www.cachesleuth.com/scytale.html) we can try all numbers of columns until we get the flag: `ECTF{L3ts_g0_ToUcH_S0me_Cl0uds}`.
