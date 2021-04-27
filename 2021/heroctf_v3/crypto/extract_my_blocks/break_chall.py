import pwn
import os
from Crypto.Cipher import AES

flagbytes = ""
end = False
for j in range(20):
    for i in range(0x20, 0x7f):
        proc = pwn.remote("chall0.heroctf.fr", 10000)
        proc.recvline()
        proc.recvuntil("ID : ")

        s = "our password : " + flagbytes + chr(i)

        payload = "AA" + s[-16:] + "A"*(16 - (len(" !\n\nY") + len(flagbytes)) % 16 )
        proc.sendline(payload)

        enc = bytes.fromhex(proc.recvlineS().rstrip())
        offset = 3 + ((len(flagbytes) + 5) // 16)
        block1 = enc[16:32]
        block2 = enc[16*offset:16*(offset+1)]
     
        if block1 == block2:
            flagbytes += chr(i)
            if chr(i) == '}':
                end = True
            print(flagbytes)
            break
    if end:
        break