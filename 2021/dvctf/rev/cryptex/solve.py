#!/usr/bin/python
from Crypto.Cipher import AES

def tobitstr(x):
    stre = []
    for a in x:
        if a < 0:
            a = 256 + a
        stre.append(a)
    return bytes(stre)

k = [-114, 62, 98, 26, 54, -7, -59, -47, 55, 88, 18, -1, -99, 116, -51, 62]
r = [11, -35, 55, 10, 62, 79, 125, 62, -28, 115, 77, 4, 73, 0, 11, 121, -126, 85, -83, 109, 1, -98, 35, -68, -4, -122, 14, 110, -28, 111, 22, -125]
klol = tobitstr(k)

aes = AES.new(klol, AES.MODE_ECB)
res = aes.decrypt(tobitstr(r))
print(res.hex())