#!/usr/bin/python
import struct
import serpent

def decryptbuf(s):
    outpt = b""
    key = 24
    for i in range(len(s)):
        outpt += bytes([s[i] ^ key])
        key = (4*key + 52) % 243
    return outpt

blop = bytes.fromhex("37e4eca91035efdb3febad25edd357b528")
print(blop)
print(decryptbuf(blop))

blop2 = bytes.fromhex("37fcf1ab1635fdd03ce3ad78e9c04ca632c16a")
print(decryptbuf(blop2))

buf3 = struct.pack("<QQ", 0xDBEF3510A9ECE437, 0xF7149DFD30ADEB3F)
print(decryptbuf(buf3 + b"\x6c"))

mysterious_array = [0xE9B554BCBF7A0351, 0x200A845B757AFF88, 0x392848A34339A3EE, 0x21F8E1C664355C7C]
watconst = [
    0x51281F74, 0x983DCAE3, 0x9BCA2E8F, 0x8939FAB3
]

def do_feistel_pass(j, seed1, seed2):
    tmp = (seed1 + watconst[j & 3] + seed2 + j + ((seed2 >> 8) ^ ((seed2 << 6) & 0xffffffff))) & 0xffffffff
    return (seed2, tmp)

def do_hash_block(x):
    seed1, seed2 = struct.unpack("<II", x[0:8])
    j = 0
    while True:
        tmp = (seed1 + watconst[j & 3] + seed2 + j + ((seed2 >> 8) ^ ((seed2 << 6) & 0xffffffff)))
        tmp = tmp & 0xffffffff
        seed1 = seed2
        j += 1
        if j == 48:
            break
        seed2 = tmp
    return (seed2, tmp)

def yoloblock(x):
    seed1, seed2 = struct.unpack("<II", x[0:8])
    for j in range(48):
        seed1, seed2 = do_feistel_pass(j, seed1, seed2)
    return (seed1, seed2)

z = do_hash_block(b"abcdefgh")
z2 = yoloblock(b"abcdefgh")
print(z, z2)


def undo_feistel_pass(j, seed2, tmp):
    while True:
        blup = watconst[j & 3] + seed2 + j + ((seed2 >> 8) ^ ((seed2 << 6) & 0xffffffff))
        pass1 = tmp - blup
        if pass1 > 0:
            break
        tmp += 0x100000000
    return (pass1, seed2)

def do_unhash_block(x):
    seed2, tmp = ((x >> 32), x & 0xffffffff)
    for i in range(47, -1, -1):
        seed2, tmp = undo_feistel_pass(i, seed2, tmp)
    return struct.pack("<II", seed2, tmp)

bufd = b""
for i in range(0, 32, 8):
    bufd += do_unhash_block(mysterious_array[i >> 3])

print(bufd)
#bufd = b"\x00"*32
for i in range(0, len(bufd), 8):
    (seed2, tmp) = do_hash_block(bufd[i:i+8])
    if mysterious_array[i >> 3] != (seed2 << 32) + tmp:
        print("BAD")

z = open("backdoor.txt", "wb")
z.write(bufd)
z.close()

# Dh1IuM7SV7xgZP8q
import serpent
z = serpent.Serpent(b"Dh1IuM7SV7xgZP8q")
bin = struct.pack("<QQQQ", 0x9601AAF388AB0192, 0x2127591BB4E06735, 0x582C4E2FDC6C7226, 0xC00B8862110C7A9D)
print(z.decrypt(bin))