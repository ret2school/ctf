import pwn

look = bytes.fromhex("011635052A210828692C0911330310311370752D2F1A720B2E273B7B7337240620123A141B7623307717250F0C366D0E7100343829042B0A181574260D327A07")
look = bytes([x ^ 0x42 for x in look])

def dec(lol):
    buf = b""
    for i in range(0, len(lol) // 4):
        bloc = lol[4*i:4*i+4]
        i0 = look.find(bloc[0])
        i1 = look.find(bloc[1])
        i2 = look.find(bloc[2])
        i3 = look.find(bloc[3])
        if i3 != -1:
            tmp = (i3) | (i2 << 6) | (i1 << 12) | (i0 << 18)
            buf += bytes([(tmp >> 16), (tmp >> 8) & 0xff, (tmp) & 0xff])
            continue
        if i2 != -1:
            tmp = (i2 << 6) | (i1 << 12) | (i0 << 18)
            tmp >>= 8
            buf += bytes([(tmp >> 8) & 0xff, (tmp) & 0xff])
            continue
        if i1 != -1:
            tmp = i1 | (i0 << 6)
            buf += bytes([tmp >> 4])
    return buf
    


blop = {}
for i in look:
    if chr(i) not in blop:
        blop[chr(i)] = 0
    blop[chr(i)] += 1

remote = pwn.remote("chall0.heroctf.fr", 3000)
i = 0
for i in range(40):
    remote.recvuntil("New cipher : ")
    deco = remote.recvline()
    bop = dec(deco).rstrip()
    remote.recvuntil(" answer : ")
    remote.sendline(bop)
print(remote.recvall())