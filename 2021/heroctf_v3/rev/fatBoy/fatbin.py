def dec(key, txt):
    res = []
    for i in range(len(txt)):
        byte = txt[i] - 0x42
        k = key[i % len(key)] % 26
        if byte < k:
            res.append(byte + 26 - k)
        else:
            res.append(byte - k)
    return res

def enc(key, txt):
    return [(key[i % len(key)] + txt[i]) % 26 + 66 for i in range(len(txt))]

k1 = b"FATMACHO"
k2 = b"BESTRONG"

buf = []
for c in dec(k1, b"CUZVTWPXYGOPLLVVLJFRGRZBGU"):
    tmp = 3*26 + c
    if tmp > ord("Z"):
        tmp = tmp - 26
    buf.append(tmp)
print(bytes(buf))