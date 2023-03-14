
lol = b'\x00uewefi_}{_tbmgleophcopb_aleo'

exp = 11
l = []
for i in range(29):
    l.append(chr(lol[pow(exp, i, 29)]))

print("".join(l))


