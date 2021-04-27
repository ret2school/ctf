v11  = "   546  9 2      7  39    49 5    7 7      2     93    56  8    1  39         8 6"

lol2 = "178546239429381567563927184935214678741865923682793415256478391814639752397152846"

for i in range(9):
    print("|".join([x for x in v11[9*i:9*(i+1)]]))

for i in range(9):
    print("|".join([x for x in lol2[9*i:9*(i+1)]]))

buf = "Hero{"
for i in range(8, 89, 9):
    buf += lol2[i - 8]
    buf += lol2[i - 7]
    buf += lol2[i - 6]
    buf += lol2[i - 5]
    buf += lol2[i - 4]
    buf += lol2[i - 3]
    buf += lol2[i - 2]
    buf += lol2[i - 1]
    buf += lol2[i]

buf += "}"

buf2 = ""
for i in range(9):
    for j in range(9):
        if v11[9*i + j] == " ":
            buf2 += "%d%d%s" % ((i+1), (j+1), lol2[9*i + j])

print(buf2)

# Hero{174562389529384167683917254935241678741856923268793415356428791817639542492175836}