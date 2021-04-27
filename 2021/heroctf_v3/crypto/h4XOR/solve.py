import pwn

f = open("flag.png.enc", "rb")
buf = f.read()

hdr = b"\x89PNG\x0d\x0a\x1a\x0a\x00"
print(len(hdr))

key = pwn.xor(buf[0:9], hdr)
print(key)
png = pwn.xor(buf, key)
open("flag.png", "wb").write(png)