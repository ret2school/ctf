#!/usr/bin/python

f = open("dump", "rb")
buf = f.read()
modbuf = bytearray(buf)

# Offset of the two first functions
offset = 0x13a9
offset2 = 0x1691

# endbr64; push rbp; mov rbp; rsp
endbr64 = bytes.fromhex("f30f1efa554889e5")

# Get the first 8 bytes of the key
func = buf[offset:offset+len(endbr64)]
key1 = bytes([x ^ y for x,y in zip(func, endbr64)])

# Get the next 8 bytes of the key
func2 = buf[offset2:offset2+len(endbr64)]
key2 = bytes([x ^ y for x,y in zip(func2, endbr64)])

# Some guessed bytes according to the disass
key = key1 + key2 + b"\x2d\x27\x57" + b"\x1a\x26"

# Luckily we have a function here too, so 8 bytes for free
func3 = buf[0x13fe:0x13fe+len(endbr64)]
key4 = bytes([x ^ y for x,y in zip(func3, endbr64)])

# Guessed bytes again
key = key + key4 + b"\xba\xca\x5e"

# Now let's decrypt the encrypted functions
for i in range(0, 896):
    modbuf[offset + i] = modbuf[offset + i] ^ key[i % 32]

out = open("dump2.bin", "wb")
out.write(modbuf)
out.close()
