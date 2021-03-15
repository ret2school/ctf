#!/usr/bin/python
z = bytes.fromhex("77415063554C5A687F0678044C4464067E5A2259744A")
u = b"\x13\x37"*11
print(str(bytes([a ^ b for a,b in zip(z,u)]), "ascii"))
