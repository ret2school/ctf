#!/usr/bin/env python3

from pwn import *

exe = ELF("cshell2_patched")
libc = ELF("libc.so.6")
ld = ELF("ld.so")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("addr", 1337)

    return r


def main():
    r = conn()

    # good luck pwning :)

    r.interactive()


if __name__ == "__main__":
    main()
