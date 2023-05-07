---
title: "[UTCTF 2023] Welcome"
date: 2023-05-5
tags: ["ctf", "nasm", "reverse", "linux", "avr", "UTCTF"]
---


# UTCTF 2023: Welcome
>  Welcome
> 
> 1000
> 
> Note: while this challenge is nominally RE, there is some crypto-level/crypto-style math involved too.
> 
> Welcome to UTCTF! I made a special last minute program just for you to display a wonderful welcome message (+ flag!) I may have accidentally (okay... purposely) made a small bug in my math > that makes this unsolvable(TM). Can you figure it out and fix it for me please?
> 
> By Jeriah (@jyu on discord)
> 

## Round 1: analysis of the program structure

In this challenge, we are given a "main.elf" binary which is a AVR-8 ELF executable that opens nice in Ghidra. In the "Language" dropdown, I selected "AVR8 atmega256" variant. Given the binary has debug symbols, the "main" function can be spotted easily, and looks like this:

```
     code:000c5b cf 93           push       Ylo
     code:000c5c df 93           push       Yhi
     code:000c5d 00 d0           rcall
     code:000c5e 00 d0           rcall
     code:000c5f 00 d0           rcall
     code:000c60 cd b7           in         Ylo,SPL
     code:000c61 de b7           in         Yhi,SPH
     code:000c62 78 94           bset       Iflg
     code:000c63 84 b5           in         R24,DAT_mem_0044                                 = ??
     code:000c64 82 60           ori        R24,0x2
     code:000c65 84 bd           out        DAT_mem_0044,R24                                 = ??
     code:000c66 84 b5           in         R24,DAT_mem_0044                                 = ??
     code:000c67 81 60           ori        R24,0x1
```

To ease analysis a bit, let's use the decompiler, to have a somewhat "easy-to-understand" pseudo-C code.
After some global variable initializations, we get huge part of the main function that initializes devices, and according to debug symbols it was a "LiquidCrystal" LCD display.

After looking at the Adafruit_LiquidCrystal source code on [Github](https://github.com/adafruit/Adafruit_LiquidCrystal/blob/master/Adafruit_LiquidCrystal.cpp), I figured out that that huge block of code was just the class constructor and "begin" method that got inlined into the main() function. The usage of those libs also give us the hint that an Arduino board, which doesn't have "main()" function, but have "init()" and "loop()" functions, that get called by a SDK-generated main function. So, the real fun would happen in the "loop" function, which can be easily spotted thanks to the disassembly graph.

Then, in the main loop, we get decompiled code that looks like this:
```c
  do {
    auStack_d = (undefined  [3])0xd70;
    Adafruit_LiquidCrystal::setCursor('\0',(byte)R23R22);
    R3 = R1;
    R2 = R1;
    while( true ) {
      *(byte *)(Y + 2) = R3;
      *(byte *)(Y + 1) = R2;
      R25R24._0_1_ = 1;
      *(undefined *)(Y + 6) = 0;
      *(byte *)(Y + 5) = (byte)R25R24;
      *(undefined *)(Y + 3) = 0xb;
      R5 = R1;
      R7R6 = CONCAT11(R1,R1);
      R9R8 = CONCAT11(R1,R1);
      *(byte *)(Y + 4) = R1;
      while (Z = *(Adafruit_I2CDevice **)(Y + 1), Z != (Adafruit_I2CDevice *)0x0) {
        if (((uint)Z & 1) != 0) {
          R11R10._0_1_ = *(undefined *)(Y + 3);
          R11R10 = CONCAT11(R5,(byte)R11R10);
          R13R12 = R7R6;
          R15R14 = R9R8;
          auStack_d = (undefined  [3])0xd9a;
          __muldi3();
          Z = (Adafruit_I2CDevice *)CONCAT11(28,(byte)Z);
          R11R10 = CONCAT11(R1,28);
          R13R12 = CONCAT11(R1,R1);
          R15R14 = CONCAT11(R1,R1);
          auStack_d = (undefined  [3])0xda5;
          __moddi3();
          *(undefined *)(Y + 5) = R18;
          *(byte *)(Y + 6) = R19;
        }
        R25R24._0_1_ = *(byte *)(Y + 1);
        R25R24._1_1_ = *(byte *)(Y + 2);
        tempvar = R25R24._1_1_;
        R25R24._1_1_ = R25R24._1_1_ >> 1;
        R25R24._0_1_ = tempvar << 7 | (byte)R25R24 >> 1;
        *(byte *)(Y + 2) = R25R24._1_1_;
        *(byte *)(Y + 1) = (byte)R25R24;
        R11R10._0_1_ = *(undefined *)(Y + 3);
        R11R10 = CONCAT11(R5,(byte)R11R10);
        R13R12 = R7R6;
        R15R14 = R9R8;
        auStack_d = (undefined  [3])0xdbb;
        __muldi3();
        Z = (Adafruit_I2CDevice *)CONCAT11(Z._1_1_,28);
        R11R10 = CONCAT11(R1,28);
        R13R12 = CONCAT11(R1,R1);
        R15R14 = CONCAT11(R1,R1);
        auStack_d = (undefined  [3])0xdc6;
        __moddi3();
        *(undefined *)(Y + 3) = R18;
        R5 = R19;
        R7R6 = R21R20;
        R9R8 = R23R22;
        *(byte *)(Y + 4) = (byte)R25R24;
      }
      Z._0_1_ = *(byte *)(Y + 5);
      Z._1_1_ = *(char *)(Y + 6);
      Z = (Adafruit_I2CDevice *)
          CONCAT11((Z._1_1_ * '\x02' + CARRY1((byte)Z,(byte)Z)) -
                   (((byte)((byte)Z * '\x02') < 242) + -2),(byte)Z * '\x02' + 14);
      R23R22._0_1_ = *(byte *)Z;
      auStack_d = (undefined  [3])0xe1b;
      Adafruit_LiquidCrystal::send(&out,(byte)R23R22,true);
      auStack_d = (undefined  [3])0xe1d;
```

After trying to understand this non-sense code the first day, I gave up and fled into the wonderful world of anime. Then, I decided to give this challenge another try, and decided to focus on the actual assembler instructions rather than relying on a broken pseudo-C.

# Round 2: AVR assembly and some math go brrrr

Inside the "loop" function, we get this initialization block:
```
                             mfw_loopped                                     XREF[3]:     code:000ce0(j), code:000e53(j), 
                                                                                          code:000e56(j)  
     code:000d6d 80 e0           ldi        R24,0x0
     code:000d6e 0e 94 87 0a     call       Adafruit_LiquidCrystal::setCursor                undefined setCursor(uchar param_
     code:000d70 31 2c           mov        R3,R1
     code:000d71 21 2c           mov        R2,R1
                             init_sparta                                     XREF[2]:     code:000e0a(j), code:000e0e(j)  
     code:000d72 3a 82           std        Y+0x2,R3                                         Y + 2 = R3 (0 ?)
     code:000d73 29 82           std        Y+0x1,R2                                         Y + 1 = R2 (0 ?)
     code:000d74 81 e0           ldi        R24,0x1
     code:000d75 90 e0           ldi        R25,0x0
     code:000d76 9e 83           std        Y+0x6,R25                                        Y + 6 = 0
     code:000d77 8d 83           std        Y+0x5,R24                                        Y + 5 = 1
     code:000d78 9b e0           ldi        R25,0xb
     code:000d79 9b 83           std        Y+0x3,R25                                        Y + 3 = 0xb (11)
     code:000d7a 51 2c           mov        R5,R1
     code:000d7b 61 2c           mov        R6,R1
     code:000d7c 71 2c           mov        R7,R1
     code:000d7d 81 2c           mov        R8,R1
     code:000d7e 91 2c           mov        R9,R1
     code:000d7f 1c 82           std        Y+0x4,R1                                         Y + 4 = 0
     code:000d80 41 2c           mov        R4,R1                                            R4 - R9 = 0

```
Followed by:

```
                             where_the_fun_begins                            XREF[1]:     code:000dcc(j)  
     code:000d81 e9 81           ldd        Zlo,Y+0x1
     code:000d82 fa 81           ldd        Zhi,Y+0x2
     code:000d83 30 97           sbiw       Z,0x0
     code:000d84 09 f4           brbc       multiply_exponent,Zflg
     code:000d85 89 c0           rjmp       sendMessage
                             multiply_exponent                               XREF[1]:     code:000d84(j)  
     code:000d86 e0 ff           sbrs       Zlo,0x0
     code:000d87 1f c0           rjmp       bit0_empty
     code:000d88 9e 81           ldd        R25,Y+0x6                                        R25 = Y + 6
     code:000d89 99 0f           add        R25,R25
     code:000d8a 99 0b           sbc        R25,R25
     code:000d8b ab 80           ldd        R10,Y+0x3                                        R10 = (Y + 3) | (Y + 4) << 48 | 
     code:000d8c b5 2c           mov        R11,R5
     code:000d8d 63 01           movw       R13R12,R7R6
     code:000d8e 74 01           movw       R15R14,R9R8
     code:000d8f 0c 81           ldd        R16,Y+0x4
     code:000d90 14 2d           mov        R17,R4
     code:000d91 2d 81           ldd        R18,Y+0x5                                        R18 = ((Y + 5),(Y + 6))
     code:000d92 3e 81           ldd        R19,Y+0x6
     code:000d93 49 2f           mov        R20,R25
     code:000d94 59 2f           mov        R21,R25
     code:000d95 69 2f           mov        R22,R25
     code:000d96 79 2f           mov        R23,R25
     code:000d97 89 2f           mov        R24,R25
     code:000d98 0e 94 79 0e     call       __muldi3                                         undefined __muldi3(void)
     code:000d9a fc e1           ldi        Zhi,28
     code:000d9b af 2e           mov        R10,Zhi
     code:000d9c b1 2c           mov        R11,R1
     code:000d9d c1 2c           mov        R12,R1
     code:000d9e d1 2c           mov        R13,R1
     code:000d9f e1 2c           mov        R14,R1
     code:000da0 f1 2c           mov        R15,R1
     code:000da1 00 e0           ldi        R16,0x0
     code:000da2 10 e0           ldi        R17,0x0
     code:000da3 0e 94 d1 0e     call       __moddi3                                         undefined __moddi3(void)
     code:000da5 2d 83           std        Y+0x5,R18                                        (Y + 5), (Y + 6) = _muldi3 % 28
     code:000da6 3e 83           std        Y+0x6,R19

bit0_empty                                      XREF[1]:     code:000d87(j)  
     code:000da7 89 81           ldd        R24,Y+0x1
     code:000da8 9a 81           ldd        R25,Y+0x2
     code:000da9 96 95           lsr        R25
     code:000daa 87 95           ror        R24
     code:000dab 9a 83           std        Y+0x2,R25
     code:000dac 89 83           std        Y+0x1,R24                                        (Y+1) = (Y+1) / 2
     code:000dad ab 80           ldd        R10,Y+0x3
     code:000dae b5 2c           mov        R11,R5
     code:000daf 63 01           movw       R13R12,R7R6
     code:000db0 74 01           movw       R15R14,R9R8
     code:000db1 0c 81           ldd        R16,Y+0x4
     code:000db2 14 2d           mov        R17,R4
     code:000db3 2a 2d           mov        R18,R10
     code:000db4 35 2d           mov        R19,R5
     code:000db5 a3 01           movw       R21R20,R7R6
     code:000db6 b4 01           movw       R23R22,R9R8
     code:000db7 80 2f           mov        R24,R16
     code:000db8 94 2d           mov        R25,R4
     code:000db9 0e 94 79 0e     call       __muldi3                                         Y3Y4 = Y3Y4 ** 2
     code:000dbb ec e1           ldi        Zlo,28
     code:000dbc ae 2e           mov        R10,Zlo
     code:000dbd b1 2c           mov        R11,R1
     code:000dbe c1 2c           mov        R12,R1
     code:000dbf d1 2c           mov        R13,R1
     code:000dc0 e1 2c           mov        R14,R1
     code:000dc1 f1 2c           mov        R15,R1
     code:000dc2 00 e0           ldi        R16,0x0
     code:000dc3 10 e0           ldi        R17,0x0
     code:000dc4 0e 94 d1 0e     call       __moddi3                                         undefined __moddi3(void)
     code:000dc6 2b 83           std        Y+0x3,R18                                        Y + 3 gets the modulus
     code:000dc7 53 2e           mov        R5,R19
     code:000dc8 3a 01           movw       R7R6,R21R20
     code:000dc9 4b 01           movw       R9R8,R23R22
     code:000dca 8c 83           std        Y+0x4,R24
     code:000dcb 49 2e           mov        R4,R25
     code:000dcc b4 cf           rjmp       where_the_fun_begins

```

The "init_sparta" seems to initialize some stack variables:
```
*(short*)(Y+5) = 1
*(short*)(Y+3) = 0xb
*(short*)(Y+1) = 0
```

Then, the label "where_the_fun_begins" check if the `Z = *(short*)(Y+1)` register is equals to zero, and jumps magic stuff that print a letter on the LCD screen.
Otherwise, the code checks the first bit of Y register, and jumps to "bit0_empty" if the bit is 0.

Let's focus on the case when bit0_empty is set to 0:
The first instructions:
```
     code:000da7 89 81           ldd        R24,Y+0x1
     code:000da8 9a 81           ldd        R25,Y+0x2
     code:000da9 96 95           lsr        R25
     code:000daa 87 95           ror        R24
```
is just a division by two optimized by GCC (it's even stated on AVR's instruction reference). For people used to crypto, an algorithm that checks the lowest bit of a variable and then divides this variable by two (and call to multiplication and modulo functions), smells like modular exponentiation but let's continue our journey.

There is a lot of stuff moved into registers before a call to a "__muldi3" call: this call is a compier-provided function that get called on architectures that don't have opcodes to multiply 64-bit integers. And it seems that the first 64-bit argument is passed through registers R18-R25, and the second 64-bit argument through R10-R17. And since registers from R5 to R9 have been set to 0, we end up with this pseudo-code:
```
{R18-R25} = _muldi3(*(short*)(Y+3),*(short*)(Y+3))
```
which is basically a power of two, reinforcing the hypothesis of a modular exponentiation.

The next call follows the same logic, except since the return value of _muldi3 is already stored into the registers used to pass the first argument, only the second argument is loaded into {R10-R17}, which is our modulus, `28`.

This means, that if the first bit of our "Y+1" variable is set to 0 (which means it's a multiple of 2), we are basically doing:

```
Y3 = (Y3*Y3) % 28
```

If the first bit of "Y+1" variable is set to 1, then we enter into the "multiply_exponent" label, where funny GCC optimizations happen (for the record, I understood some parts of those optimizations when writing this writeup, I flagged by making an educated guess on modular exponentiation):
```
     code:000d88 9e 81           ldd        R25,Y+0x6                                        R25 = Y + 6
     code:000d89 99 0f           add        R25,R25
     code:000d8a 99 0b           sbc        R25,R25
     code:000d8b ab 80           ldd        R10,Y+0x3                                        R10 = (Y + 3) | (Y + 4) << 48
     code:000d8c b5 2c           mov        R11,R5
     code:000d8d 63 01           movw       R13R12,R7R6
     code:000d8e 74 01           movw       R15R14,R9R8
     code:000d8f 0c 81           ldd        R16,Y+0x4
     code:000d90 14 2d           mov        R17,R4
```
In our case, R25 will be always 0 (since R24R25 only contain an integer modulo 28) and the same happens for the byte in `Y+4`.

Basically, the code does:
 ```
*(short*)Y5 = (*(short*)Y5) * (*(short*)Y3) % 28
````

This can be translated by:
```
while(Y1) {
  if(Y1 & 1) {
    Y5 = (Y5) * (Y3) % 28
  }
  Y1 = Y1 / 2;
  Y3 = (Y3*Y3) % 28
}
```
And bingo, the educated guess was correct :þ

Now let's make another educated guess and considering we can get the flag with
```python
lol = b'\x00uewefi_}{_tbmgleophcopb_aleo'

exp = 11
l = []
for i in range(28):
    l.append(chr(lol[pow(exp, i, 28)]))

print("".join(l))
```

And... `ut{labut{labut{labut{l`, which obviously does not look like a flag.

The problem here is that the modulus 28 is not a prime number, which can lead to funny things, like making impossible to find a generator of the set of numbers from 1 to n-1.

But fortunately, 28 = 29-1, and 29 is a prime number, so let's change 28 by 29:
```python
lol = b'\x00uewefi_}{_tbmgleophcopb_aleo'

exp = 11
l = []
for i in range(29):
    l.append(chr(lol[pow(exp, i, 29)]))

print("".join(l))
```
... and `utflag{beep_boop_welcome_hi}u`
