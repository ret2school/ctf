---
title: "[CSAW CTF 2020 - RE] : Cuba"
date: 2020-09-13 17:14:00
---

Hi

This is my write up for the challange `Cuba` of CSAW CTF 2020 :

So this challenge is a CUBA program wrapped in a Windows Executable. CUBA is a GPU langage created by NVIDIA to work around GPU with high performance langage. 

https://docs.nvidia.com/cuda/cuda-c-programming-guide/index.html

Luckily there is a public SDK for it, with a disassembler :

https://docs.nvidia.com/cuda/cuda-binary-utilities/index.html

Using a tool called `cuobjdump`, we can extract the assembly code :

    To extract ptx text from a host binary, use the following command:

    cuobjdump -ptx <host binary>

And after reversing the output, we can see that it's a simple xor looping through a ciphered flag

```asm
.global .align 1 .b8 $CORRECT[18] = {67, 79, 82, 82, 69, 67, 84, 32, 80, 65, 83, 83, 87, 79, 82, 68, 33, 0};

.global .align 1 .b8 $WRONG[27] = {87, 82, 79, 78, 71, 32, 80, 65, 83, 83, 87, 79, 82, 68, 44, 32, 84, 82, 89, 32, 65, 71, 65, 73, 78, 33, 0};
...

// load each xorred bytes on stack

mov.u16         %rs1, 99;
.loc	        1 14 18;
st.u8           [%SP+30], %rs1;
mov.u16         %rs2, 103;
st.u8           [%SP+29], %rs2;
mov.u16         %rs3, 104;
st.u8           [%SP+28], %rs3;
mov.u16         %rs4, 122;
st.u8           [%SP+27], %rs4;
mov.u16         %rs5, 41;
st.u8           [%SP+26], %rs5;
mov.u16         %rs6, 113;
...

LOOP:
.loc            1 20 5;
mov.u32         %r4, %r21;              // %r4 = i
mov.u32         %r3, %r20;
ld.u32          %r11, [%rd2];           // %r11 = FLAG_SIZE
setp.lt.s32     %p3, %r4, %r11;         // %p3 = i < %r11
not.pred        %p4, %p3;               // %p4 = %p3 == 0
@%p4 bra        FINAL_CMP;              // if %p4 : jmp
bra.uni         UNCIPHER;

UNCIPHER:
.loc            1 22 9;
cvt.s64.s32     %rd10, %r4;             // %r4 = i
add.s64         %rd11, %rd1, %rd10;     // %rd11 = &INPUT + 1
ld.u8           %rs25, [%rd11];         // %rs25 = INPUT[i]
cvt.r32.u16     %r14, %rs25;            // unsigned -> signed 
cvt.s32.s8      %r15, %r14;             // %r15 = INPUT[i] 
xor.b32         %r16, %r15, %r4;        // %r16 = %r15 ^ i
cvt.s64.s32     %rd12, %r4;
add.u64         %rd13, %SP, 0;          // %rd13 = &FLAG
add.s64         %rd14, %rd13, %rd12;    // %rd13 = &FLAG + 1
ld.u8           %rs26, [%rd14];         // %rs26 = FLAG[i]
cvt.u32.u16     %r17, %rs26;            // unsigned -> signed 
cvt.s32.s8      %r18, %r17;             // %r18 = FLAG[i]
setp.eq.s32     %p7, %r16, %r18;        // %p7 = %r16 == %r18
not.pred        %p8, %p7;
mov.u32         %r22, %r3;
@%p8 bra        BB6_6;
...

bra.uni LOOP;

FINAL_CMP:
.loc	        1 26 5;
setp.eq.s32	    %p5, %r3, 31;           // %p5 = %r3 == 31
not.pred        %p6, %p5;               // %p6 = %p5 == 0
@%p6 bra        WRONG_PASS;
bra.uni         CORRECT_PASS;

WRONG_PASS:
.loc	        1 30 9;
mov.u64         %rd4, $WRONG;
cvta.global.u64 %rd5, %rd4;
mov.u64         %rd6, 0;

CORRECT_PASS:
.loc	        1 27 9;
mov.u64         %rd7, $CORRECT;
cvta.global.u64 %rd8, %rd7;
mov.u64         %rd9, 0;

```

Then a decryption script :

```python
xorred = [102, 109, 99, 100, 127, 104, 53, 52, 124, 86, 103, 56, 83, 100, 96, 80, 114, 125, 123, 99, 103, 74, 120, 72, 123, 113, 41, 122, 104, 103, 99]

for i in range(len(xorred)):
    xorred[i] = xorred[i] ^ i

print(xorred)
```

And here is the flag : `flag{m33t_m3_in_blips_n_ch3atz}`

~r0da