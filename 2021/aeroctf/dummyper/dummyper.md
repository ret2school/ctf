# Aero CTF 2021 - Dummyper (454 pts)

This the first challenge I did. The challenge's task was:
> This stupid program has encrypted our flag.
>
> We only have a dump left.

With a mysterious "dump.7z" that contains a "dump" file. This file is an ELF binary, so we load it in IDA.

## Overview

IDA complains about broken section table, but still succeeds to load the bin. We get classical glibc's `__libc_start_main`, and the "main" function which looks like this:
```
; int __fastcall main(int, char **, char **)
main proc near
endbr64
push    rbp
mov     rbp, rsp
call    loc_1691
call    sub_172A
call    sub_188B
mov     eax, 0
pop     rbp
retn
main endp
```
The first function contains garbage, such as:
```
loc_1691:                               ; CODE XREF: main+8↓p
LOAD:0000000000001691                 out     53h, al
LOAD:0000000000001693                 pop     rbp
LOAD:0000000000001694                 out     1, eax          ; DMA controller, 8237A-5.
LOAD:0000000000001694                                         ; channel 0 base address and word count
LOAD:0000000000001696                 std
LOAD:0000000000001697                 adc     [rdi+65h], cl
LOAD:000000000000169A                 movsb
LOAD:000000000000169B                 mov     ebx, 58D66E0Ah
LOAD:000000000000169B ; ---------------------------------------------------------------------------
LOAD:00000000000016A0                 dq 91870DBC4BC97160h, 1FEC1165698C4247h, 26B5D424EA599C8Ah
```
which probably means that the binary was edited before the dump was taken. A quick look to the next function (`sub_172a`) confirms this:
```c
_BYTE *sub_172A()
{
  _BYTE *result; // rax
  int i; // [rsp+Ch] [rbp-34h]
  int j; // [rsp+10h] [rbp-30h]
  int v3; // [rsp+14h] [rbp-2Ch]
  int v4; // [rsp+1Ch] [rbp-24h]
  void *ptr; // [rsp+28h] [rbp-18h]
  void *v6; // [rsp+38h] [rbp-8h]

  v3 = getpagesize();
  mprotect((char *)&loc_13A9 - (unsigned __int64)&loc_13A9 % v3, v3, 7);
  ptr = (void *)((__int64 (__fastcall *)(__int64))loc_13A9)(32LL);
  fread(ptr, 0x20uLL, 1uLL, stream);
  for ( i = 0; i <= 63; ++i )
  {
    v4 = rand() % 2047;
    v6 = (void *)((__int64 (__fastcall *)(_QWORD))loc_13A9)(v4);
    fread(v6, v4, 1uLL, stream);
  }
  result = &loc_13A9;
  for ( j = 0; j <= 895; ++j )
  {
    result = (char *)&loc_13A9 + j;
    *result ^= *((_BYTE *)ptr + j % 32);
  }
  return result;
}
```
It's obvious to see that the function calls mprotect to allow writing on the .text session, then call `loc_13a9`, which also contains garbage. Then, some part of the text section is xored with a random key. So to analyze further the binary, we need to find the decryption key, which is a 32-byte key.

Luckily, we have an amd64 binary, and gcc puts an "endbr64" instruction at the beginning of each section, before the habitual prologue `push rbp, mov rbp, rsp`. So we can recover 8 bytes of the key with partial known plaintext.

We have two encrypted functions, and luckily, the first function is at position 0 mod 32, and the second function at pos 8 mod 32, which means we know the first 16 bytes of the key, we have to xor the 8 first bytes of the function with "f30f1efa554889e5" (our prologue).

Then, we can manage to "guess" some bytes looking at the partial disassembly, which gives this decoding script:
```python
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

out = open("dump2", "wb")
out.write(modbuf)
out.close()
```
Now we have recovered the full code, we can analyze the dump.

## Analysis of the decrypted dump
The main function didn't change a lot, but now the `sub_1691` function disassembles correctly. Let's have a look to the decompiled function:
```c
__int64 sub_1691()
{
  unsigned int v0; // eax
  FILE *stream; // [rsp+0h] [rbp-10h]
  void *ptr; // [rsp+8h] [rbp-8h]

  randomfile = fopen("/dev/urandom", "r");
  v0 = time(0LL);
  srand(v0);
  stream = fopen("./flag.txt", "r");
  ptr = (void *)alloc_mem(128LL);
  fread(ptr, 0x80uLL, 1uLL, stream);
  fclose(stream);
  return cryptostuff(ptr);
}
```
The function calls `alloc_mem` which looks like this:
```c
char *__fastcall alloc_mem(size_t a1)
{
  char *s; // [rsp+18h] [rbp-8h]

  s = (char *)&unk_5060 + count;
  memset((char *)&unk_5060 + count, 204, a1);
  count += a1;
  return s;
}
```
to write the flag on it. Then the function calls `cryptostuff`, we'll look into.
```c
 for ( i = 0; i <= 63; ++i )
  {
    v9 = rand() % 2047;
    ptr = alloc_mem(v9);
    fread(ptr, v9, 1uLL, randomfile);
  }
  aeskey = alloc_mem(0x20uLL);
  for ( j = 0; j <= 63; ++j )
  {
    v8 = rand() % 2047;
    v15 = alloc_mem(v8);
    fread(v15, v8, 1uLL, randomfile);
  }
  aesiv = alloc_mem(0x10uLL);
  for ( k = 0; k <= 63; ++k )
  {
    v7 = rand() % 2047;
    v14 = alloc_mem(v7);
    fread(v14, v7, 1uLL, randomfile);
  }
  fread(aeskey, 1uLL, 0x20uLL, randomfile);
  fread(aesiv, 1uLL, 0x10uLL, randomfile);
  aes_ctx = alloc_mem(0xC0uLL);
  for ( l = 0; l <= 63; ++l )
  {
    v6 = rand() % 2047;
    v13 = alloc_mem(v6);
    fread(v13, v6, 1uLL, randomfile);
  }
  aes_setup_key((__int64)aes_ctx, (__int64)aeskey);
  aes_setup_iv(aes_ctx, aesiv);
  return aes_encrypt(aes_ctx, flag, 128LL);
  ```
  The function calls the custom "malloc" to get the AES key and IV (the AES function could be identified thanks to its S-Box which begins with `63h, 7Ch, 77h, 7Bh, 0F2h, 6Bh, 6Fh, 0C5h, 30h, 1, 67h`). To avoid being found easily, a lot of junk allocation with random sizes are performed. Fortunately, those random allocation are performed with `rand`, which is initialized with `srand(time(NULL))`. So we just need to know when the program was run, you can know thanks to the modification date of the "dump" file in the archive.

  So, the solve script to fetch the flag (I use the offset of the xor key as a check to determine if we got the right seed):
  ```python
  #!/usr/bin/python
from ctypes import CDLL
from Crypto.Cipher import AES
libc = CDLL("libc.so.6")

# Offset where blocks are allocated
blockoff = 0x5060

f = open("dump", "rb")
buf = f.read()

# Get the encrypted flag
encflag = buf[blockoff:blockoff + 0x80]

# Bruteforce timestamps for the 25 Feb. to get the correct seed
ts = 1614211200
for i in range(0, 24*3660):
    blockpos = 0x80
    libc.srand(ts + i)
    for _ in range(0, 64):
        blockpos += libc.rand() % 2047
    aeskey = buf[blockoff + blockpos:blockoff + blockpos + 0x10]
    blockpos += 0x20
    for _ in range(0, 64):
        blockpos += libc.rand() % 2047
    aesiv = buf[blockoff + blockpos:blockoff + blockpos + 0x10]
    blockpos += 0x10
    for _ in range(0, 64):
        blockpos += libc.rand() % 2047
    blockpos += 0xc0
    for _ in range(0, 64):
        blockpos += libc.rand() % 2047
    # If the computed offset is the offset of the xor key in the dump, we won
    if(blockoff + blockpos == 0x4ba74):
        print("Found candidate %d" % i)
        break

c = AES.new(aeskey, AES.MODE_CBC, aesiv)
print(i)
print(c.decrypt(encflag))
```
And the flag we got is `Aero{d37fd6db2f8d562422aaf2a83dc62043}`