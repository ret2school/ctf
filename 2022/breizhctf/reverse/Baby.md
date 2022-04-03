# [BreizhCTF2020 - Reverse] Baby

    Value: 50

    Description:

    Le reverse c'est quand même vachement compliqué... ou pas ?

    Auteur: Worty

    Format : BZHCTF{}

Like all the CTF challenges named "Baby", this challenge was very simple.

You just had to open the source code in `radare2` to see the flag in clear:

```
> r2 baby
[0x00001070]> aaa
[Cannot find function at 0x00001070 sym. and entry0 (aa)
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze function calls (aac)
[x] Analyze len bytes of instructions for references (aar)
[x] Check for objc references
[x] Check for vtables
[x] Type matching analysis for all functions (aaft)
[x] Propagate noreturn information
[x] Use -AA or aaaa to perform additional experimental analysis.
[0x00001070]> s main
[0x00001169]> pdf
            ; DATA XREF from entry0 @ +0x18
┌ 157: int main (int argc, char **argv);
│           ; var char **var_40h @ rbp-0x40
│           ; var int64_t var_34h @ rbp-0x34
│           ; var char *s1 @ rbp-0x30
│           ; var int64_t canary @ rbp-0x8
│           ; arg int argc @ rdi
│           ; arg char **argv @ rsi
│           0x00001169      55             push rbp
│           0x0000116a      4889e5         mov rbp, rsp
│           0x0000116d      4883ec40       sub rsp, 0x40
│           0x00001171      897dcc         mov dword [var_34h], edi    ; argc
│           0x00001174      488975c0       mov qword [var_40h], rsi    ; argv
│           0x00001178      64488b042528.  mov rax, qword fs:[0x28]
│           0x00001181      488945f8       mov qword [canary], rax
│           0x00001185      31c0           xor eax, eax
│           0x00001187      488d057a0e00.  lea rax, qword str.What_is_the_password ; 0x2008 ; "What is the password?"
│           0x0000118e      4889c7         mov rdi, rax                ; const char *s
│           0x00001191      e89afeffff     call sym.imp.puts           ; int puts(const char *s)
│           0x00001196      488d45d0       lea rax, qword [s1]
│           0x0000119a      4889c6         mov rsi, rax
│           0x0000119d      488d057a0e00.  lea rax, qword str.35s      ; 0x201e ; "%35s"
│           0x000011a4      4889c7         mov rdi, rax                ; const char *format
│           0x000011a7      b800000000     mov eax, 0
│           0x000011ac      e8affeffff     call sym.imp.__isoc99_scanf ; int scanf(const char *format)
│           0x000011b1      488d45d0       lea rax, qword [s1]
│           0x000011b5      488d156c0e00.  lea rdx, qword str.BZHCTF_b4by_r3_f0r_y0u_g00d_luck ; 0x2028 ; "BZHCTF{b4by_r3_f0r_y0u_g00d_luck!!}"
│           0x000011bc      4889d6         mov rsi, rdx                ; const char *s2
│           0x000011bf      4889c7         mov rdi, rax                ; const char *s1
│           0x000011c2      e889feffff     call sym.imp.strcmp         ; int strcmp(const char *s1, const char *s2)
│           0x000011c7      85c0           test eax, eax
│       ┌─< 0x000011c9      7511           jne 0x11dc
│       │   0x000011cb      488d057e0e00.  lea rax, qword str.Well_done__You_can_validate_with_this_flag ; 0x2050 ; "Well done! You can validate with this flag!"
│       │   0x000011d2      4889c7         mov rdi, rax                ; const char *s
│       │   0x000011d5      e856feffff     call sym.imp.puts           ; int puts(const char *s)
│      ┌──< 0x000011da      eb0f           jmp 0x11eb
│      ││   ; CODE XREF from main @ 0x11c9
│      │└─> 0x000011dc      488d05990e00.  lea rax, qword str.No...    ; 0x207c ; "No..."
│      │    0x000011e3      4889c7         mov rdi, rax                ; const char *s
│      │    0x000011e6      e845feffff     call sym.imp.puts           ; int puts(const char *s)
│      │    ; CODE XREF from main @ 0x11da
│      └──> 0x000011eb      b800000000     mov eax, 0
│           0x000011f0      488b55f8       mov rdx, qword [canary]
│           0x000011f4      64482b142528.  sub rdx, qword fs:[0x28]
│       ┌─< 0x000011fd      7405           je 0x1204
│       │   0x000011ff      e83cfeffff     call sym.imp.__stack_chk_fail ; void __stack_chk_fail(void)
│       │   ; CODE XREF from main @ 0x11fd
│       └─> 0x00001204      c9             leave
└           0x00001205      c3             ret
```

```
BZHCTF{b4by_r3_f0r_y0u_g00d_luck!!}
```