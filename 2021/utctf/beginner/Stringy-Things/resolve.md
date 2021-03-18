Name: Stringy Things
Description: I know there's a string in this binary somewhere.... Now where did I leave it?
Author: balex
Points: 100

Let's open the bianry in radare2 to see what it looks like, as we did for RUN-ELF.

```
❯ radare2 calc                                                                                                                                                                                                        100%
Warning: run r2 with -e io.cache=true to fix relocations in disassembly
 -- radare2 is power, France is pancake.
 [0x00001060]> aaa
 [x] Analyze all flags starting with sym. and entry0 (aa)
 [x] Analyze function calls (aac)
 [x] Analyze len bytes of instructions for references (aar)
 [x] Check for vtables
 [x] Type matching analysis for all functions (aaft)
 [x] Propagate noreturn information
 [x] Use -AA or aaaa to perform additional experimental analysis.
 [0x00001060]> s main
 [0x00001159]> dissas
 Usage: di  Debugger target information
 | di             Show debugger target information
 | di*            Same as above, but in r2 commands
 | diq            Same as above, but in one line
 | dij            Same as above, but in JSON format
 | dif [$a] [$b]  Compare two files (or $alias files)
 [0x00001159]> pdf
             ; DATA XREF from entry0 @ 0x1081
             ┌ 440: int main (int argc, char **argv, char **envp);
             │           ; var int64_t var_21h @ rbp-0x21
             │           ; var double var_20h @ rbp-0x20
             │           ; var int64_t var_18h @ rbp-0x18
             │           ; var char *var_10h @ rbp-0x10
             │           ; var int64_t canary @ rbp-0x8
             │           0x00001159      55             push rbp
             │           0x0000115a      4889e5         mov rbp, rsp
             │           0x0000115d      4883ec30       sub rsp, 0x30
             │           0x00001161      64488b042528.  mov rax, qword fs:[0x28]
             │           0x0000116a      488945f8       mov qword [canary], rax
             │           0x0000116e      31c0           xor eax, eax
             │           0x00001170      488d3d910e00.  lea rdi, str.Enter_an_operator_________:_ ; 0x2008 ; "Enter an operator (+, -, *,): " ; const char *format
             │           0x00001177      b800000000     mov eax, 0
             │           0x0000117c      e8bffeffff     call sym.imp.printf         ; int printf(const char *format)
             │           0x00001181      488d45df       lea rax, [var_21h]
             │           0x00001185      4889c6         mov rsi, rax
             │           0x00001188      488d3d980e00.  lea rdi, [0x00002027]       ; "%c" ; const char *format
             │           0x0000118f      b800000000     mov eax, 0
             │           0x00001194      e8b7feffff     call sym.imp.__isoc99_scanf ; int scanf(const char *format)
             │           0x00001199      488d3d8a0e00.  lea rdi, str.Enter_two_operands:_ ; 0x202a ; "Enter two operands: " ; const char *format
             │           0x000011a0      b800000000     mov eax, 0
             │           0x000011a5      e896feffff     call sym.imp.printf         ; int printf(const char *format)
             │           0x000011aa      488d55e8       lea rdx, [var_18h]
             │           0x000011ae      488d45e0       lea rax, [var_20h]
             │           0x000011b2      4889c6         mov rsi, rax
             │           0x000011b5      488d3d830e00.  lea rdi, str._lf__lf        ; 0x203f ; "%lf %lf" ; const char *format
             │           0x000011bc      b800000000     mov eax, 0
             │           0x000011c1      e88afeffff     call sym.imp.__isoc99_scanf ; int scanf(const char *format)
             │           0x000011c6      0fb645df       movzx eax, byte [var_21h]
             │           0x000011ca      0fbec0         movsx eax, al
             │           0x000011cd      83f82f         cmp eax, 0x2f
             │       ┌─< 0x000011d0      0f84cd000000   je 0x12a3
             │       │   0x000011d6      83f82f         cmp eax, 0x2f
             │      ┌──< 0x000011d9      0f8ffb000000   jg 0x12da
             │      ││   0x000011df      83f82d         cmp eax, 0x2d
             │     ┌───< 0x000011e2      7451           je 0x1235
             │     │││   0x000011e4      83f82d         cmp eax, 0x2d
             │    ┌────< 0x000011e7      0f8fed000000   jg 0x12da
             │    ││││   0x000011ed      83f82a         cmp eax, 0x2a
             │   ┌─────< 0x000011f0      747a           je 0x126c
             │   │││││   0x000011f2      83f82b         cmp eax, 0x2b
             │  ┌──────< 0x000011f5      0f85df000000   jne 0x12da
             │  ││││││   0x000011fb      f20f104de0     movsd xmm1, qword [var_20h]
             │  ││││││   0x00001200      f20f1045e8     movsd xmm0, qword [var_18h]
             │  ││││││   0x00001205      f20f58c8       addsd xmm1, xmm0
             │  ││││││   0x00001209      f20f1045e8     movsd xmm0, qword [var_18h]
             │  ││││││   0x0000120e      488b45e0       mov rax, qword [var_20h]
             │  ││││││   0x00001212      660f28d1       movapd xmm2, xmm1
             │  ││││││   0x00001216      660f28c8       movapd xmm1, xmm0
             │  ││││││   0x0000121a      66480f6ec0     movq xmm0, rax
             │  ││││││   0x0000121f      488d3d210e00.  lea rdi, [0x00002047]       ; "%.1lf + %.1lf = %.1lf" ; const char *format
             │  ││││││   0x00001226      b803000000     mov eax, 3
             │  ││││││   0x0000122b      e810feffff     call sym.imp.printf         ; int printf(const char *format)
             │ ┌───────< 0x00001230      e9b6000000     jmp 0x12eb
             │ │││││││   ; CODE XREF from main @ 0x11e2
             │ ││││└───> 0x00001235      f20f1045e0     movsd xmm0, qword [var_20h]
             │ ││││ ││   0x0000123a      f20f104de8     movsd xmm1, qword [var_18h]
             │ ││││ ││   0x0000123f      660f28d0       movapd xmm2, xmm0
             │ ││││ ││   0x00001243      f20f5cd1       subsd xmm2, xmm1
             │ ││││ ││   0x00001247      f20f1045e8     movsd xmm0, qword [var_18h]
             │ ││││ ││   0x0000124c      488b45e0       mov rax, qword [var_20h]
             │ ││││ ││   0x00001250      660f28c8       movapd xmm1, xmm0
             │ ││││ ││   0x00001254      66480f6ec0     movq xmm0, rax
             │ ││││ ││   0x00001259      488d3dfd0d00.  lea rdi, [0x0000205d]       ; "%.1lf - %.1lf = %.1lf" ; const char *format
             │ ││││ ││   0x00001260      b803000000     mov eax, 3
             │ ││││ ││   0x00001265      e8d6fdffff     call sym.imp.printf         ; int printf(const char *format)
             │ ││││┌───< 0x0000126a      eb7f           jmp 0x12eb
             │ │││││││   ; CODE XREF from main @ 0x11f0
             │ ││└─────> 0x0000126c      f20f104de0     movsd xmm1, qword [var_20h]
             │ ││ ││││   0x00001271      f20f1045e8     movsd xmm0, qword [var_18h]
             │ ││ ││││   0x00001276      f20f59c8       mulsd xmm1, xmm0
             │ ││ ││││   0x0000127a      f20f1045e8     movsd xmm0, qword [var_18h]
             │ ││ ││││   0x0000127f      488b45e0       mov rax, qword [var_20h]
             │ ││ ││││   0x00001283      660f28d1       movapd xmm2, xmm1
             │ ││ ││││   0x00001287      660f28c8       movapd xmm1, xmm0
             │ ││ ││││   0x0000128b      66480f6ec0     movq xmm0, rax
             │ ││ ││││   0x00001290      488d3ddc0d00.  lea rdi, str._.1lf___.1lf___.1lf ; 0x2073 ; "%.1lf * %.1lf = %.1lf" ; const char *format
             │ ││ ││││   0x00001297      b803000000     mov eax, 3
             │ ││ ││││   0x0000129c      e89ffdffff     call sym.imp.printf         ; int printf(const char *format)
             │ ││┌─────< 0x000012a1      eb48           jmp 0x12eb
             │ │││││││   ; CODE XREF from main @ 0x11d0
             │ ││││││└─> 0x000012a3      f20f1045e0     movsd xmm0, qword [var_20h]
             │ ││││││    0x000012a8      f20f104de8     movsd xmm1, qword [var_18h]
             │ ││││││    0x000012ad      660f28d0       movapd xmm2, xmm0
             │ ││││││    0x000012b1      f20f5ed1       divsd xmm2, xmm1
             │ ││││││    0x000012b5      f20f1045e8     movsd xmm0, qword [var_18h]
             │ ││││││    0x000012ba      488b45e0       mov rax, qword [var_20h]
             │ ││││││    0x000012be      660f28c8       movapd xmm1, xmm0
             │ ││││││    0x000012c2      66480f6ec0     movq xmm0, rax
             │ ││││││    0x000012c7      488d3dbb0d00.  lea rdi, str._.1lf____.1lf___.1lf ; 0x2089 ; "%.1lf / %.1lf = %.1lf" ; const char *format
             │ ││││││    0x000012ce      b803000000     mov eax, 3
             │ ││││││    0x000012d3      e868fdffff     call sym.imp.printf         ; int printf(const char *format)
             │ ││││││┌─< 0x000012d8      eb11           jmp 0x12eb
             │ │││││││   ; CODE XREFS from main @ 0x11d9, 0x11e7, 0x11f5
             │ │└─└─└──> 0x000012da      488d3dbf0d00.  lea rdi, str.Error__operator_is_not_correct ; 0x20a0 ; "Error! operator is not correct" ; const char *format
             │ │ │ │ │   0x000012e1      b800000000     mov eax, 0
             │ │ │ │ │   0x000012e6      e855fdffff     call sym.imp.printf         ; int printf(const char *format)
             │ │ │ │ │   ; CODE XREFS from main @ 0x1230, 0x126a, 0x12a1, 0x12d8
             │ └─└─└─└─> 0x000012eb      488d05cd0d00.  lea rax, str.utflagstrings_is_op ; 0x20bf ; "utflag{strings_is_op}"
             │           0x000012f2      488945f0       mov qword [var_10h], rax
             │           0x000012f6      b800000000     mov eax, 0
             │           0x000012fb      488b4df8       mov rcx, qword [canary]
             │           0x000012ff      64482b0c2528.  sub rcx, qword fs:[0x28]
             │       ┌─< 0x00001308      7405           je 0x130f
             │       │   0x0000130a      e821fdffff     call sym.imp.__stack_chk_fail ; void __stack_chk_fail(void)
             │       │   ; CODE XREF from main @ 0x1308
             │       └─> 0x0000130f      c9             leave
             └           0x00001310      c3             ret
             [0x00001159]> q
```

This time, again we can get the flag without any effort.