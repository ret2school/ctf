Name: Run-ELF
Description: Anyone know how to run an ELF file? I bet you could figure it out.
Author: balex
Points: 100

Let's open the bianry in radare2 to see what it looks like.

```
❯ radare2 run                                                                                                                                                                                                    100%
Warning: run r2 with -e io.cache=true to fix relocations in disassembly
 -- Heisenbug: A bug that disappears or alters its behavior when one attempts to probe or isolate it.
 [0x00001040]> aaa
 [x] Analyze all flags starting with sym. and entry0 (aa)
 [x] Analyze function calls (aac)
 [x] Analyze len bytes of instructions for references (aar)
 [x] Check for vtables
 [x] Type matching analysis for all functions (aaft)
 [x] Propagate noreturn information
 [x] Use -AA or aaaa to perform additional experimental analysis.
 [0x00001040]> s main
 [0x00001139]> pdf
             ; DATA XREF from entry0 @ 0x1061
             ┌ 43: int main (int argc, char **argv, char **envp);
             │           ; var char *format @ rbp-0x8
             │           0x00001139      55             push rbp
             │           0x0000113a      4889e5         mov rbp, rsp
             │           0x0000113d      4883ec10       sub rsp, 0x10
             │           0x00001141      488d05c00e00.  lea rax, str.utflagrun_run_binary_9312854_n ; 0x2008 ; "utflag{run_run_binary_9312854}\n"
             │           0x00001148      488945f8       mov qword [format], rax
             │           0x0000114c      488b45f8       mov rax, qword [format]
             │           0x00001150      4889c7         mov rdi, rax                ; const char *format
             │           0x00001153      b800000000     mov eax, 0
             │           0x00001158      e8d3feffff     call sym.imp.printf         ; int printf(const char *format)
             │           0x0000115d      b800000000     mov eax, 0
             │           0x00001162      c9             leave
             └           0x00001163      c3             ret
             [0x00001139]> q
```
Indeed, we would have just had to run the binary to get the flag.