# sELF control (75 pts)
> I found a program to read the flag but it seems to be broken... Could you help me patching patching two bytes to make it functional ?
> 
> Challenge : nc chall0.heroctf.fr 2048
> 
> Format : Hero{}
> 
> Author : SoEasY

The binary given is an ELF File, but IDA detects it as "IA64" ELF. Looking up at it on radare2
show that's machine code is indeed x86_64, and the ELF header is messed up.

To fix that, we must patch the header to correct the architecture, which is the field `e_machine`
of the ELF header, at offset 0x12, with the value EM_X86_64, defined to 0x3e.

Now, trying to run the binary triggers a segfault, so we open GDB to check what happens and we see this:

```
#0  0x0000555d375c90a1 in _start ()
(gdb) disass
Dump of assembler code for function _start:
   0x0000555d375c90a0 <+0>:	xor    ebp,ebp
```

The low byte of the start address (e_entry) at 0x18 is wrong, and we need to patch it to 0xa0, too. After those patches, the binary runs correctly, and we can connect to the server:

```

Position of the byte to patch in hex (example: 08) : 12
Value to put at this offset in hex (example: 17) : 3e

Position of the byte to patch in hex (example: 03) : 18
Value to put at this offset in hex (example: 04) : a0

[+] Execution : 
Hero{W0w_s0_y0u_4r3_4n_ELF_h34d3r_M4sT3r???}
```

# JNI (90 pts)
> Find the flag in this android application.
> 
> Format : Hero{}
> 
> Author : xanhacks

We are given an Android application (in APK). But, as the challenge title says, the flag verification check happens in a native library, which is called by the application through Java Native Interface.

So, we decompress the APK (which is just a zip file), and extract the "lib/" folder which contains native libs. Luckily we have a x86_64 version of the native lib, which spares us the burden of reversing ARM assembly.

In IDA, we find an interesting function, `Java_fr_heroctf_jni_MainActivity_checkFlag`, which seems to be the flag checker. Let's look at its code:
```
.text:00000000000007AF                 mov     rdi, [rbp+s]    ; s
.text:00000000000007B3                 call    _strlen
.text:00000000000007B8                 mov     [rbp+var_18], rax
.text:00000000000007BC
.text:00000000000007BC loc_7BC:                                ; CODE XREF: Java_fr_heroctf_jni_MainActivity_checkFlag+7A↑j
.text:00000000000007BC                 cmp     [rbp+var_18], 3
.text:00000000000007C1                 jnz     loc_802
.text:00000000000007C7                 mov     rax, [rbp+var_58]
.text:00000000000007CB                 movsx   ecx, byte ptr [rax]
.text:00000000000007CE                 cmp     ecx, 36h ; '6'
.text:00000000000007D1                 jnz     loc_802
.text:00000000000007D7                 mov     rax, [rbp+var_58]
.text:00000000000007DB                 movsx   ecx, byte ptr [rax+1]
.text:00000000000007DF                 cmp     ecx, 36h ; '6'
.text:00000000000007E2                 jnz     loc_802
.text:00000000000007E8                 mov     rax, [rbp+var_58]
.text:00000000000007EC                 movsx   ecx, byte ptr [rax+2]
.text:00000000000007F0                 cmp     ecx, 36h ; '6'
.text:00000000000007F3                 jnz     loc_802
.text:00000000000007F9                 mov     [rbp+var_31], 1
.text:00000000000007FD                 jmp     loc_80B
```

It's pretty obvious that the input string is compared with "666", and we can validate the challenge with `Hero{666}`.

# Password Keeper (100 pts)
> You are mandated to pentest a new password manager application. Try to log your self to the application !
> 
> Format : Hero{user:password}
> 
> Author : SoEasY

This time we are given a Mach-O executable from OS X. As usual, we open it in IDA, which warns us it's written in Objective-C, and asks us if we want to analyze this (yes plz).

We have an interesting function `-[ViewController logMe:]`, which is decompiled like this with hex-rays:
```c
  this = self;
  location[1] = (id)a2;
  location[0] = 0LL;
  objc_storeStrong(location, a3);
  dico = (id)*((_QWORD *)this + 3);
  user_txt = objc_msgSend(*((id *)this + 1), "text"); // fetches user name
  usertxtbuf = objc_retainAutoreleasedReturnValue(user_txt);
  v4 = objc_msgSend(dico, "objectForKey:", usertxtbuf);
  v14 = objc_retainAutoreleasedReturnValue(v4);
  v5 = objc_msgSend(*((id *)this + 2), "text"); // fetches password
  v13 = objc_retainAutoreleasedReturnValue(v5);
  v12 = (unsigned __int8)objc_msgSend(v14, "isEqualToString:", v13);
  objc_release(v13);
  objc_release(v14);
  objc_release(usertxtbuf);
  if ( (v12 & 1) != 0 )
  {
    v6 = objc_msgSend(
           &OBJC_CLASS___UIAlertController,
           "alertControllerWithTitle:message:preferredStyle:",
           CFSTR("Good password"),
           CFSTR("\nYou found the good password ! But you didn't store anything here ¯\\_(ツ)_/¯"),
           1LL);
```

We can see that the contents of the user input is used as key in a dictionary, whose value is the password, which is then compared to the password input. Now, we have to find where this dictionary is constructed. There is a `-[ViewController viewDidLoad]` function that seems interesting:
```c
  // call the "viewDidLoad" method to the superclass
  v21.super_class = (Class)&OBJC_CLASS___ViewController;
  objc_msgSendSuper2(&v21, "viewDidLoad");
  // Call "GetRandomNumberBetween1and10" method with the string Sw4gGP4ssw0rd
  swag = objc_retain(CFSTR("Sw4gGP4ssw0rd"));
  md5swag = objc_msgSend(swag, "GetRandomNumberBetween1and10");
  md5 = objc_retainAutoreleasedReturnValue(md5swag);
  // Concatenate Sw4gGP4ssw0rd, - and the string computed before
  swag_tiret = objc_msgSend(swag, "stringByAppendingString:", CFSTR("-"));
  swgt = objc_retainAutoreleasedReturnValue(swag_tiret);
  v4 = objc_msgSend(swgt, "stringByAppendingString:", md5);
  v17 = objc_retainAutoreleasedReturnValue(v4);
  // Decode base64-encoded string
  v16 = objc_retain(CFSTR("eFhENHJLX0szdjFuWHg="));
  v5 = objc_alloc(&OBJC_CLASS___NSData);
  v15 = objc_msgSend(v5, "initWithBase64EncodedString:options:", v16, 0LL);
  v6 = objc_alloc(&OBJC_CLASS___NSString);
  location = objc_msgSend(v6, "initWithData:encoding:", v15, 4LL);
  v7 = objc_msgSend(&OBJC_CLASS___NSArray, "arrayWithObjects:", v17, 0LL);
  v13 = objc_retainAutoreleasedReturnValue(v7);
  v8 = objc_msgSend(&OBJC_CLASS___NSArray, "arrayWithObjects:", location, 0LL);
  v12 = objc_retainAutoreleasedReturnValue(v8);
  v9 = objc_msgSend(&OBJC_CLASS___NSDictionary, "dictionaryWithObjects:forKeys:", v13, v12);
  v10 = (NSDictionary *)objc_retainAutoreleasedReturnValue(v9);
  dico = v23->dico;
  v23->dico = v10;
  ```
  The GetRandomNumberBetween1and10 method just computes the MD5 sum of the string given to it:
  ```c
  data = (const char *)objc_msgSend(v2, "UTF8String");
  v3 = strlen(data);
  CC_MD5(data, v3, v19);
  // then code to format md5 hash to hex
  ```
  So, let's decode the base64 string, so we get the username: `xXD4rK_K3v1nXx`. And the password is `Sw4gGP4ssw0rd-d6e3698efe051ace727202e0d8bc56a1`, which gives us the flag: `Hero{xXD4rK_K3v1nXx:Sw4gGP4ssw0rd-d6e3698efe051ace727202e0d8bc56a1}`.

# RustInPeace (100 pts)
> Could you break my super encryption algorithm ?
> 
> Format : Hero{}
> 
> Author : SoEasY

This challenge, as the name says, is a Linux binary written in Rust. Unfortunately, the binary is stripped, making it a bit harder to reverse, because we'll have to reverse rust standard library along with useful code.

Let's have a look in the main function:
```
push    rax
movsxd  rax, edi
lea     rdi, rust_main
mov     [rsp+8+var_8], rsi
mov     rsi, rax
mov     rdx, [rsp+8+var_8]
call    rust_init
pop     rcx
retn
```
It just calls Rust's runtime init function with the real rust main function as argument (which will be called by the runtime).

The disassembly of this function is quite scary (thanks Rust compiler which generate ugly code, even worse than C++), and I executed the program inside IDA's debugger to have a global overview.

Then, I used my best friend hex-rays which generated unreadable pseudo-C code, because analysis engine had trouble identifying the correct number of arguments used in functions. During debugging sessions, I figured out that the code used a lot of Rust strings (which can be seen as a C struct with a pointer to the buffer and a length), and a "slice" which represents a subset of the string (and contains a pointer to the buffer, a pointer to the start of the slice in the bufer and a pointer to the end).

So, after defining those structs in IDA and identifying functions and redefining prototypes, I was able to get a nice pseudocode.

The crackme first expects two arguments: a number (which must be "60"), and a path to the file which contains the flag:
```c
      argv_elt2 = (void *)get_list_elt((__int64)argv_list, 2LL);
      arg2_ptr = getbuf(argv_elt2);
      CreateFile(wrap_fileobj, arg2_ptr);
      file_unwrap(file_obj, wrap_fileobj);
      v1 = getbuf(file_obj);
      strend = adder_lol(v1.s_ptr, v1.len);
      s_endptr = strend.s_ptr;
      s_endbuf = strend.len;
      v3 = getbuf(file_obj);
      v4 = adder_lol(v3.s_ptr, v3.len);
      strlen_utf8(v4.s_ptr, v4.len);
      correctinput = 1;
      first_arg = get_list_elt((__int64)argv_list, 1LL);
      if ( (string_compare(&first_arg, &str_60) & 1) != 0 )
      {
        correctinput = 0;
      }
```
Then the crackme does slice stuff with the string, check if the file content begins with "FLAG=" string, and then does this:
```c
                  if ( pos2 >= 47 )
                    ZN4core9panicking18panic_bounds_check17h4b3d0dcda831e378E();
                  if ( __CFADD__(xorkey, pos2) )
                    core::panicking::panic();
                  if ( encryptedflag[pos2] != ((xorkey + pos2) ^ chr2) )
                    correctinput = 0;
                  break;
```
The input flag is xored with `xorkey + pos` where "pos" is the i-th char of the user input being read.
So, we can recover the flag:
```python
flag = [163, 221, 65, 246, 49, 9, 39, 49, 43, 62, 2, 118, 44, 22, 51, 123, 57, 18, 37, 33, 96, 38, 13, 103, 54, 101, 35, 35, 7, 11, 47, 110, 40, 2, 44, 108, 22, 82, 16, 16, 85, 11, 1, 88, 87, 20, 96]
print(bytes([x ^ (0x3c + i) for i,x in enumerate(flag)][5:]))
```
which gives `Hero{D1d_y0u_kn0w_4b0ut_Ru5t_r3v3rs1ng??}`

# ARMada (100 pts)
> You are commissioned to test a new military-grade encryption, but apparently the developers haven't invented much...
> 
> nc chall0.heroctf.fr 3000
> 
> Format : Hero{}
> 
> Author : SoEasY


This time, the binary is a 32-bit ARM C++ program (I couldn't use hex-rays because I don't have 32-bit decompilers yay, and Ghidra's decompiler gave shitty useless code), so let's dig in the assembly.

The binary starts by asking the user an input and computes its length:
```
MOV     R0, #0x40 ; '@' ; unsigned int
BL      _Znaj           ; operator new[](uint)
MOV     R3, R0
STR     R3, [R11,#user_input]
LDR     R1, =aEntrezUnInput ; "Entrez un input : "
LDR     R0, =_ZSt4cout__GLIBCXX_3.4
BL      _ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc ; std::operator<<<std::char_traits<char>>(std::ostream &,char const*)
MOV     R3, #0xA        ; delimiter
MOV     R2, #0x41 ; 'A' ; buf_len
LDR     R1, [R11,#user_input] ; buffer
LDR     R0, =0x23148    ; this
BL      _ZNSi7getlineEPcic ; std::istream::getline(char *,int,char)
```
Then it allocates a vector from the user buffer, and another copy that will be given to a "yolo" function, along with a string that will contain encrypted input:
```
SUB     R3, R11, #-encbuf
SUB     R2, R11, #-input_copy
MOV     R1, R2          ; input
MOV     R0, R3          ; encrypted
;   try {
BL      _Z4yoloB5cxx11St6vectorIhSaIhEE ; yolo(std::vector<uchar>)
```

The "yolo" function seems to be a bit scary at first, because of those
```
LDR     R3, =0xAAAAAAAB
UMULL   R2, R3, R3, R1
MOV     R2, R3,LSR#1
```
which are just a division by 3, optimized by the compiler. So, this function just read the string by 3 chars, and for each block, does something like this:
```c
unsigned long block = (*buf++) << 16 + (*buf++) << 8 + (*buf++);
out.append(encodeLookup[((block >> 18) & 0x3f)] ^ 0x42);
out.append(encodeLookup[((block >> 12) & 0x3f)] ^ 0x42);
out.append(encodeLookup[((block >> 6) & 0x3f)] ^ 0x42);
out.append(encodeLookup[((block) & 0x3f)] ^ 0x42);
```
Some people may have recognized that *really* looks like base64 encoding algorithm. And actually, if we xor the "encodeLookup" array with 0x42 we get this:
`CTwGhcJj+nKSqARsQ27omX0Iley91ufDbPxVY4ar5UgMNt/L3BvzkFiHZW6dOp8E`, which really looks like a custom base64 ;)

Now, let's have a look to the server given in the challenge `nc chall0.heroctf.fr 3000`:
```
=================== ARMada (by SoEasY) ===================

New cipher : XipH+jukexCE
--> Your answer : 
```
it looks like we'll have to "decrypt" this string, and sending back the cleartext. Let's reimplement the algorithm and automate answers with pwntools:

```python
import pwn

look = bytes.fromhex("011635052A210828692C0911330310311370752D2F1A720B2E273B7B7337240620123A141B7623307717250F0C366D0E7100343829042B0A181574260D327A07")
look = bytes([x ^ 0x42 for x in look])

def dec(lol):
    buf = b""
    for i in range(0, len(lol) // 4):
        bloc = lol[4*i:4*i+4]
        i0 = look.find(bloc[0])
        i1 = look.find(bloc[1])
        i2 = look.find(bloc[2])
        i3 = look.find(bloc[3])
        if i3 != -1:
            tmp = (i3) | (i2 << 6) | (i1 << 12) | (i0 << 18)
            buf += bytes([(tmp >> 16), (tmp >> 8) & 0xff, (tmp) & 0xff])
            continue
        if i2 != -1:
            tmp = (i2 << 6) | (i1 << 12) | (i0 << 18)
            tmp >>= 8
            buf += bytes([(tmp >> 8) & 0xff, (tmp) & 0xff])
            continue
        if i1 != -1:
            tmp = i1 | (i0 << 6)
            buf += bytes([tmp >> 4])
    return buf
    


blop = {}
for i in look:
    if chr(i) not in blop:
        blop[chr(i)] = 0
    blop[chr(i)] += 1

remote = pwn.remote("chall0.heroctf.fr", 3000)
i = 0
for i in range(40):
    remote.recvuntil("New cipher : ")
    deco = remote.recvline()
    bop = dec(deco).rstrip()
    remote.recvuntil(" answer : ")
    remote.sendline(bop)
print(remote.recvall())
```
We finally get the flag after a short time: `Hero{0h_w0W_s0_y0u_not1c3d_1t_w4s_cust0m_b64_?}`

# fatBin (125 pts)
> You'll never find my flag.
> 
> Format : Hero{}
> 
> Author : SoEasY

So, challenge accepted ;). It's (again) a Mach-O binary, more precisely, according to "file" command: `fatBoy: Mach-O universal binary with 2 architectures: [x86_64:Mach-O 64-bit x86_64 executable, flags:<NOUNDEFS|DYLDLINK|TWOLEVEL|PIE>] [arm64:Mach-O 64-bit arm64 executable, flags:<NOUNDEFS|DYLDLINK|TWOLEVEL|PIE>]`.

As usual we open it on IDA, which asks us which binary we want to analyze. Because Intel assembly is cool, I choosed the x86_64 bin to reverse. The algorithm is pretty straightforward (thanks Hex-Rays again):
```c
  // key initialization
  key[0] = ~KEY[0];
  key[1] = KEY[1] ^ 0xAB;
  key[2] = KEY[2] ^ 0xE5;
  key[3] = KEY[3] ^ 0x8A;
  key[4] = KEY[4] ^ 0x5C;
  key[5] = KEY[5] ^ 0x44;
  key[6] = KEY[6] ^ 0x20;
  key[7] = KEY[7] ^ 0x47;
  key[8] = 0;
  inputlen = strlen(a1);
  v15 = strlen(key);
  v12 = v5;
  v9 = inputlen;
  // snipped useless code
  i = 0;
  v13 = 0;
  __s1 = (char *)v5;
  while ( i < (int)inputlen )
  {
    if ( v13 == v15 )
      v13 = 0;
    v8[i++] = key[v13++];
  }
  v8[i] = 0;
  for ( i = 0; i < (int)inputlen; ++i )
    __s1[i] = (v8[i] + __s[i]) % 26 + 'B';
  v3 = __s1;
  __s1[i] = 0;
  v5[5] = puts(v3);
```
It seems to be some kind of Caesar/Vigenere cipher, but weirdly implemented, so we'll need extra care to decrypt it, which gives us as script:
```python
def dec(key, txt):
  res = []
  for i in range(len(txt)):
      byte = txt[i] - 0x42
      k = key[i % len(key)] % 26
      if byte < k:
          res.append(byte + 26 - k)
      else:
          res.append(byte - k)
  return res

k1 = b"BESTRONG"

buf = []
for c in dec(k1, b"KRLIJGMIWYMB[HWZPTMNZTTSCL"):
    tmp = 3*26 + c
    if tmp > ord("Z"):
        tmp = tmp - 26
    buf.append(tmp)
print(bytes(buf))
```
Unfortunately, this gives us: `IMSORRYBUTTHISISNOTTHEFLAG`, which isn't our flag oubviously. But remember, we have an ARM64 binary to reverse inside our "fat" binary. Let's open it on IDA. Luckily for us, it's the same algorithm, but the key and ciphertext changed. The key decodes as `FATMACHO` this time, and when running the script this those arguments:
```python
k1 = b"FATMACHO"

buf = []
for c in dec(k1, b"CUZVTWPXYGOPLLVVLJFRGRZBGU"):
    tmp = 3*26 + c
    if tmp > ord("Z"):
        tmp = tmp - 26
    buf.append(tmp)
print(bytes(buf))
```
We get `WTFISTHISFUCKINGFILEFORMAT`, and the flag is `Hero{WTFISTHISFUCKINGFILEFORMAT}`

# WTF (350 pts)
> Find the flag in this android application.
> 
> Format : Hero{}
> 
> Author : SoEasY

This time, the challenge author is lying to us and the "android" application is again a Mach-O binary (he's probably an OSX lover).

The function starts by filling a 81-byte buffer with spaces, and then puts some numbers between 0 and 9 at "random" places in this buffer.
Then the function looks likes this:
```c
 v3 = *user_input
 while ( 1 )
  {
    input0 = v3 - '1';
    input1 = user_input[1] - '1';
    input2 = user_input[2];
    if ( checkfunc(v11, input0, user_input[1] - '1', input2) )
      v11[9 * input0 + input1] = input2;
    user_input += 3;
    v7 = 0;
    for ( i = 8LL; i != 89; i += 9LL )
      v7 += (v10[i] != 32)
          + (v10[i + 1] != 32)
          + (v10[i + 2] != 32)
          + (v10[i + 3] != 32)
          + (v10[i + 4] != 32)
          + (v10[i + 5] != 32)
          + (v10[i + 6] != 32)
          + (v10[i + 7] != 32)
          + (v11[i] != 32);
    if ( v7 == 81 )
      break;
    v3 = *user_input;
    if ( !*user_input )
    {
      puts("Nope.");
      return 1LL;
    }
  }
```
The checkfunc is quite ugly so I won't paste it here, but we can deduce that the 81-byte buffer is actually a 9x9 grid, and "input0" and "input1" are (x,y) coordinates in this grid, while "input2" is the number to place in the grid. Also the functions ends if we reached the end of user input, or if there are no "space" chars left in the grid.

Those things made me to think this check function was just checking if the grid was still a valid Sudoku grid after trying to add the number. So, I wrote a little program that printed the buffer into a 9*9 grid:
```python
v11  = "   546  9 2      7  39    49 5    7 7      2     93    56  8    1  39         8 6"
for i in range(9):
  print("|".join([x for x in v11[9*i:9*(i+1)]]))
```
which gave me:
```
 | | |5|4|6| | |9
 |2| | | | | | |7
 | |3|9| | | | |4
9| |5| | | | |7| 
7| | | | | | |2| 
 | | | |9|3| | | 
 |5|6| | |8| | | 
 |1| | |3|9| | | 
 | | | | | |8| |6
```
 So I copied this grid into an online Sudoku solver which solved it, and copied back the completed Sudoku grid line by line, which gave the flag:
`Hero{178546239429381567563927184935214678741865923682793415256478391814639752397152846}`