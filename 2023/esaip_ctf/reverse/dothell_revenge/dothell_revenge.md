+++
title: "[ESAIP CTF 2023 - reverse] Dothell Revenge"
date: 2023-05-27
tags: ["ctf", "Alol", "reverse", "dotnet", "Z3", "ESAIP CTF", "2023"]
+++

# Dothell Revenge

> Solves : 3
>
> They downed the CTF infra as soon as it ended so I didn't have the time to save the challenge prompt :\(
>
> Author: Oogle

Dothell Revenge was a hard reverse-engineering challenge from ESAIP CTF 2023. It was a modified version of Dothell, a challenge from the 2022 edition that had 0 solves. I didn't participate IRL last year, but I did this year, and even beat two of the best reversers I know to the first blood.

## TL;DR

- Unpack ConfuserEx
- Write a keygen with Z3

## Unpacking ConfuserEx

Looking at the decompiled code in dnSpy indicates the binary is packed.

![](https://raw.githubusercontent.com/ret2school/ctf/master/2023/esaip_ctf/reverse/dothell_revenge/regretting_my_life_choices_rn.png)

Thankfully, when scrolling to the bottom of the `Main` function, we see that the program tries to load the `koi` module.

```c#
Assembly executingAssembly = Assembly.GetExecutingAssembly();
Module manifestModule = executingAssembly.ManifestModule;
GCHandle gchandle = <Module>.Decrypt(array, 2751949377U);    // decrypt module
byte[] array2 = (byte[])gchandle.Target;
Module module = executingAssembly.LoadModule("koi", array2); // load module, /!\ "koi" -> ConfuserEx
Array.Clear(array2, 0, array2.Length);
gchandle.Free();
Array.Clear(array, 0, array.Length);
<Module>.key = manifestModule.ResolveSignature(285212673);   // Resolve metadataToken of the entrypoint
AppDomain.CurrentDomain.AssemblyResolve += <Module>.Resolve;
module.GetTypes();
MethodBase methodBase = module.ResolveMethod((int)<Module>.key[0] | ((int)<Module>.key[1] << 8) | ((int)<Module>.key[2] << 16) | ((int)<Module>.key[3] << 24)); // Resolve entrypoint
object[] array3 = new object[methodBase.GetParameters().Length];
if (array3.Length != 0)
{
    array3[0] = args;
}
object obj = methodBase.Invoke(null, array3);                // Invoke entrypoint
if (obj is int)
{
    return (int)obj;
}
return 0;
```

This tells us with high certainty that the PE was packed using [ConfuserEx](https://github.dev/yck1509/ConfuserEx) (an open-source but discontinued .NET protector). To unpack it we can use a [pre-existing unpacker](https://github.com/XenocodeRCE/ConfuserEx-Unpacker).

## Writing a keygen with Z3

Now that we've unpacked the PE, let's analyze the source code and write a keygen. The program isn't obfuscated and there's only a single anti-debug function (`nantendoShadowBan`) that makes the program exit if `dnSpy` or `ILSpy` are present in the process list. Other than that, the program isn't very complicated, it creates a form containing an input box and a button (the button runs the `checker_Click` function). The source code of the form is available [here](https://raw.githubusercontent.com/ret2school/ctf/master/2023/esaip_ctf/reverse/dothell_revenge/Form1.cs).

To write the keygen we'll use Z3Py, an API around Z3 a SMT solver/theorem prover by Microsoft. A keygen using Z3 can be written by "translating" the `C#` to `Python` and modifying the syntax a bit. Below is the commented solve script (also available [here](https://raw.githubusercontent.com/ret2school/ctf/master/2023/esaip_ctf/reverse/dothell_revenge/solve.py)).

```py
from base64 import b64decode
from string import printable
import z3

# Before adding constraints we need to find the number of variables to use (ie. the length of the flag)
# Thankfully it's not too hard to find ... 🥲

# This single assumption cost me 3h, most of my sanity and half of my brain cells. Why?
# Because '/' isn't a true division, it's a *floor division*
# Meaning that the condition is true for 35 but also 36, 37, 38 and 39

"""
if (length / 5 + 1 != 8)
{
    MessageBox.Show("Not for you!");
    return;
}
"""
length = 39

flag = [z3.BitVec(f"{i:02}", 8) for i in range(length)]
s = z3.Solver()

for i in range(length):
    s.add(ord(min(printable)) <= flag[i])
    s.add(flag[i] <= ord(max(printable)))

"""
int num = 1;
int length = this.supplier.Text.Length;
int num2 = -1;
while (num == 1)
{
    if (num2 + 5 > length - 1)
    {
        num = 0;
    }
    else
    {
        num2 += 5;
        if (!this.supplier.Text[num2].Equals(Encoding.UTF8.GetString(Convert.FromBase64String("LQ=="))[0]))
        {
            MessageBox.Show("Not for you!");
            return;
        }
    }
}
"""

num = 1
num2 = -1

while (num == 1):
    if (num2 + 5 > length - 1):
        num = 0;
    else:
        num2 += 5;
        s.add(flag[num2] == ord(b64decode("LQ==").decode()))

"""
int num3 = 1;
int num4 = 0;
int num5 = 0;
if (num4 > length - 1)
{
    MessageBox.Show("Not for you!");
    return;
}
while (num3 == 1)
{
    if (!this.supplier.Text[num4].Equals(Convert.ToChar((int)(Encoding.UTF8.GetString(Convert.FromBase64String(this.ichi.Text))[num5] - '\u0014'))))
    {
        MessageBox.Show("Not for you!");
        return;
    }
    if (num4 + 5 > length - 1)
    {
        num3 = 0;
    }
    else
    {
        num4 += 5;
        num5++;
    }
}
"""

# this.ichi is a component of the Form just used to store text
ichi = "ZWpkaGtpYWIK";
num3 = 1
num4 = 0
num5 = 0

while (num3 == 1):
    s.add(flag[num4] == ord(b64decode(ichi).decode()[num5]) - 0x14 )
    if (num4 + 5 > length - 1):
        num3 = 0;
    else:
        num4 += 5;
        num5 +=1;

"""
int num6 = 1;
num4 = length - 1;
num5 = 0;
if (num4 > length - 1)
{
    MessageBox.Show("Not for you!");
    return;
}
while (num6 == 1)
{
    if (!Convert.ToChar((int)(this.supplier.Text[num4] % '\u007f')).Equals(Convert.ToChar((int)(Encoding.UTF8.GetString(Convert.FromBase64String(this.ni.Text))[num5] - '\u0018'))))
    {
        MessageBox.Show("Not for you!");
        return;
    }
    if (num4 - 5 < 0)
    {
        num6 = 0;
    }
    else
    {
        num4 -= 5;
        num5++;
    }
}
"""

# same as this.ichi, component of the Form just used to store text
ni   = "cnRwdnh1encK"
num6 = 1;
num4 = length - 1;
num5 = 0;

while (num6 == 1):
    s.add(flag[num4] % 0x7f == ord(b64decode(ni).decode()[num5]) - 0x18)

    if (num4 - 5 < 0):
        num6 = 0;
    else:
        num4 -= 5;
        num5 +=1;

"""
int num7 = 1;
num4 = 1;
num5 = 0;
if (num4 > length - 1)
{
    MessageBox.Show("Not for you!");
    return;
}
while (num7 == 1)
{
    if (!this.supplier.Text[num4].Equals(Form.ActiveForm.Text[num5 * 2]))
    {
        MessageBox.Show("Not for you!");
        return;
    }
    if (!this.supplier.Text[num4 + 1].Equals(Form.ActiveForm.Text[num5 * 2 + 1]))
    {
        MessageBox.Show("Not for you!");
        return;
    }
    if (num4 + 5 > length - 1)
    {
        num7 = 0;
    }
    else
    {
        num4 += 5;
        num5++;
    }
}
"""

# name of active form
ActiveForm = "Mario star grabber";
num7 = 1;
num4 = 1;
num5 = 0;

while (num7 == 1):
    s.add(flag[num4]   == ord(ActiveForm[num5*2]))
    s.add(flag[num4+1] == ord(ActiveForm[num5*2 + 1]))

    if (num4 + 5 > length - 1):
        num7 = 0;
    else:
        num4 += 5;
        num5 +=1;

# in case there are multiple valid keys (shouldn't be the case, but you never know)
def all_smt(s, initial_terms):
    # https://github.com/Z3Prover/z3/issues/5765#issuecomment-1009760596
    def block_term(s, m, t):
        s.add(t != m.eval(t, model_completion=True))
    def fix_term(s, m, t):
        s.add(t == m.eval(t, model_completion=True))
    def all_smt_rec(terms):
        if z3.sat == s.check():
           m = s.model()
           yield m
           for i in range(len(terms)):
               s.push()
               block_term(s, m, terms[i])
               for j in range(i):
                   fix_term(s, m, terms[j])
               yield from all_smt_rec(terms[i:])
               s.pop()   
    yield from all_smt_rec(list(initial_terms))

if z3.sat == s.check():
    for m in all_smt(s, flag):
        print(''.join([chr(m[i].as_long()) for i in sorted(m, key=str)]))
else:
    print("Oh no")

# QMa_-Vrib-Po ]-Tst`-War^-U gX-Mra\-NbbZ
```
