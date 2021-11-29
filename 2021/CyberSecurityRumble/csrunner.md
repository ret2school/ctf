> Collect green stuff, avoid red guys. Easy as pie, right? Not even your speedhacks will help you here! You might have to take a closer look and inspect it carefully. Have fun & good luck!

This challenge is a game, according to its description. Since I gave up on the challenge I was trying to do (NOdeBANKing), I went to help other teammates blocked on this challenge.

This game was using Unity3D as engine, where game logic is usually written in C# or other language that compiles to MSIL. So let's find the GameAssembly.dll, but no luck it's a native DLL and not a managed one... After opening it in IDA Free, I noticed "il2cpp_" references, and after some googling, figured out it was a tool that compile MSIL code to native x86 code.

I first thought that the game "logic" could actually be embedded in resources (the "data.unity3d" file in CSRunner_Data), but I failed to find a tool able to open the new UnityFS format, all I got was weird lz4 invalid stream issues coming from nowhere.

So, I looked for a tool able to reconstruct metadata of the "original" assembly, and finally came across [Il2CppDumper](https://github.com/Perfare/Il2CppDumper), which even comes with an IDAPython script to rename funcs and add types in IDA Pro. I used that tool to generate "dummy" assemblies that could be opened in dnSpy, even if there was no MSIL code in the assemblies, but it's a good starting point to understand the class structure.

And the tool also comes with IDAPython scripts to rename il2cpp-converted functions, which I could use since I managed to compile IDAPython and make it run on my IDA Free 7.6. I first explored Game methods, which only seemed to print debug messages stuff even if `PickupHit` and `PickupMiss` methods looked promising.

But there was another class with interesting name, `DieOnCollision`, which seemed to handle collisions, I looked at the `DieOnCollision$$OnCollisionEnter` and saw this:

```cpp
    tag = UnityEngine_GameObject__get_tag(gameObject, 0i64);
    if ( System_String__op_Equality(tag, StringLiteral_4306, 0i64) )
    {
        if ( !byte_180A0BB4F )
        {
        sub_1801292D0(5488i64);
        byte_180A0BB4F = 1;
        }
        instance = Game_TypeInfo->static_fields->instance;
        if ( instance )
        {
        v9 = DieOnCollision_TypeInfo;
        if ( (DieOnCollision_TypeInfo->_2.bitflags2 & 2) != 0 && !DieOnCollision_TypeInfo->_2.cctor_finished )
        {
            il2cpp_runtime_class_init(DieOnCollision_TypeInfo, v7);
            v9 = DieOnCollision_TypeInfo;
        }
        PHRASES_ENEMY = v9->static_fields->PHRASES_ENEMY;
        if ( PHRASES_ENEMY )
        {
            v11 = UnityEngine_Random__RandomRangeInt(0, PHRASES_ENEMY->max_length, 0i64);
            v12 = v11;
            if ( (unsigned int)v11 >= LODWORD(PHRASES_ENEMY->max_length) )
            {
            v32 = sub_180129250();
            sub_1801293E0(v32, 0i64);
            }
    LABEL_15:
            Game__GameOver(instance, PHRASES_ENEMY->m_Items[v12], 0i64);
            return;
        }
        goto LABEL_50;
        }
    }
```

So I just had to force the `if ( System_String__op_Equality(tag, StringLiteral_4306, 0i64) )` condition to be always false (patching the `jz      loc_1806E612D` at `0x1806e6078` to a jmp), and colliding with enemies would do nothing.

Then I gave the modified assembly to our team's pro gamer (since I run Linux, and couldn't manage to get the tool mentioned before on `GameAssembly.so` of the Linux version), which was able to get the flag in two game tries.

Author: [supersnail](https://github.com/aaSSfxxx)
