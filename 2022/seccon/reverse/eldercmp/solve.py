from triton import *
import os, sys
from IPython import embed

PRE_DEBUG = False
POST_DEBUG = False

CRITICAL_JMP = 0x555555555dee

sym_flag = []

def toggle_pre_debug():
    global PRE_DEBUG
    PRE_DEBUG ^= True

def toggle_post_debug():
    global POST_DEBUG
    POST_DEBUG ^= True

# Dumped using https://github.com/JonathanSalwan/Triton/blob/434b2cbb6349d3cda1ba901e4e414dea76387833/src/examples/python/ctf-writeups/defcon-2016-baby-re/gdb-peda-fulldump.patch
def load_dump(ctx, path):
    global memoryCache

    # Open the dump
    fd = open(path)
    data = eval(fd.read())
    fd.close()

    # Extract registers and memory
    regs = data[0]
    mems = data[1]

    # Load registers and memory into the libctx
    print('[+] Define registers')
    for k, v in regs.items():
        print(f"[+] Setting {k} to {v:#x}")
        ctx.setConcreteRegisterValue(ctx.registers.__dict__[k], v)

    print('[+] Define memory areas')
    for seg in mems:
        if None in seg.values():
            continue
        ctx.setConcreteMemoryAreaValue(seg['start'], seg['memory'])
    return

def emulate(ctx, pc):
    global PRE_DEBUG
    global POST_DEBUG

    C = ctx.getAstContext()

    print(f"[+] Starting emulation at {pc:#x}")
    while pc:
        opcode = ctx.getConcreteMemoryAreaValue(pc, 16)

        instruction = Instruction()
        instruction.setOpcode(opcode)
        instruction.setAddress(pc)

        if PRE_DEBUG and input(): embed()

        try: ctx.processing(instruction)
        except KeyboardInterrupt:
            embed()
            ctx.processing(Instruction)
        print(instruction)

        if POST_DEBUG and input(): embed()

        pc = ctx.getConcreteRegisterValue(ctx.registers.rip)
        #if 0x5555555557e4 == pc:
        #embed()
        if CRITICAL_JMP == pc:
            model = ctx.getModel(C.land([ C.lnot(ctx.getPathPredicate()),
                                          sym_flag[0] == ord('S'),
                                          sym_flag[1] == ord('E'),
                                          sym_flag[2] == ord('C'),
                                          sym_flag[3] == ord('C'),
                                          sym_flag[4] == ord('O'),
                                          sym_flag[5] == ord('N'),
                                          sym_flag[6] == ord('{') ]))
            print(model)
            if {} != model:
                embed()
            else:
                pc = 0
        elif 0x555555555100 == pc:
            print('/!\\ Inside puts')
            embed()
            pc = 0
        elif 0x555555555170 == pc:
            print('/!\\ Inside exit')
            embed()
            pc = 0

    print('[+] Emulation done.')

def initialize():
    global sym_flag
    ctx = TritonContext()

    # Define the target architecture
    ctx.setArchitecture(ARCH.X86_64)

    # Define symbolic optimizations
    ctx.setMode(MODE.ALIGNED_MEMORY, True)
    ctx.setMode(MODE.ONLY_ON_SYMBOLIZED, True)
    ctx.setMode(MODE.CONSTANT_FOLDING, True)
    ctx.setMode(MODE.AST_OPTIMIZATIONS, True)

    # Load the meory dump
    load_dump(ctx, os.path.join(os.path.dirname(__file__), "fulldump.dump"))

    user_input = ctx.getConcreteMemoryValue(MemoryAccess(ctx.getConcreteRegisterValue(ctx.registers.rdi), 8))
    print(f"[+] Symbolizing at {user_input:#x}")
    for i in range(len('SECCON{y0u_f0und_7h3_baby_flag_YaY}')):
        ctx.symbolizeMemory(MemoryAccess(user_input+i, 1), f"sym_flag{i:x}")
        sym_flag += [ctx.getSymbolicMemory(user_input+i).getAst()]

    return ctx

if __name__ == '__main__':
    # Initialize symbolic emulation
    ctx = initialize()
    emulate(ctx, ctx.getConcreteRegisterValue(ctx.registers.rip))
