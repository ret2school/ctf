from IPython import embed
import angr

p = angr.Project("./chall")
state = p.factory.full_init_state()
simgr = p.factory.simgr(state)

MAIN = 0x459BF4
WALK_START = 0x40625B
WALK_END = 0x459BE5
GET_INPUT = 0x401229
OSEF = [0x401120, WALK_END, 0x401100, 0x526fc0, 0, GET_INPUT, 0x4010d0]

functions = open("./functions.txt", "r").read()
functions = functions.split("\n")[:-1]
functions = [MAIN, WALK_START] + [p.loader.find_symbol(name).relative_addr + 0x400000 for name in functions]

main_passed = False

def avoid(s):
    global main_passed
    global simgr
    if s.callstack.func_addr == MAIN:
        main_passed = True

    if main_passed:
        call_stack = []
        for f in s.callstack:
            if f.func_addr not in OSEF:
                call_stack += [f.func_addr]
        call_stack.reverse()

        if not call_stack:
            return False

        return functions[:len(call_stack)] != call_stack


    else:
        return False

try:
    simgr.explore(avoid=avoid, find=[0x459C56, 0x59BE5])
except KeyboardInterrupt:
    pass

print(simgr)
embed()
