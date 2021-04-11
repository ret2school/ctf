We used the proximity browser in IDA with the "Add node -> Find path" mini-trick to get the path between the `main` and `walk_end` function.
Once all the function names in the path where dumped, in the same order as in IDA, inside `functions.txt`, we just have to tell angr to discard, avoid, every state wherein the callstack is different from the path linking `main` and `walk_end`.

```py
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

# Construct the desired callstack from the symbols/function names in functions.txt
functions = open("./functions.txt", "r").read()
functions = functions.split("\n")[:-1]
functions = [MAIN, WALK_START] + [p.loader.find_symbol(name).relative_addr + 0x400000 for name in functions]

# Wether the main function has be executed or not
main_passed = False

def avoid(s):
    global main_passed
    if s.callstack.func_addr == MAIN:
        main_passed = True

    if main_passed:
        # Constructs the current callstack
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
    # Find the success message or the walk_end func
    simgr.explore(avoid=avoid, find=[0x459C56, 0x59BE5])
except KeyboardInterrupt:
    pass

print(simgr)
embed()
```


`OSEF` holds the function addresses inside the callstack that we ignore like all imported functions. The `0x526fc0` and the `0` are default addresses that angr pushed onto the callstack at the beginning of the execution, so we just ignore them.

When the script is done, you get a IPython shell.
Do a nice `simgr.found[0].posix.dumps(0)` to get the right input and upload it to the server
We obtained, spaces stripped, `aBIksNPZlfMnluFMRqtNOAkdWfuMuTIICGGWvhbWYwMlbdlCGznVNVzAsHjynOjHuuuvMkOmLMhYVeEWKjGLhmhLxyvtvxpzGCWuibxDhGzEmAfkepZDINxdHTQkKrirkJNnmyVRweEjBoEAwgTVEEkEVdRjzAFcxZrdSYbPQstuILsIjOSWgLLLXvkCAQVyYqJxa`.

`printf thesuperlongrightinput | nc labyrevnt-01.play.midnightsunctf.se 29285`

I don't remember the flag that you obtain from the server, sorry p:
