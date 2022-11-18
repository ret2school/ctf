import angr, claripy, IPython

pr = angr.Project("./chall.baby")

sym_flag = claripy.BVS("sym_flag", 8*64)
state = pr.factory.full_init_state(args=["./chall.baby", sym_flag])
simgr = pr.factory.simgr(state)

simgr.explore()
print(simgr)
IPython.embed()
# SECCON{y0u_f0und_7h3_baby_flag_YaY}
