import z3
z = z3.BitVec("lol", 288)

s = z3.Solver()
s.append(z ^ (z >> 3) == 0x4a3ad948eb3eceb425b74609f480951c3d5503a3a9f4bef9d713dae9dc14d71e1e155192)
while(s.check() == z3.sat):
    m = s.model()
    m = m[z]
    print(hex(int(str(m))))
    s.append(z != m)