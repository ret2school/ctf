def do_pass(s):
    ret = []
    for b in s:
        if b == 33:
            b = 127
        ret.append(b-1)
    print(ret)
    return bytes(ret)

flag = b"]1nH^oa86K2z0kL+z*NzmLQ%Rz/Kp+_zSOSt:"
for i in range(0, 0x1b):
    flag = do_pass(flag)
print(flag)