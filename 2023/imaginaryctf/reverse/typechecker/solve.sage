import sage.all
import galois

s1 = 'eZ!gjyTdSLcJ3{!Y_pTcMqW7qu{cMoyb04JXFHUaXx{8gTCIwIGE-AAWb1_wu32{'
s2 = 'HuuMKaxLVHVqC6NSB1Rwl2WC1F7zkxxrxAuZFpPogbBd4LGGgBfK9!eUaaSIuqJK'
chars = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ{_-!}'

def read_matrix(s):
    m = [[0 for i in range(8)] for j in range(8)]
    for i in range(8):
        for j in range(8):
            m[i][j] = chars.index(s[8*i+j])
    return m

m1 = read_matrix(s1)
m2 = read_matrix(s2)

m_eq = [[0 for i in range(64)] for j in range(70)]

for i in range(8):
    for j in range(8):
        for k in range(8):
            for l in range(8):
                if k == i:
                    if l == j:
                        m_eq[8*i+j][8*k+l] = m1[i][i] - m2[j][j]
                    else:
                        m_eq[8*i+j][8*k+l] = -m2[l][j]
                else:
                    if l == j:
                        m_eq[8*i+j][8*k+l] = m1[i][k]
                    else:
                        m_eq[8*i+j][8*k+l] = 0                   


# We want m_eq * (unknown vector) = (null vector)
# We set the values of the known chars (ictf{...}) with extra trivial equations
# at the end to avoid extra possible solutions
                        
m_eq[64][0] = 1
m_eq[65][1] = 1
m_eq[66][2] = 1
m_eq[67][3] = 1
m_eq[68][4] = 1
m_eq[69][61] = 1                  

M_eq = matrix(GF(67),m_eq)
Zero = matrix(GF(67),[0 for i in range(64)]+[18,12,29,15,62,66]).transpose()

X = M_eq.solve_right(Zero)

flag = ""

for i in range(62):
    flag += chars[X[i][0]]

print(flag)
