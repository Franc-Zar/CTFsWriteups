# Unbreakable

The challenge provides the following GitHub repo url: https://github.com/Lukerd-29-00/unbreakable

This repo contains two files:

`enc.py`

```python
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import os
key = os.urandom(16)

with open("flag.txt","r") as f:
    flag = f.read().strip().encode()

iv = os.urandom(AES.block_size)

ct = AES.new(key,AES.MODE_CBC,iv).encrypt(pad(flag,AES.block_size))

with open("flag.enc","wb") as f:
    f.write(iv + ct)
```

and `flag.enc`

The above code does not present any vulnerability and so it is not possible to obtain the flag from it.

However, in the repo commit history there is an interesting message:

    removed password from repo

by checking the previous file state is possible to see that the password used to encrypt was hardcoded in the first version of the file:

```python
key = hashlib.sha256(b"tasciewapeoiu").digest()
```

At this point we just need to normally decrypt `flag.enc` and obtain the flag:

```python
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

key = hashlib.sha256(b"tasciewapeoiu").digest()

with open("./flag.enc","rb") as f:
    iv = f.read(AES.block_size)
    enc_flag = f.read()

aes_eng = AES.new(key,AES.MODE_CBC,iv)
flag = unpad(aes_eng.decrypt(enc_flag), AES.block_size).decode()

print(flag)
```

    UDCTF{N0th1ng_pr0t3cts_4gainst_5l0ppiness}
