# ECB++

## Source Code Analysis

The service enables to arbitrarily encode messages prepended to the flag.
Each round a different key is used to encrypt the provided message.

```python
#!/usr/local/bin/python3
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import random

f = open('./flag.txt','r')
flag = f.read()

def encrypt(message):
    global flag
    message = message.encode()
    message += flag.encode()
    key = random.getrandbits(256)
    key = key.to_bytes(32,'little')
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(pad(message, AES.block_size))
    return(ciphertext.hex())

print("Welcome to my secure encryption machine!")
print("I'll encrypt all your messages (and add a little surprise at the end)")

while(True):
    print("Do you have a message to encrypt? [Y|N]")
    response = input()
    if(response == 'Y'):
        print("Gimme your message:")
        message = input()
        print("Your message is: ",encrypt(message))
    else:
        exit(0)
```

## Exploit

The server implements an [ECB oracle](https://www.ctfrecipes.com/cryptography/symmetric-cryptography/aes/mode-of-operation/ecb/ecb-oracle), it is possible to manipulate sent messages to recover each byte of the flag at a time.

```python
from pwn import remote
from Crypto.Cipher import AES
import string
import re

flag_size = 192 // AES.block_size

adaptive_plain_prefix = b"i" * (AES.block_size * flag_size) + b"a" * (AES.block_size - 1)
suffix = b"a" * (AES.block_size - 1)
flag = ""

r = remote("ecbpp.kctf-453514-codelab.kctf.cloud", 1337)
while True:
    for g in string.printable:
        #print(f"Trying: {g}")
        try:
            intro = r.recvuntil(b"]\n").decode()
            #print(intro)
            r.sendline(b"Y")
            resp = r.recv()
            
            #print(resp)
            to_send = adaptive_plain_prefix + g.encode() + suffix
            r.sendline(to_send)
            resp = r.recvuntil(b"\n").decode()
            #print(resp)        
            ciphertext = re.search("Your message is: (.*)\n", resp).group(1).strip()
            ciphertext_blocks = [ciphertext[i:i+(2*AES.block_size)] for i in range(0, len(ciphertext), 2*AES.block_size)]
            
            #print(ciphertext_blocks)
            if ciphertext_blocks[exploration_block] == ciphertext_blocks[target_block]:
                flag += g
                adaptive_plain_prefix = adaptive_plain_prefix[1:] + g.encode()
                print(f"partial flag: {flag}")
                if len(flag) % 16 == 0:
                    suffix = b"a" * AES.block_size
                    target_block += 1
                suffix = suffix[1:]
                break
        except Exception as e:
            r.close()
            r = remote("ecbpp.kctf-453514-codelab.kctf.cloud", 1337)
            print(f"Error: {str(e)}")
            break
```
