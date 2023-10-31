# by looking at previous commits on github repo of the challenge you can find the previous version of unbreakable showing the actual key 
'''
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import os
key = hashlib.sha256(b"tasciewapeoiu").digest()

with open("flag.txt","r") as f:
    flag = f.read().strip().encode()

iv = os.urandom(AES.block_size)

ct = AES.new(key,AES.MODE_CBC,iv).encrypt(pad(flag,AES.block_size))

with open("flag.enc","wb") as f:
    f.write(iv + ct)
'''


import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
key = hashlib.sha256(b"tasciewapeoiu").digest()

iv = bytes.fromhex("c8e7e61e798ceef170fa57c3237062e9")
enc_flag = bytes.fromhex("b631c985b57cb6a52073253240275457310140f919a8460b31c2df3b4fe5885e224cb38101d3fbc5151de651a4bb95de")

aes_eng = AES.new(key,AES.MODE_CBC,iv)
flag = unpad(aes_eng.decrypt(enc_flag), AES.block_size).decode()

print(flag)
#UDCTF{N0th1ng_pr0t3cts_4gainst_5l0ppiness}