# Greatest Hits 1 of 4

The previous url contained the following script:


```python
#Python 2.7
flag="REDACTED"
import random
import time
print(time.time())
#1697043249.53
time.sleep(random.randint(0, 50))
random.seed(int(time.time()))
ct=""
for c in flag:
    ct += chr(random.randint(0,255) ^ ord(c))
print(ct.encode('hex'))
#a0469bbb0b3a4f06306739032244b0c5119ba66a0d3b5a2322acdd7070bf85690cdf8573212c1b927e0ba624
```

`random` is not cryptographically secure and in this case it is seed with a value we are able to retrieve at most with 50 trials (not considering the amount of time i wasted running the code in python3...):

```python  
# Python2.7  
import random
import binascii

past = 1697043249.53
ct = binascii.unhexlify("a0469bbb0b3a4f06306739032244b0c5119ba66a0d3b5a2322acdd7070bf85690cdf8573212c1b927e0ba624")

index = 0

for delay in range(51):
    flag = ""
    _seed = past + delay
    generator = random.Random()
    generator.seed(int(_seed))
    decrypted = bytearray()

    for i in range(len(ct)):
        key_part = generator.randint(0, 255)
        decrypted_byte = chr(ord(ct[i]) ^ key_part)
        decrypted.append(decrypted_byte)
        index += 1
    
    try:
        decoded_flag = decrypted.decode("utf-8")
        if "UDCTF" in decoded_flag:
            print("SEED: " + str(int(_seed)))
            print("DELAY: " + str(delay))
            print(decoded_flag)
    except UnicodeDecodeError:
        pass
```

which outputs the flag:

```python
SEED: 1697043291.53
DELAY: 42
UDCTF{4hh_m3m0r1es_th4t5_wh4t_1ts_4ll_about}
```