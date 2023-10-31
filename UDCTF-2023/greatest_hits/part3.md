# Greatest Hits 3 of 4

The previous url contained the following script:

```python
flaglink="REDACTED"

def xor(msg, key):
    o = ''
    for i in range(len(msg)):
        o += chr(ord(msg[i]) ^ ord(key[i % len(key)]))
    return o

clue="https://gist.github.com/AndyNovo"
import os
key = os.urandom(len(clue))
assert(flaglink.count(clue) > 0)

print(xor(flaglink, key).encode('hex'))
#98edbf5c8dd29e9bbc57d0e2990e4e692efb81c2318c69c626d7ea42f2efc70fece4ae5c89c7999fef1e8bac99021d7266bc9cde3cd97b9a2adaeb08dea1ca0582eaac13ced7dfdbad1194b1c60f5d372eeec29832ca20d12a85b545f9f69b1aaeb6ec4cd4
```

The plaintext message is apparently (again) the url to the flag and the last challenge. In particular, it is suggested that it is xored with a random 32 bytes key.

The challenge is basically a classic known plaintext attack, but this line of code suggests that the given `clue` can be placed in any part of the whole `flaglink`:

```python
assert(flaglink.count(clue) > 0)
```
In order to overcome this issue, we perform the basic known plaintext attack on all the right rotation of the original encoded flag, in the following way:

```python
def xor(msg, key):
    o = ""
    for i in range(len(msg)):
        o += chr(msg[i] ^ key[i % len(key)])
    return o


clue="https://gist.github.com/AndyNovo"

encoded = "98edbf5c8dd29e9bbc57d0e2990e4e692efb81c2318c69c626d7ea42f2efc70fece4ae5c89c7999fef1e8bac99021d7266bc9cde3cd97b9a2adaeb08dea1ca0582eaac13ced7dfdbad1194b1c60f5d372eeec29832ca20d12a85b545f9f69b1aaeb6ec4cd4"

rotations = []

for i in range(0, len(encoded) - len(clue), 2):
    rotated_string = encoded[-2:] + encoded[:-2]  
    byte_array = bytes.fromhex(rotated_string)  
    rotations.append(byte_array)
    encoded = rotated_string  

for r in rotations:
    index = 0
    key = bytearray()
    for l in clue:
        for b in range(256):
            enc = b ^ ord(l)

            if enc == r[index]:
                key.append(b)
                index += 1
                break
    flaglink = xor(r, key)
    if "AndyNovo/" in flaglink:
        print(flaglink) 
        print("\n")
```

which outputs in particular:

```python
https://gist.github.com/AndyNovo/d2415028d31f572ff9ec03bf95fb3605+PÀ©ve×9ÖªBûä=â5
```
the [url](https://gist.github.com/AndyNovo/d2415028d31f572ff9ec03bf95fb3605) for the flag and the last challenge of this series:

    UDCTF{x0r_and_I_g0_w4y_back}