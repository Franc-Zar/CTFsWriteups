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