from pwn import remote, context
import re

def reverse_check_cat_box(transformed, cat_state):
    c = bytearray(transformed)
    if cat_state == "alive":
        for i in range(len(c)):
            c[i] ^= 0xAC
            c[i] = (c[i] >> 1)
    elif cat_state == "dead":
        for i in range(len(c)):
            c[i] ^= 0xCA
            c[i] = ((c[i] << 1) & 0xFF) | (c[i] >> 7)
    return bytes(c)

def otp(p, k):
    k_r = (k * ((len(p) // len(k)) + 1))[:len(p)]
    return bytes([p ^ k for p, k in zip(p, k_r)])

KEY_LENGTH = 160

r = remote("pad.ctf.intigriti.io", 1348)

found_key = bytearray()
key_to_iterate = bytearray(b"\x00" * KEY_LENGTH)
to_find = 0

chosen_plaintext = bytearray(b"\x00" * KEY_LENGTH)
print(chosen_plaintext)

r.recv()
response = r.recv().decode()
print(response)
enc_flag = bytes.fromhex(re.search(': (.*)\n\n', response).group(0)[2:])

r.sendline(chosen_plaintext)   
response = r.recv().decode()
cat_state = re.search('=(.*):', response).group(0)
cat_state = re.sub('[\W_]+', '', cat_state)
print(cat_state)

enc_message_cat_box = bytes.fromhex(re.search(': (.*)\n', response).group(0)[2:])
enc_message = reverse_check_cat_box(enc_message_cat_box, cat_state)

r.close()

while len(found_key) != KEY_LENGTH:
    for b in range(256):
        key_to_iterate[to_find] = b
        
        if enc_message[to_find] ^ key_to_iterate[to_find] == chosen_plaintext[to_find]:
            print(f"found key byte: {b}")
            found_key.append(b)
            to_find += 1
            break

flag = otp(enc_flag, found_key).decode()
print(flag)
