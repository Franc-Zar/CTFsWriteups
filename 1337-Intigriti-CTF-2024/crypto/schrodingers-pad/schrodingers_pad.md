#  Schrödinger's Pad

## Description

<span style="color:pink">created by CryptoCat</span>

Everyone knows you can't reuse a OTP, but throw in a cat and a box.. Maybe it's secure?

`nc pad.ctf.intigriti.io 1348`

## Source code analysis

The code executed by the challenge server is provided and presented below:


`server.py`
```python
import os
import socket
import threading
import random
import traceback
import string

FLAG = os.getenv("FLAG", (
    "Not the flag you're searching for, Keep looking close, there's plenty more. "
    "INTIGRITI{TODO} A clue I might be, but not the key, The flag is hidden, not in me!!!"
))

MAX_LENGTH = 160


def otp(p, k):
    k_r = (k * ((len(p) // len(k)) + 1))[:len(p)]
    return bytes([p ^ k for p, k in zip(p, k_r)])


def check_cat_box(ciphertext, cat_state):
    c = bytearray(ciphertext)
    if cat_state == 1:
        for i in range(len(c)):
            c[i] = ((c[i] << 1) & 0xFF) ^ 0xAC
    else:
        for i in range(len(c)):
            c[i] = ((c[i] >> 1) | (c[i] << 7)) & 0xFF
            c[i] ^= 0xCA
    return bytes(c)


def handle_client(client_socket):
    try:
        # Set socket timeout to prevent hanging
        client_socket.settimeout(60)

        KEY = ''.join(random.choices(
            string.ascii_letters + string.digits, k=160)).encode()

        message = (
            "Welcome to Schrödinger's Pad!\n"
            "Due to its quantum, cat-like nature, this cryptosystem can re-use the same key\n"
            "Thankfully, that means you'll never be able to uncover this secret message :')\n\n"
        )
        client_socket.send(message.encode())

        client_socket.send(
            f"Encrypted (cat state=ERROR! 'cat not in box'): {otp(FLAG.encode(), KEY).hex()}\n".encode(
            )
        )

        client_socket.send(b"\nAnyway, why don't you try it for yourself?\n")

        plaintext = client_socket.recv(1024).strip()

        if len(plaintext) > MAX_LENGTH:
            client_socket.send(
                f"Plaintext too long! Max allowed length is {MAX_LENGTH} characters.\n".encode(
                )
            )
            return

        cat_state = random.choice([0, 1])
        ciphertext = otp(plaintext, KEY)
        c_ciphertext = check_cat_box(ciphertext, cat_state)
        cat_state_str = "alive" if cat_state == 1 else "dead"

        client_socket.send(
            f"Encrypted (cat state={cat_state_str}): {c_ciphertext.hex()}\n".encode(
            )
        )

    except socket.timeout:
        client_socket.send(b"Error: Connection timed out.\n")
    except BrokenPipeError:
        print("Client disconnected abruptly.")
    except Exception as e:
        print(f"Server Error: {e}")
        traceback.print_exc()
    finally:
        client_socket.close()


def start_server():
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("0.0.0.0", 1337))

        # Increase backlog size for more concurrent connections
        server.listen(100)
        print("Server started on port 1337")

        while True:
            try:
                client_socket, addr = server.accept()
                print(f"Accepted connection from {addr}")

                # Create a daemon thread to handle each client
                client_handler = threading.Thread(
                    target=handle_client, args=(client_socket,))
                # Daemon thread will exit automatically when main thread ends
                client_handler.daemon = True
                client_handler.start()

            except Exception as e:
                print(f"Error accepting connection: {e}")
                traceback.print_exc()

    except Exception as e:
        print(f"Critical server error: {e}")
    finally:
        server.close()
        print("[*] Server shutdown")


if __name__ == "__main__":
    start_server()

```

Below is a detailed analysis of the parts of the code that are of interest in understanding the server vulnerability and thus solving the challenge.

`handle_client()` implements the main logic exposed by the server.
In particular it performs the following operations:

```python 
KEY = ''.join(random.choices(string.ascii_letters + string.digits, k=160)).encode()
```

The previous operation generates a 160-character session key composed of ASCII letters (both uppercase and lowercase) and digits, then encodes it into bytes.
The key is re-computed in different sessions but is persistent in the .

```python
client_socket.send(
    f"Encrypted (cat state=ERROR! 'cat not in box'): {otp(FLAG.encode(), KEY).hex()}\n".encode()
)
```

The server uses the session key to generate an OTP with the challenge flag and sends it to the client.

The `otp()` function is highlighted below:

```python
def otp(p, k):
    k_r = (k * ((len(p) // len(k)) + 1))[:len(p)]
    return bytes([p ^ k for p, k in zip(p, k_r)])
```

it implements a basic **<i>stream cipher</i>**, that produces a keystream by simply XORing each byte of the plaintext with the corresponding byte of the employed key, and reuses the same key for plaintext longer than the key itself by rotating it until the plaintext lenght is reached.

The `otp()` encryption algorithm is determined by the following formula:

$`c_i = p_i \oplus k_{i \mod len(k) - 1} \ \ \ \forall i = 0 \ \text{...} \ len(p) - 1`$

The server after having sent the encrypted flag, is accepting client inputs:

```python
plaintext = client_socket.recv(1024).strip()

        if len(plaintext) > MAX_LENGTH:
            client_socket.send(
                f"Plaintext too long! Max allowed length is {MAX_LENGTH} characters.\n".encode(
                )
            )
            return

        cat_state = random.choice([0, 1])
        ciphertext = otp(plaintext, KEY)
        c_ciphertext = check_cat_box(ciphertext, cat_state)
        cat_state_str = "alive" if cat_state == 1 else "dead"

        client_socket.send(
            f"Encrypted (cat state={cat_state_str}): {c_ciphertext.hex()}\n".encode(
            )
        )
```

In order: 

1. the server is not accepting client messages longer than ```MAX_LENGTH = 160 == len(KEY)```
   - this prevents the server from being vulnerable to common [stream cipher attacks](https://en.wikipedia.org/wiki/Stream_cipher_attacks) based on same key reuse (e.g., frequency analysis based on the statistical properties of natural language or known plaintext structures). 

2. the server encrypts the client message using the same session key.

3. the server randomly chooses a bit value [0, 1] and uses it in `check_cat_box()` function to further manipulate the encrypted client message.

    ```python
    def check_cat_box(ciphertext, cat_state):
        c = bytearray(ciphertext)
        if cat_state == 1:
            for i in range(len(c)):
                c[i] = ((c[i] << 1) & 0xFF) ^ 0xAC
        else:
            for i in range(len(c)):
                c[i] = ((c[i] >> 1) | (c[i] << 7)) & 0xFF
                c[i] ^= 0xCA
        return bytes(c) 
    ```

    This function provides additional unpredictability to the nominal ciphertext, according to the provided `cat_state` value and returns the resulting bytes:

    * `cat_state == 1`: each ciphertext byte is manipulated as follows:

        $`c_i' = ((c_i \ll 1) \ \& \ \text{0xFF})) \oplus \text{0xAC}`$
      
    $`c_i`$ is left-shifted ($`\ll`$) of 1 position, i.e., multiplied by 2; the outcome is used to perform a bitwise AND (&) with 0xFF = 11111111 to ensure that only the least significant 8 bits are retained; in the end, the previous result is XORed with 0xAC = 10101100.

    * `cat_state == 0`: each ciphertext byte is manipulated as follows:
      
        $`c_i' = (\left( (c_i \gg 1) \, | \, (c_i \ll 7) \right) \, \& \, \text{0xFF}) \oplus \text{0xCA}`$

    $`c_i`$ is right-shifted of one 1 ($`\gg`$), i.e., divided by 2; $c_i$ is also left-shifted of 7 positions ($`\ll`$), i.e., multiplied by $`2^{7} = 128`$; the outcome of the previous shifts are combined in a or ( | ) operation; previous result is used to perform a bitwise AND with 0xFF = 11111111; the outcome of the previous operation is finally XORed with 0xCA = 11001010.


4. the server finally returns the hex-encoded final result `c_ciphertext` and the used `cat_state` ("alive" = 1, "dead" = 0) to the client and close the connection.


## Exploit

It is possible to leverage the client capability to encrypt a message to perform a **<i>chosen plaintext attack</i>**, recover the session key and then use it to decrypt the flag.

This is feasible because:

1. both operations of `check_cat_box()` are determistic and reversible.
2. `c_ciphertext` is provided together with the `cat_state`, which enables to identify the set of operations to reverse for each byte `c_ciphertext[i]` in order to recover `ciphertext[i]` and ultimately obtain `ciphertext`.

The following formulas represent the `check_cat_box()` inverse operations:

* `cat_state == "alive"`: 

    $`c_i = ((c_i' \oplus \text{0xAC}) \gg 1)`$

* `cat_state == "dead"`: 

    $`c_i = \left( \left(c_i' \oplus \text{0xCA} \right) \ll 1) \ \& \ \text{0xFF} \right) \, | \, \left( \left(c_i' \oplus \text{0xCA} \right) \gg 7 \right)`$

The implementation of the previous formulas in python code:

```python
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
```

To recover the session key is sufficient to send a chosen plaintext such as `\x00 * MAX_LENGTH`, i.e., a null-byte sequence of length equal to key length.

Then it is necessary to retrieve the server encrypted output `c_ciphertext` and `cat_state`, reverse `check_cat_box` manipulations with the function defined above, and then, since the plaintext is chosen and known, guess the key one byte at a time by attempting decryption of each `ciphertext` byte `ciphertext[i]` until it is correctly decrypted.
Once the client chosen message has been decrypted, the key is discovered.

```python
enc_message = reverse_check_cat_box(enc_message_cat_box, cat_state)

while len(found_key) != KEY_LENGTH:
    for b in range(256):
        key_to_iterate[to_find] = b
        
        if enc_message[to_find] ^ key_to_iterate[to_find] == chosen_plaintext[to_find]:
            print(f"found key byte: {b}")
            found_key.append(b)
            to_find += 1
            break
```
Ultimately, it is simply necessary to decrypt the received flag with the discovered session key.

```python
flag = otp(enc_flag, found_key).decode()
print(flag)
```

All operations necessary to build the attack are implemented in the following script:

`solve.py`

```python
from pwn import remote, context
import re

def reverse_check_cat_box(transformed, cat_state):
    c = bytearray(transformed)
    if cat_state == "alive":
        for i in range(len(c)):
            c[i] ^= 0xAC
            c[i] = ((c[i] >> 1) & 0xFF)
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
```

`output`

    Schrodinger's cat in a quantum bind, INTIGRITI{d34d_0r_4l1v3} hidden, hard to find. 
    Is it alive, or has fate been spun? In superposition, the game's never done.

`flag`

    INTIGRITI{d34d_0r_4l1v3}
