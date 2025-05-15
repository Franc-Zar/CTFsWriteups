# Let's Dance!

## Description

Bob wants to invite Alice to dance, but he doesn't know how to dance salsa! Don't let him embarrass himself, help him find the right moves!

Connection: `nc 91.99.1.179 60005`

## Source Code Analysis

```python
#!/usr/local/bin/python3
from Crypto.Util.number import bytes_to_long
from Crypto.Util.Padding import pad
from Crypto.Cipher import Salsa20
import secrets
import random
import os

FLAG = os.environ['FLAG'].encode()
k = secrets.token_bytes(32)
n = secrets.token_bytes(8)

def get_salsa_move():
    with open("moves.txt", "r") as f:
        moves_list = eval(f.read())
    move = random.choice(moves_list)
    return move

def random_shuffle(x):
    l = list(x)
    random.seed(bytes_to_long(n))
    random.shuffle(l)
    x = bytes(l)
    return x

def encrypt(x):
    p = pad(x, 16)
    s = random_shuffle(p)
    cipher = Salsa20.new(k, n)
    return cipher.nonce + cipher.encrypt(s)

if __name__ == "__main__":
    move = bytes(get_salsa_move(), encoding='utf-8')

    print("ct1 = ", encrypt(move))
    print("ct2 = ", encrypt(FLAG))
```

The server code picks a random string from the `moves.txt` file and the flag, shuffles and encrypt them with Salsa20 using same key and nonce.
The nonce is provided as part of the output and is also used to seed the random engine before shuffling the plaintexts.

Here's a cleaner and more concise version of your **Exploit** section in Markdown:

## Exploit

The challenge is vulnerable due to **keystream reuse** in a stream cipher. Given a move indexed by `x`, the ciphertexts are computed as follows:

* $ct_1 = \text{enc}(k, \text{shuffle}(\text{move}_x)) = \text{shuffle}(\text{move}_x) \oplus k$
* $ct_2 = \text{enc}(k, \text{shuffle}(\text{FLAG})) = \text{shuffle}(\text{FLAG}) \oplus k$

By XORing the two ciphertexts:

$$
ct_1 \oplus ct_2 = \text{shuffle}(\text{move}_x) \oplus k \oplus \text{shuffle}(\text{FLAG}) \oplus k = \text{shuffle}(\text{move}_x) \oplus \text{shuffle}(\text{FLAG})
$$

The keystream cancels out, leaving the XOR of the two shuffled plaintexts.

Since `move_x` is randomly chosen from a known list (`moves.txt`), we can brute-force it:

1. For each move in `moves.txt`:

   * Pad and shuffle it using the known nonce.
   * XOR it with $ct_1 \oplus ct_2$ to obtain a candidate shuffled flag.
   * Reverse the shuffle to recover a plaintext candidate.

2. Validate candidates by checking for known flag structure (i.e. it starts with `UVT{` and ends with `}` and a correct padding).

```python
from pwn import remote
import re
import random
from Crypto.Util.number import bytes_to_long
import ast
from Crypto.Util.Padding import pad, unpad
from collections import defaultdict

def random_shuffle(x, nonce):
    l = list(x)
    random.seed(bytes_to_long(nonce))
    random.shuffle(l)
    x = bytes(l)
    return x

def get_shuffle_pattern(non_shuffled, shuffled):
    """
    Returns the pattern of indices used to produce shuffled from non_shuffled.
    Handles repeated elements by tracking all their positions.

    :param non_shuffled: Original list or string before shuffling.
    :param shuffled: Shuffled version of the same list or string.
    :return: List of indices showing how non_shuffled was shuffled to become shuffled.
    """
    if len(non_shuffled) != len(shuffled):
        raise ValueError("Inputs must be the same length.")

    # Map each character to all its positions in non_shuffled
    value_to_indices = defaultdict(list)
    for idx, val in enumerate(non_shuffled):
        value_to_indices[val].append(idx)

    # Generate the pattern by popping the earliest unused index for each char
    pattern = []
    for val in shuffled:
        if not value_to_indices[val]:
            raise ValueError(f"Value '{val}' appears more times in shuffled than in original.")
        pattern.append(value_to_indices[val].pop(0))

    return pattern

def reverse_shuffle(pattern, shuffled):
    result = bytearray(len(shuffled))
    for i, p in enumerate(pattern):
        result[p] = shuffled[i]
    return result

moves = [
    "Sombrero con Mambo",
    "Enchufla con Mambo",
    "Sombrero Complicado",
    "Setenta Complicado",
    "Enchufla Complicado",
    "Sombrero con Plancha",
    "Sombrero de Manny",
    "Sombrero Manolito",
    "Sombrero por Abajo",
    "Abanico Complicado",
    "Enchufla y Quedate",
    "Enchufla y Exhibela",
    "Enchufla y Paseala",
    "Enchufla y Vacilala",
    "Enchufla y Sombrero",
    "Setenta Complicado con Gancho",
    "Enchufla Doble con Mambo",
    "Sombrero con Mambo Complicado",
    "Enchufla con Mambo Complicado",
    "Sombrero de Manny con Mambo",
    "Sombrero Manolito con Mambo",
    "Sombrero por Abajo con Mambo",
    "Abanico Complicado con Mambo",
    "Enchufla y Quedate con Mambo",
    "Enchufla y Exhibela con Mambo",
    "Enchufla y Paseala con Mambo",
    "Enchufla y Vacilala con Mambo",
    "Enchufla y Sombrero con Mambo",
    "La Babosa con Mambo",
    "El Chisme con Sabor",
    "Patineta con Mambo",
    "Coca Cola con Salsa",
    "Dame Directo con Mambo",
    "Con Dos y Dos con Salsa",
    "Dame con Sabor y Salsa",
    "Ochenta y Uno con Mambo",
    "Ochenta y Dos con Salsa",
    "Tumba Francesa con Mambo",
    "Ochenta y Tres con Salsa",
    "Uno Complicado con Mambo",
    "Enchufla Doble con Salsa",
    "Medio Sombereo con Mambo",
    "Enchufla Simple con Salsa",
    "Sacala con Mambo y Sabor",
    "Enchufla Policia con Mambo",
    "Vacilala con Paseo y Salsa",
    "MontaÃ±a con Mambo",
    "Kentucky con Salsa",
    "Siete Loco con Mambo",
    "Setenta Nuevo con Salsa",
    "Sombrero Doble con Mambo",
    "Enchufla y Adios con Salsa",
    "Enchufla y Arriba con Mambo",
    "Tumba con Mambo y Salsa",
    "Enchufla de Mambo y Salsa",
    "Siete con Gancho y Mambo",
    "Enchufla con Sabor y Salsa",
    "Setenta y Complicado con Salsa",
    "MontaÃ±a de Salsa con Mambo",
    "Doble Enchufla con Salsa",
    "Enchufla y Bailar con Mambo",
    "Salsa con PasiÃ³n y Mambo",
    "Enchufla y Mambo con Sabor",
]


candidates = []
while len(candidates) < 100:
    r = remote("91.99.1.179", 60005)
    enc_move = re.search("ct1 = (.*)\n", r.recvline().decode()).group(1)
    enc_flag = re.search("ct2 = (.*)\n", r.recvline().decode()).group(1)

    enc_move = ast.literal_eval(enc_move)
    enc_flag = ast.literal_eval(enc_flag)

    nonce = enc_flag[:8]
    assert enc_move[:8] == nonce

    enc_move = enc_move[8:]
    enc_flag = enc_flag[8:]
    required = [b'U', b'V', b'T', b'{', b'}']

    # bruteforce 
    for m in moves:
        m = bytes(m, encoding='utf-8')
        p = pad(m, 16)
        s = random_shuffle(p, nonce)
        key = [x ^ y for x, y in zip(s, enc_move)]
        attempt = [x ^ y for x, y in zip(enc_flag, key)]
        attempt = bytes(attempt)
        if all(attempt.count(c) == 1 for c in required):  
            pattern = get_shuffle_pattern(p, s)
            candidate = reverse_shuffle(pattern, attempt)
            if candidate.startswith(b"UVT{"):
                candidates.append(candidate)
                print("candidate: ", candidate)
                print("candidates number: ", len(candidates))
            else:
                r.close()
                break

char_freq = [defaultdict(int) for _ in range(32)]

for i, char_freq_dict in enumerate(char_freq):
    for c in candidates:
        if c[i] in char_freq_dict:
            char_freq_dict[c[i]] += 1
        else:
            char_freq_dict[c[i]] = 1

flag = bytearray(32)
for i, char_freq_dict in enumerate(char_freq):
    correct_char = max(char_freq_dict, key=char_freq_dict.get)
    flag.append(correct_char)
print(flag)
```

Flag: `UVT{ju5t_f33l_th3_r1thm}` 