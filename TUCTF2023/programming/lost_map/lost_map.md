#  Plenty O Fish in the Sea

## Description

You have embarked on a quest to find the One Bit! Your first step is to find the scattered pieces of the treasure map on this here abandoned island!

## Analysis

The challenge provides a `.txt` file named `lost_map.log` with the following content:

    Inside this coastal cave
    Under this palm tree
    Inside this shipwreck
    Under this palm tree
    Inside this shipwreck
    Behind this foliage
    In this stream
    At the top of this cliff
    Inside this shipwreck
    Behind this foliage
    In this stream
    At the top of this cliff
    Inside this shipwreck
    Under this palm tree
    Inside this shipwreck
    Behind this foliage
    In this stream
    At the top of this cliff
    Inside this shipwreck
    Behind this foliage
    In this stream
    ...
    ...
    ...
    Inside this shipwreck
    At the top of this cliff
    Inside this shipwreck
    Behind this foliage
    In this stream
    At the top of this cliff
    Inside this shipwreck
    Behind this foliage
    In this stream
    At the top of this cliff
    Inside this shipwreck
    At the top of this cliff
    Inside this shipwreck
    Inside this coastal cave 
    Inside this coastal cave
    In this old rum stash
    In this old rum stash
    In this old rum stash
    In this old rum stash
    Inside this coastal cave 

It looks like a sort of treasure map; as we can see many lines are repeated.

Since the flag is somehow stored inside this file, first thing i tried to do was searching for words different from the one repeating in the file showed above:

    Under this big rock 
    Inside this shipwreck
    Behind this foliage
    In this stream
    TUCTF
    Under this big rock
    Inside this shipwreck
    Behind this foliage
    In this stream

By searching the string `"TUCTF"` i found a match inside the file: as we could have expected, the flag is divided into several substrings randomly placed inside the file.

By reading some lines of the file, we can easily determine which is the pattern of repeated phrases and write a simple script that reads the file and only extracts all lines not matching those: the result of this operation will be the list of all flag pieces.

```python
blacklist = ["Inside", "Behind", "In", "Under", "At"]
flag_pieces = []

with open("./programming/lost_map/lost_map.log", "r") as lost_map:
    candidate = lost_map.readline()
    while candidate:
        for b in blacklist:
            if b in candidate:
                candidate = lost_map.readline()
                break
        else:
            flag_pieces.append(candidate.strip())
            candidate = lost_map.readline()

print(flag_pieces)
```

output:

    ['TUCTF', '%7B83h%2', '1Nd_7h3_', 'W%4073rF', '%4011%7D']

The output looks like the flag with some character being "url encoded", we modify the script to decode the result and obtain the flag:

```python
from urllib.parse import unquote

blacklist = ["Inside", "Behind", "In", "Under", "At"]
flag_pieces = []

with open("./programming/lost_map/lost_map.log", "r") as lost_map:
    candidate = lost_map.readline()
    while candidate:
        for b in blacklist:
            if b in candidate:
                candidate = lost_map.readline()
                break
        else:
            flag_pieces.append(candidate.strip())
            candidate = lost_map.readline()

print(flag_pieces)
print(unquote("".join(flag_pieces)))
```

output:

    ['TUCTF', '%7B83h%2', '1Nd_7h3_', 'W%4073rF', '%4011%7D']
    TUCTF{83h!Nd_7h3_W@73rF@11}
