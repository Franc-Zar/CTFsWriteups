# Simpler Cipher

## Description

I decided to challenge myself and build my own cryptographic cipher, surely it's unbreakable!

`nc chal.tuctf.com 30000`

## Source code analysis

This challenge provides a custom encryption and decryption service. It involves a simple cryptographic system where users can encrypt plaintext, decrypt ciphertext, or attempt to retrieve the flag.

`cipher.py`
```python
import time

exptables=[REDACTED]

def main():
    while(2>1):
        time.sleep(2)
        inp = input('''Please Select Your Mode\n
                    [1] Encrypt a message with a custom key
                    [2] Decrypt a message 
                    [3] Get the flag 
                    [4] Exit
                    \n''')
        if not(inp in ('1','2','3','Encrypt a message with a custom key','Decrypt a message','Get the flag','4','Exit')):
            print('Sorry, please try again!')
        else:
            if inp=='1' or inp=='Encrypt a message with a custom key':
                try:
                    encrypt()
                except Exception as e:
                    print('Error Encrypting! Please try again\n' + e)
            elif inp=='2' or inp=='Decrypt a message':
                try:
                    decrypt()
                except Exception as e:
                    print('Error decrypting!  Please try again\n' + e)
            elif inp=='4' or inp=='Exit':
                return True
            else:
                try:
                    getFlag()
                except:
                    print('Error getting flag! Please try again')

def encrypt():
    pt = str(input('Enter your plaintext: '))
    try:
        key = input('Enter your 6 byte key (ex. 0011AABBCCDD): ').strip()
        binKey = str(bin(int('1'+key,base=16)))[3:]
    except:
        print('Invalid Key! Please ensure that your input is 6 bytes!')
        return -1
    if(len(binKey)!=48):
        print('Error with key! Please ensure key is 6 bytes long!')
        return -1
    binPT=''
    for chr in pt:
        binPT+='{0:08b}'.format(ord(chr)) 
    binCText=''
    binPT=pad(binPT)
    for i in range(0,len(binPT),48):
        binCText+=expand(xor(binPT[i:i+48],binKey))
    print('\nYour ciphertext is: \n' + binCText+'\n\n')


def decrypt():
    ctext = str(input('Enter your ciphertext as binary (ex. 0011001101010101000011110000000011111111): ')).strip()
    try:
        key = input('Enter your 6 byte key (ex. 0011FFDDCCBB): ').strip()
        binKey = str(bin(int('1'+key,base=16)))[3:]
    except:
        print('Invalid Key! Please ensure that your input is 6 bytes!')
        return -1
    if(len(binKey)!=48):
        print('Error with key! Please ensure key is 6 characters long!')
        return -1
    binPText=''
    for i in range(0,len(ctext),72):
        binPText+=xor(unexpand(ctext[i:i+72]),binKey)
    decodedMessage=''
    for i in range(0,len(binPText),8):
        decodedMessage+=str(chr(int(binPText[i:i+8],2))) 
    print('\nHere is your plaintext back: \n ' + decodedMessage+'\n\n')

def getFlag():
    print('''
          111100010001010001101000000101110001010001100001100001100001000101101010010010010001100001101010000101010010111000011001010001101110111000101110010010010001111000000101101101110001010001110001010001000101000101111100010010010101000101110001111000010101100001011001010001011110011001010001101010010010100001010010010001011001111000110011010001010010010001010101111100101010100001101010101101110001100001010001011001110011000101100001010010110011101101010010100001110011011001101101101101011001101101100001
          ''') 


def unexpand(ctext):
    unexp = ''
    for i in range(0,len(ctext),6):
        for j in range(0,4):
            try:
                lsb = exptables[j].index(ctext[i:i+6])
                unexp += '{0:02b}'.format(j)
                unexp += '{0:02b}'.format(lsb)
            except:
                continue
    return unexp


def pad(ptext): ##DONE 
    if len(ptext)%48!=0:
        bytesToAdd = (48-(len(ptext)%48))//8
        for i in range(0,bytesToAdd):
            ptext+='{0:08b}'.format(i)   
    elif len(ptext)==0:
        raise ValueError("Invalid plaintext length")    
    return ptext


def xor(ptext,key):
    text=''
    for i in range(0,48):
        text+=str(int(ptext[i])^int(key[i]))
    return text


def expand(ctext):
    ct=''
    for i in range(0,len(ctext),4):
        msb = ctext[i:i+2]
        lsb = ctext[i+2:i+4]
        exp = exptables[int(msb,2)][int(lsb,2)]
        ct+=exp
    return ct


if __name__=='__main__':
    main()
```

The encryption system works as follows:

1. **Input and Key**: Users provide plaintext and a 6-byte hexadecimal key.
2. **Padding**: Plaintext is padded to a length divisible by 48 bits.
3. **XOR**: The padded plaintext is XORed with the binary representation of the key.
4. **Expansion**: The XORed result is expanded using predefined lookup tables (`exptables`).

```python
def expand(ctext):
    ct=''
    for i in range(0,len(ctext),4):
        msb = ctext[i:i+2]
        lsb = ctext[i+2:i+4]
        exp = exptables[int(msb,2)][int(lsb,2)]
        ct+=exp
    return ct
```

It can be observed that `exptables` is a 4x4 matrix. By examining the encrypted flag and the reverse operation implemented in `unexpand()`, it becomes evident that each element of the matrix is a 6-bit long string.

```python
def unexpand(ctext):
    unexp = ''
    for i in range(0,len(ctext),6):
        for j in range(0,4):
            try:
                lsb = exptables[j].index(ctext[i:i+6])
                unexp += '{0:02b}'.format(j)
                unexp += '{0:02b}'.format(lsb)
            except:
                continue
    return unexp
```

## Exploit

To solve the challenge, the following steps are required:

1. Recover the elements of `exptables`.  
2. Determine the key used to encrypt the flag.

The elements of the expansion table can be reconstructed by using a carefully chosen plaintext and its corresponding ciphertext. Encrypting the plaintext with a 0-byte key effectively neutralizes the XOR operation, allowing each element to be directly mapped to its corresponding expanded value. The recovery function is reported below:


```python
def recover_expansion_table(ciphertext, unexpanded_ciphertext):
    """
    Reconstructs the expansion table from the ciphertext and unexpanded ciphertext.

    Args:
        ciphertext (str): The ciphertext as a binary string.
        unexpanded_ciphertext (str): The unexpanded ciphertext as a binary string.

    Returns:
        list: A 4x4 expansion table filled with reconstructed values.
    """
    # Initialize a 4x4 expansion table with empty strings
    expansion_table = [['' for _ in range(4)] for _ in range(4)]
    
    # Index to track position in ciphertext
    ciphertext_idx = 0

    # Iterate through unexpanded ciphertext in 4-bit chunks
    for i in range(0, len(unexpanded_ciphertext), 4):
        # Extract MSB and LSB from the current 4-bit chunk
        msb = unexpanded_ciphertext[i:i+2]
        lsb = unexpanded_ciphertext[i+2:i+4]
        
        # Map the current 6-bit ciphertext chunk to the expansion table
        expansion_table[int(msb, 2)][int(lsb, 2)] = ciphertext[ciphertext_idx:ciphertext_idx+6]
        
        # Move to the next 6-bit chunk in the ciphertext
        ciphertext_idx += 6

    return expansion_table
```

To ensure the complete recovery of the expansion table, a sufficiently long plaintext should be used to maximize the probability of generating all possible matrix index combinations. This approach ensures that all 16 possible 4-bit input combinations are mapped to their corresponding 6-bit expanded outputs:

    0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ

Once `exptables` has been successfully recovered and verified by unexpanding the ciphertext of the chosen plaintext, it becomes possible to unexpand the flag ciphertext. 
Although the flag's key is still unknown, it is known that the flag format is `TUCTF{(.*)}`, which is exactly 6 bytes long, matching the cipher key length. 
By leveraging this knowledge, we can force the XOR decryption to reveal the initial part of the flag, thereby determining the key and ultimately fully decrypting the flag.

```python
# discover with chosen plaintext flag key
def xor_with_key(key, message):
    return bytes([message[i] ^ key[i % len(key)] for i in range(len(message))])

flag_key = bytearray()
unexpanded_flag = long_to_bytes(int(unexpand(enc_flag, exptable),2))
known_flag_part = b"TUCTF{"

for k in range(6):
    for b in range(256):
        if unexpanded_flag[k] ^ b == known_flag_part[k]:
            flag_key.append(b)
            break
flag = xor_with_key(flag_key, unexpanded_flag)
print(f"Flag: {flag.decode()}")
```
`TUCTF{tr@ck_th3_exp@nsi0ns_and_r3v3rs3}\x00\x01\x02`
