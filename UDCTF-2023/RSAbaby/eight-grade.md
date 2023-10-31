# RSA School 8th Grade 

The challenge provides the following files:

```python
from sympy import *
from Crypto.Util.number import *
import random
p=getPrime(512)
q = nextprime(p + random.randint(10**9,10**10))
N=p*q
msg=b'UDCTF{REDACTED}'
pt = bytes_to_long(msg)
e = 65537
ct = pow(pt, e, N)
print(N)
print(e)
print(ct)
```

    150459385706485253914441877113384979120500190162060302508541299821944089329499694790524295291567135320851306118878915105907451588623958757693847782920309145753994837129247899050065917279292484317798035721308006529470560777407483024961882645653400385816416526996027114542480513056100444908809723540145733606413
    
    65537
    
    2307423154990120835718508986514267143655326830191633946685219656220840494132925634069678170936781595742873539412034460586639622885239343246714559828497111273868089182257159904851948098861145910137615097694560608874412798124055642460363270612990137075678106724613406247492210136960473648165963598137216228495

Similarly to the previous one, i was able to obtain the flag performing again a [Fermat Attack](https://fermatattack.secvuln.info/):

```python
import math
from Crypto.Util.number import long_to_bytes

# Function to find the Floor
# of square root of a number
def sqrtF(x):
	# if x is less than 0
	if x < 0:
		raise ValueError("Negative argument.")
	
	# if x==0 or x==1
	if x == 0 or x == 1:
		return x
	
	y = x // 2
	
	# run a loop
	while y > x // y:
		y = (x // y + y) // 2
	
	return y

# function to find the Ceil
# of square root of a number
def sqrtC(x):
	y = sqrtF(x)

	if x == y * y:
		return y
	else:
		return y + 1

# Fermat factorisation
def FermatFactors(n):
	# if n%2 ==0 then return the factors
	if n % 2 == 0:
		return str(n // 2) + ", 2"
	
	# find the square root
	a = sqrtC(n)
	
	# if the number is a perfect square
	if a * a == n:
		return str(a) + ", " + str(a)
	
	# else perform factorisation
	while True:
		b1 = a * a - n
		b = sqrtF(b1)
		
		if b * b == b1:
			break
		else:
			a += 1
	
	return [a - b, a + b]

# Driver code
if __name__ == "__main__":
    e = 65537
    ct = 2307423154990120835718508986514267143655326830191633946685219656220840494132925634069678170936781595742873539412034460586639622885239343246714559828497111273868089182257159904851948098861145910137615097694560608874412798124055642460363270612990137075678106724613406247492210136960473648165963598137216228495
    N = 150459385706485253914441877113384979120500190162060302508541299821944089329499694790524295291567135320851306118878915105907451588623958757693847782920309145753994837129247899050065917279292484317798035721308006529470560777407483024961882645653400385816416526996027114542480513056100444908809723540145733606413
    factors = FermatFactors(N)
    phi = (factors[0] - 1) * (factors[1] - 1)
    
    d = pow(e, -1, phi)
    flag = long_to_bytes(pow(ct, d, N)).decode()
    
    print(flag)     
```

    UDCTF{4n_RSA_5ch0ol_gr4dua73!!}