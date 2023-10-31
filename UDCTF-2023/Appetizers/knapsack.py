#Subset Sum Problem
#https://imgs.xkcd.com/comics/np_complete.png
import random
choices = list(set([random.randint(100000,1000000000) for _ in range(30)]))
random.shuffle(choices)
winners = choices[:15]
target = sum(winners)
winners.sort()
flag = "UDCTF{%s}" % ("_".join(map(str,winners)))
#print(flag)
choices.sort()
print(choices)
print(target)
