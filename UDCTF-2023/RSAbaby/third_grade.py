from Crypto.Util.number import long_to_bytes

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

n = 87587426608653108851564813489752475287019321764561555461700901651463446024854423042554629096780987943450742890279417241231211446818009232077230407281610183609540264821974669679932743621434901779832901512681108061652309435608446510337833028029876549629818957952682516026313018526405972829923620377438164377109
e = [71, 101]

enc_flag = [
    1421275848974615267320815554113040672023972283807752574007971561416386636110464890632994733734995114229161525885389065244354678964389211537085513310823751266472044865745324866096898051759507738772227296453397678055024824805366251635154522059070310922367078281343183508274450904681187384450253350434931649011,
    26097095086985946477598349002260598942399303275420948828501512467473619292573670218058274201990116295246084096584962695127706609264424951086000719935218496250047555039460733768633688410770610612614744411304261153778159881980276162174277085197608466835857196307432992312260307797540746411319330318058866868362]

res = egcd(e[0], e[1])

u = res[1]
v = res[2]

flag = pow(enc_flag[0], u, n) * pow(enc_flag[1], v, n) % n

print(long_to_bytes(flag).decode())




