from factordb.factordb import FactorDB
from Crypto.Util.number import long_to_bytes

n = 166045890368446099470756111654736772731460671003059151938763854196360081247044441029824134260263654537
e = 65537
ct = 141927379986409920845194703499941262988061316706433242289353776802375074525295688904215113445883589653

db = FactorDB(n)
db.connect()

factors = db.get_factor_list()

phi = (factors[0] - 1) * (factors[1] - 1)

d = pow(e, -1, phi)

flag = long_to_bytes(pow(ct, d, n)).decode()

print(flag)
