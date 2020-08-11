try:
    from crypto.SHA1 import SHA1
except:
    from SHA1 import SHA1
import secrets

# From https://stackoverflow.com/questions/4798654/modular-multiplicative-inverse-function-in-python
def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    return x % m

def randprime(n):
    test = secrets.randbits(n)
    while Miller_Rabin(test, n) is False:
        test = secrets.randbits(n)
    return test

def Miller_Rabin(n, k=3):
    # List of primes from https://code.activestate.com/recipes/366178-a-fast-prime-number-list-generator/
    p = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73,
    79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163
    , 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251
    , 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349
    , 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443
    , 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557
    , 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647
    , 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757
    , 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863
    , 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983
    , 991, 997, 1009, 1013, 1019, 1021, 1031, 1033, 1039, 1049, 1051, 1061, 1063, 1069, 
    1087, 1091, 1093, 1097, 1103, 1109, 1117, 1123, 1129, 1151, 1153, 1163, 1171
    , 1181, 1187, 1193, 1201, 1213, 1217, 1223, 1229, 1231, 1237, 1249, 1259, 1277,
    1279, 1283, 1289, 1291, 1297, 1301, 1303, 1307, 1319, 1321, 1327, 1361, 1367, 1373, 
    1381, 1399, 1409, 1423, 1427, 1429, 1433, 1439, 1447, 1451, 1453, 1459, 1471
    , 1481, 1483, 1487, 1489, 1493, 1499, 1511, 1523, 1531, 1543, 1549, 1553, 1559,
    1567, 1571, 1579, 1583, 1597, 1601, 1607, 1609, 1613, 1619, 1621, 1627, 1637, 1657,
    1663, 1667, 1669, 1693, 1697, 1699, 1709, 1721, 1723, 1733, 1741, 1747, 1753
    , 1759, 1777, 1783, 1787, 1789, 1801, 1811, 1823, 1831, 1847, 1861, 1867, 1871,
    1873, 1877, 1879, 1889, 1901, 1907, 1913, 1931, 1933, 1949, 1951, 1973, 1979, 1987,
    1993, 1997, 1999, 2003, 2011, 2017, 2027, 2029, 2039, 2053, 2063, 2069, 2081
    , 2083, 2087, 2089, 2099, 2111, 2113, 2129, 2131, 2137, 2141, 2143, 2153, 2161,
    2179, 2203, 2207, 2213, 2221, 2237, 2239, 2243, 2251, 2267, 2269, 2273, 2281, 2287,
    2293, 2297, 2309, 2311, 2333, 2339, 2341, 2347, 2351, 2357, 2371, 2377, 2381
    , 2383, 2389, 2393, 2399, 2411, 2417, 2423, 2437, 2441, 2447, 2459, 2467, 2473,
    2477, 2503, 2521, 2531, 2539, 2543, 2549, 2551, 2557, 2579, 2591, 2593, 2609, 2617,
    2621, 2633, 2647, 2657, 2659, 2663, 2671, 2677, 2683, 2687, 2689, 2693, 2699
    , 2707, 2711, 2713, 2719, 2729, 2731, 2741, 2749, 2753, 2767, 2777, 2789, 2791,
    2797, 2801, 2803, 2819, 2833, 2837, 2843, 2851, 2857, 2861, 2879, 2887, 2897, 2903, 
    2909, 2917, 2927, 2939, 2953, 2957, 2963, 2969, 2971, 2999]


    for prime in p:
        if prime == n:
            return True
        if (n % prime == 0):
            return False
    r = 0
    d = n - 1
    while d % 2 == 0:
        r += 1
        d = d//2
    for i in range(k):
        a = secrets.randbelow(n-2)
        while a < 2:
            a = secrets.randbelow(n-2)
        x = pow(a, d, n)
        if (x == 1) or (x == n - 1):
            continue
        j = 0
        while x != (n - 1):
            #print(x)
            if (j == r - 1):
                return False
            x = pow(x, 2, n)
            j += 1
    return True

class Digital_Signature(object):
    def __init__(self):
        self.hash_function = SHA1
        self.L = 1024
        self.N = 160
        self.q = randprime(self.N)
        self.p = (secrets.randbits(self.L) * self.q) + 1
        #self.p = 283
        #self.q = 47
        while not Miller_Rabin(self.p):
            #self.q = randprime(self.N)
            self.p = (secrets.randbits(self.L) * self.q) + 1
        #print((self.p - 1) % self.q, self.p, self.q)
        self.h = secrets.randbelow(self.p-2)
        while self.h < 2:
            self.h = secrets.randbelow(self.p-2)
        self.g = pow(self.h, (self.p-1)//self.q, self.p)
        self.x = secrets.randbelow(self.q-1)
        self.y = pow(self.g, self.x, self.p)
        

    def sign(self, message):
        k = secrets.randbelow(self.q-1)
        r = pow(self.g, k, self.p) % self.q
        s = (modinv(k, self.q) * (int(SHA1(message), 16) + self.x * r)) % self.q
        return [r, s, self.p, self.q, self.g, self.y]

def check_sign(key, m):
    r = key[0]
    s = key[1]
    p = key[2]
    q = key[3]
    g = key[4]
    y = key[5]
    if r <= 0 or r >= q:
        return False
    if s <= 0 or s >= q:
        return False
    w = modinv(s, q)
    u1 = (int(SHA1(m), 16) * w) % q
    u2 = (r * w) % q
    v = ((pow(g, u1, p) * pow(y, u2, p)) % p) % q
    #print(v, r)
    return v == r

                    

if __name__ == "__main__":
    test = "TEST"
    temp = Digital_Signature()
    print([temp.p, temp.q, temp.g, temp.y])
    print(temp.x)
    t = temp.sign(test)
    print(check_sign(t, test, SHA1))
