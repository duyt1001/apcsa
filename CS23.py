#!/usr/bin/env python

import math
from random import randrange
from hashlib import md5

#
# Implementation of MIT PRIMES CS Problems 2023
# https://math.mit.edu/research/highschool/primes/materials/2023/CSproblems2023.pdf
#
# Tested in Python 3.10.4 on both Mac and Windows.
#
# Run following command on CLI to run this program
# python CS23.py
# Or if your default python is not version 3:
# python3 CS23.py

#
# Modular multiplicative inverse
# https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm
def ModularInverse(num, mod):
    "Return inverse of num modulo mod by Extended Euclidean Algorithm"

    assert mod > 0
    assert num > 0

    # Get Quotient List
    quotient = []
    m, n = mod, num % mod
    r = n
    while True:
        q, r = m // n, m % n
        # print(f'{m} = {n} x {q} + {r}')
        m, n = n, r
        if r != 0:
            quotient.append(q)
        else:
            break
    # print(quotient)

    # Get Inverse
    inv = [1, quotient[-1]]
    lq = len(quotient)
    for i in range(2, lq+1):
        inv.append(inv[i-2] + inv[i-1] * quotient[lq - i])

    # If odd lq, then mod - last, else last
    return inv[-1] if (lq % 2 == 0) else (mod - inv[-1])

def Problem1Part6():
    print("\nMIT PRIMES CS 2023 Problem 1 Part 6:")
    print(f'7 modulo 120 = {ModularInverse(7,120)}')
    print(f'100 modulo 22391 = {ModularInverse(100,22391)}')
    print(f'10799 modulo 4699463680 = {ModularInverse(10799,4699463680)}')


# Return Modular exponentiation a**k % mod
def ModPow(a, k, mod):
    "Find a**k % mod"

    # simplify if k is 0 or 1
    a0 = a % mod
    if k == 0:
        return 1
    elif k == 1:
        return a0

    # l is minimum exponent that a**l > mod
    l = math.ceil(math.log(mod, a0))
    if k < l:
        return a0 ** k
    
    # separate k = (k//l)*l + lr, so that
    # a^k % mod = (a**l %mod)**(k//l) * a**lr % mod
    lr = k % l
    a1 = (a0**l) % mod
    p = ModPow(a1, k//l, mod) * a0**lr
    return p % mod


def Problem1Part8():
    print("\nMIT PRIMES CS 2023 Problem 1 Part 8:")
    print(f'7**33 mod 11 = {ModPow(7,33,11)}')


def Problem1Part9():
    print("\nMIT PRIMES CS 2023 Problem 1 Part 9:")
    print(f'7**123456 mod 11 = {ModPow(7,123456,11)}')


# Euler's totient function with n = p or n = pq
# https://en.wikipedia.org/wiki/Euler%27s_totient_function
def phi(p, q=None):
    if q is not None:
        return (p-1) * (q-1)
    else:
        return p-1

# check if a b are coprimes
def coPrime(a, b):
    return math.gcd(a, b) == 1

# return tuple of public key (n, e)
def publicKey(p,q,e):
    assert coPrime(e, phi(p,q))
    return (p*q, e)

# return tuple of private key (p, q, d)
def privateKey(p,q,e):
    assert coPrime(e, phi(p, q))
    return (p, q, ModularInverse(e, phi(p, q)))

# RSA encryption: m**e % N
def encrypt(m, pubKey):
    N, e = pubKey
    return ModPow(m, e, N)

# a**k % mod when mod is prime
def powPrimeMod(a, k, modPrime):
    phi = modPrime - 1
    return ModPow(a, (k % phi), modPrime)

# RSA decrption c**d % N using Chinese Remainder Theorem
# https://en.wikipedia.org/wiki/Chinese_remainder_theorem
def decrypt(c, privKey):
    p,q,d = privKey
    # message = ModularInverse(c, d, p*q)
    # Use Chinese Remainder Theorem
    # phi = (p-1)*(q-1)
    # d1 = d % phi
    # print(ModPow(c, d1, p*q))
    dp = powPrimeMod(c, d, p)
    dq = powPrimeMod(c, d, q)
    qinv_p = ModularInverse(q, p)
    pinv_q = ModularInverse(p, q)
    return (dp * qinv_p * q + dq * pinv_q * p) % (p*q)

def Problem2Part5():
    print("\nMIT PRIMES CS 2023 Problem 2 Part 5:")
    p = 8783
    q = 9133
    e = 5
    m = 34367293
    print(f"p={p}, q={q}, e={e}, m={m}")
    pubKey = publicKey(p,q,e)
    print(f"public key: {pubKey}")
    privKey = privateKey(p,q,e)
    print(f"private key: {privKey}")
    c = encrypt(m, pubKey)
    print(f"c = {c}")
    decrypted = decrypt(c, privKey)
    print(f"m = {decrypted}")
    assert m == decrypted

# calculate signature: s = m**d % N
def signature(m, d, N):
    return ModPow(m, d, N)

# Get m from signature, i.e. s**m % n, in order to verify signature
def s2m(s, pubKey):
    n, e = pubKey
    return ModPow(s, e, n)

def Problem3Part1():
    print("\nMIT PRIMES CS 2023 Problem 3 Part 1:")
    n = 80215139
    e = 5
    pubKey = (n, e)
    print(f"Given n = {n}, e = {e}")
    m, s = 123, 49259120
    m1 = s2m(s, pubKey)
    print(f"m = {m}, s(m) = {s}, m1 = {m1}, verified {m == m1}")
    m, s = 555, 59131983
    m1 = s2m(s, pubKey)
    print(f"m = {m}, s(m) = {s}, m1 = {m1}, verified {m == m1}")
    m, s = 1234567, 58520412
    m1 = s2m(s, pubKey)
    print(f"m = {m}, s(m) = {s}, m1 = {m1}, verified {m == m1}")

# Simulate the process to create a blinded message 
def blindMessage(m, n, e):
    # Generate blind factor
    r = randrange(n)

    # Get the blinded message with r^e * m mod n
    mb = (ModPow(r, e, n) * m) % n
    return mb, r

def unblindSignature(s, n, e, r):
    return (ModularInverse(r, n) * s) % n


# Simulate the process to blind a message, send to get signature, and unblind it
def Problem5Part4():
    print("\nMIT PRIMES CS 2023 Problem 5 Part 4:")
    # test data, they can be changed to test other data
    message = 1234567890
    # p = 8783
    # q = 9133
    # e = 5
    p = 197261
    q = 103141
    e = 65537

    # Get public key from server or bank
    n, e = publicKey(p, q, e)

    # Blind the message.
    mb, r = blindMessage(message, n, e)
    print(f"Blinding factor {r}, blinded message {mb}")

    # Simulate server/bank process to create signature using its private key
    def getSignature(message):
        # encapsulate the process of the private key within server/bank
        _, _, d = privateKey(p, q, e)
        return signature(message, d, p*q)
    
    # Send to server/bank to get signature of blinded message
    sb = getSignature(mb)
    print(f"signature with blinding factor is {sb}")

    # Unblind the signature to get original signature message**d % n
    s = unblindSignature(sb, n, e, r)
    print(f"signature without blinding factor is {s}")

    # verify that the signature matches message, i.e. s^e = message % n
    m1 = s2m(s, (n, e))
    print (f"verify: m = {message}, m1 = {m1}")
    assert m1 == message


### For Problem 6
def HashFunction(x, y):
    # Make sure the inputs are between 0 and 2**32-1
    assert 0 <= x <= 0xFFFFFFFF
    assert 0 <= y <= 0xFFFFFFFF

    # concat x and y, with front padding to 10 decimal digits
    xy = f"{x:010d}{y:010d}"

    # get md5
    digest = md5(xy.encode("utf-8")).hexdigest()
    # print(digest)
    return digest[:8], digest[-8:]

def f(x, y):
    return HashFunction(x, y)[0]

def g(x, y):
    return HashFunction(x, y)[1]

def test_HashFunction():
    print(f(1, 2))
    print(g(1, 2))
    print(f(0, 0xffffffff))
    # print(g(-1, 1))
    print(f(9999999999, 0))

class Bank:
    def __init__(self) -> None:
        # Prepare for public key and private key
        # _p .. are supposed to be private by convention
        self._p = 103141
        self._q = 197261
        self.e = 65537
        self.n = self._p * self._q
        self.PubicKey = publicKey(self._p, self._q, self.e)
        self._PrivateKey = privateKey(self._p, self._q, self.e)
        self._d = self._PrivateKey[2]

        self.k = 10
        self.k1 = 10

        self.nextAccountNumber = 10000
        self.nextBillNumber = 10000
        self.accounts = []

    # Create an account with 5-digit id, and save to accounts list
    def createAccount(self):
        assert self.nextAccountNumber <= 99999
        acctNum = self.nextAccountNumber
        self.nextAccountNumber += 1
        self.accounts.append(acctNum)
        return acctNum

    # Create a bill with 5-digit id
    # Bank doesn't save it after the creation
    def createBill(self):
        assert self.nextBillNumber <= 99999
        billNum = self.nextBillNumber
        self.nextBillNumber += 1
        return billNum

    # public function to sign a message
    def createSignature(self, message):
        return ModPow(message, self._d, self.n)

    # public functin to verify whether signature s matches m
    def verifySignature(self, m, s):
        m1 = ModPow(s, self.e, self.n)
        return m == m1

    # function to set a new k value if needed
    def setK(self, k):
        self.k = k

    # function to set a new k1 value if needed
    def setK1(self, k1):
        self.k1 = k1

    # Customer request to sign a bill
    # chunks include k+k1 chunks
    # randomly get k1 chunks to unblind
    # then sign
    def signBill(self, customer, to_sign_file):
        pass



class Customer:
    def __init__(self, bank) -> None:
        self.bank = bank
        self.acctNum = bank.createAccount()
        self.bills = []
        print(f"Customer {self.acctNum} is created")


    def generateBill(self):
        billn = self.bank.createBill()
        chunks = []
        for i in range(self.bank.k + self.bank.k1):
            chunk = self.prepareChunk(billn)
            chunks.append(chunk)
        self.bills.append((billn, chunks))
        print(f"Bill {self.bills[-1]} is generated")

    # Prepare a chunk for the bill
    # return (a, aXorI, c, d, x, y, fi)
    def prepareChunk(self, billNum):
        I = int(f"{self.acctNum:05d}{billNum:05d}")
        a = randrange(0, 0xffffffff)
        c = randrange(0, 0xffffffff)
        d = randrange(0, 0xffffffff)
        aXorI = a ^ I
        x = int(g(a, c), 16)
        y = int(g(aXorI, d), 16)
        fi = int(f(x, y), 16)
        return (a, aXorI, c, d, x, y, fi)


def test_signature(bank):
    s = bank.createSignature(1234)
    valid = bank.verifySignature(1234, s)
    print(f"{s} is {valid}")

def Problem6Part6():
    print("\nMIT PRIMES CS 2023 Problem 6 Part 6:")
    bank = Bank()
    # test_signature(bank)
    alice = Customer(bank)
    alice.generateBill()

if __name__ == '__main__':
    Problem1Part6()
    Problem1Part8()
    Problem1Part9()
    Problem2Part5()
    Problem3Part1()
    Problem5Part4()
    # test_HashFunction()
    Problem6Part6()
