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

    # Get the blinded message = r^e * m mod n
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

###
### Problem 6
###

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
        self.accounts = []  # keeps all account numbers of customers and merchants
        # bills keeps all the bills and the owner, it stores in the format of
        #   {'account': account, 'signature': signatures}
        self.bills = [] 
        self.next_signed = 0

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

    # Return unblinded signature, this is only for chunk verification
    def unblindSignature(self, s, r):
        return (ModularInverse(r, self.n) * s) % self.n

    # function to set a new k value if needed
    def setK(self, k):
        self.k = k

    # function to set a new k1 value if needed
    def setK1(self, k1):
        self.k1 = k1

    # Verify 1 chunk: get unblinded f from a,c,d, unblinded signature from r and fb, verify they match
    def verify1Chunk(self, fb, r, a, c, d, I):
        aXorI = a ^ I
        x = int(g(a, c), 16)
        y = int(g(aXorI, d), 16)
        fi = int(f(x, y), 16)   # original hash

        sb = self.createSignature(fb) # signature from blinded f
        si = self.unblindSignature(sb, r)   # signature from unblinded f

        return self.verifySignature(fi, si)

    # check the chunks of a bill
    # Return false if any chunk doesn't match
    def verifyAndSignChunks(self, customerNum, bank_verify_file='bank_verify.txt', tosign='to_sign.txt'):
        print(f"Bank: verifying unblinded list from {bank_verify_file}")
        thebill = self.nextBillNumber - 1 # because it's already incremented
        theI = int(f"{customerNum:05d}{thebill:05d}")

        # read the k1 unblind factors and etc
        k1chunks = []
        with open(bank_verify_file) as f:
            for line in f:
                r, a, c, d = line.strip().split()
                r = int(r)
                a = int(a)
                c = int(c)
                d = int(d)
                # print(r, a, c, d)
                k1chunks.append({'r': r, 'a': a, 'c': c, 'd': d})

        # read to_sign into allchunks_fb, which is one value of blinded f (fb) per line
        allchunks_fb = []
        with open(tosign) as f:
            for line in f:
                allchunks_fb.append(int(line.strip()))

        # Then match them with the original chunks 
        j = 0
        for i in range(len(self.unblindIt)):
            if self.unblindIt[i] == False:  # don't need k chunks
                continue
            chunk = k1chunks[j]
            if self.verify1Chunk(allchunks_fb[i], chunk['r'], chunk['a'], chunk['c'], chunk['d'], theI) == False:
                return False
            j += 1

        # verified, sign the k chunks and save to signed.txt
        signedfile = f"signed-{self.next_signed}.txt"
        self.next_signed += 1   # make sure it's unique signature file
        signedf = open(signedfile, 'w')
        sbs = []
        for i in range(len(self.unblindIt)):
            if self.unblindIt[i] == True:   # don't need k1 chunks
                continue
            sb = self.createSignature(allchunks_fb[i])
            sbs.append(sb)
            print(sb, file=signedf)
        signedf.close()

        # save the bill with customer
        self.bills.append({'account': customerNum, 'signatures': sbs})

        print(f"Bank: bill {thebill} successfully verified {self.k1} chunks")
        return signedfile

    # Verify each chunk based on the reveal bit, which is first char in chunkinfo
    def reveal1chunk(self, chunkinfo, sig):
        if chunkinfo[0] == '1':
            a = int(chunkinfo[1])
            c = int(chunkinfo[2])
            y = int(chunkinfo[3])
            r = int(chunkinfo[4])
            x = int(g(a, c), 16)
            fi = int(f(x, y), 16)
            fb = (ModPow(r, self.e, self.n) * fi) % self.n
            return self.verifySignature(fb, sig)
        elif chunkinfo[0] == '0':
            aXorI = int(chunkinfo[1])
            d = int(chunkinfo[2])
            x = int(chunkinfo[3])
            r = int(chunkinfo[4])
            y = int(g(aXorI, d), 16)
            fi = int(f(x, y), 16)
            fb = (ModPow(r, self.e, self.n) * fi) % self.n
            return self.verifySignature(fb, sig)


    # return a list of k+k1 where k1 chunks are to be unblinded
    def requestK1Unblind(self):
        print(f"Bank: randomly creating {self.k1} for customer to unblind ")
        # randomly pick k1 
        unblindIt = [False] * (self.k+self.k1)
        more = self.k1 # need more to unblind
        while more > 0:
            i = randrange(self.k + self.k1)
            if unblindIt[i] == False:
                unblindIt[i] = True
                more -= 1
        # print(unblindIt)
        self.unblindIt = unblindIt  # save for next step verification
        return unblindIt

    def compareSignatures(self, sigs1, sigs2):
        if len(sigs1) != len(sigs2):
            return False
        for i in range(len(sigs1)):
            if sigs1[i] != sigs2[i]:
                return False
        return True

    # Verify the merchant's information and save the deposit
    def depositMerchant(self, merchNum, depositfile='deposit.txt'):
        print(f'Bank: Verify the deposit.txt from Merchant {merchNum}')
        # read the depositfile
        chunkinfos = []
        sigs = []
        with open(depositfile) as f:
            for line in f:
                items = line.strip().split()
                chunkinfos.append(items[:-1])
                sigs.append(int(items[-1]))

        # Verify all the chunks
        for i in range(len(chunkinfos)):
            self.reveal1chunk(chunkinfos[i], sigs[i])

        # search for the same signatures to find the bill
        for bill in self.bills:
            if self.compareSignatures(sigs, bill['signatures']):
                break
        else:
            print(f'Bank: Unable to find this bill {bill} \nin {self.bills}')
            return False

        # Found the bill, check double-spending
        double_spending, offenderI = self.checkDoubleSpending(bill,chunkinfos)
        if double_spending:
            offender = str(offenderI)[:5]
            offendingBill = str(offenderI)[-5:]
            print(f"Bank: caught double spending from account {offender} on bill {offendingBill}")
            return False
        else:
            # deposit the bill to merchant:
            bill['account'] = merchNum
            # save chunkinfos:
            bill['chunks'] = chunkinfos
            print(f"Bank: Deposit the bill to account {merchNum} successfully")

        return True


    # Check for double spending by comparing to previously saved bill info
    def checkDoubleSpending(self, bill, chunkinfos):
        if 'chunks' not in bill:
            return False, None
        
        for i in range(len(chunkinfos)):
            billchunki = bill['chunks'][i]
            revealbit = chunkinfos[i][0]
            a_or_aXorI = int(chunkinfos[i][1])
            aXorI_or_a = int(billchunki[1])
            if revealbit != billchunki[0]:
                return True, (a_or_aXorI ^ aXorI_or_a)
        
        return False, None

class Customer:
    def __init__(self, bank) -> None:
        self.bank = bank
        self.acctNum = bank.createAccount()
        self.bills = [] # format: {billn, chunks, signedfile}
        print(f"Customer {self.acctNum} is created")


    def generateBill(self):
        print(f"Customer {self.acctNum} is generating a bill")
        billn = self.bank.createBill()

        # prepare for k+k1 chunks for bank to check and sign
        print(f"Customer {self.acctNum} bill {billn} preparing for chunks and saving to to_sign.txt")
        unsigned_chunks = []
        tosign = open('to_sign.txt', 'w')
        for i in range(self.bank.k + self.bank.k1):
            chunk = self.prepareChunk(billn)
            unsigned_chunks.append(chunk)
            # write blinded f to file to_sign.txt
            print(chunk['fb'], file=tosign)
        tosign.close()

        # Send to bank to request k1 chunks to be unblind
        unblindIt = self.bank.requestK1Unblind()

        # write the k1 chunks to file bank_verify.txt
        print(f"Customer {self.acctNum} unblind chunks in bank_verify.txt based on bank's unblind list")
        bank_verify = open('bank_verify.txt', 'w')
        for i in range(len(unblindIt)):
            if unblindIt[i] == True:
                chunk = unsigned_chunks[i]
                print(chunk['r'], chunk['a'], chunk['c'], chunk['d'], file=bank_verify)
        bank_verify.close()

        # call bank to verify k1 chunks
        signedfile = self.bank.verifyAndSignChunks(self.acctNum, 'bank_verify.txt')
        if signedfile:
            # delete k1 chunks
            for i in range(len(unblindIt)):
                j = len(unblindIt) - i - 1  # reverse order
                if unblindIt[j] == True:
                    del unsigned_chunks[j]
            assert len(unsigned_chunks) == self.bank.k
        else:
            print(f"Customer: the bill {billn} didn't pass the bank verification")
            return -1

        # 
        self.bills.append({"billn": billn, 'chunks': unsigned_chunks, 'signedfile': signedfile})
        print(f"Bank: Bill {billn} is generated and signed")
        return billn

    # Prepare a chunk for the bill
    # return (a, aXorI, c, d, x, y, fi) as dict
    def prepareChunk(self, billNum):
        I = int(f"{self.acctNum:05d}{billNum:05d}")
        a = randrange(0, 0xffffffff)
        c = randrange(0, 0xffffffff)
        d = randrange(0, 0xffffffff)
        aXorI = a ^ I
        x = int(g(a, c), 16)
        y = int(g(aXorI, d), 16)
        fi = int(f(x, y), 16)   # original hash
        # fb is blinded f, and r is the blinding factor
        fb, r = blindMessage(fi, self.bank.n, self.bank.e)
        return {
            'a': a,
            'aXorI': aXorI,
            'c': c,
            'd': d,
            'x': x,
            'y': y,
            'fi': fi,
            'fb': fb,
            'r': r
        }

    def sendBillToMerchant(self, merchant, billn=-1):
        print(f'Customer: sending bill {billn} to merchant')
        reveal = merchant.whichChunksToReveal()

        # find the bill by billn
        if billn == -1:
            bill = self.bills[0]
        else:
            for bill in self.bills:
                if bill['billn'] == billn:
                    break

        # write to merch_verify.txt
        merch_verify = open('merch_verify.txt', 'w')
        for i in range(self.bank.k):
            chunki = bill['chunks'][i]
            if reveal[i] == '1':
                print('1', chunki['a'], chunki['c'], chunki['y'], chunki['r'], file=merch_verify)
            elif reveal[i] == '0':
                print('0', chunki['aXorI'], chunki['d'], chunki['x'], chunki['r'], file=merch_verify)
        merch_verify.close()
        print(f"Customer: save reveal chunk info to merch_verify.txt")

        # inform merchant to proceed
        valid = merchant.verifyAndDeposit('merch_verify.txt', signed=bill['signedfile'])



class Merchant:
    def __init__(self, bank) -> None:
        self.bank = bank
        self.acctNum = bank.createAccount()
        self.bills = []
        self.reveal = ''
        print(f"Merchant {self.acctNum} is created")

    def whichChunksToReveal(self):
        reveal = ''
        for i in range(self.bank.k):
            reveal = f"{reveal}{randrange(2)}"
        self.reveal = reveal
        print(f'Merchant: reveal {reveal}')
        return reveal

    def verifyAndDeposit(self, merch_verify='merch_verify.txt', signed='signed.txt'):
        # read the merch_verify info
        print('Merchant: verify the bill')
        verify_info = []
        with open(merch_verify) as f:
            for line in f:
                verify_info.append(line.strip().split())
        assert len(verify_info) == self.bank.k
        
        # read the signed.txt
        signatures = []
        with open(signed) as f:
            for line in f:
                signatures.append(int(line.strip()))
        assert len(signatures) == self.bank.k

        for i in range(self.bank.k):
            valid = self.bank.reveal1chunk(verify_info[i], signatures[i])
            if not valid:
                print('Merchant: chunk verification failed')
                return False
        
        # all chunks are verified, start to deposit to bank
        self.deposit(verify_info, signatures, 'deposit.txt')

        return True



    def deposit(self, chunkinfos, signatures, depositfile='deposit.txt'):
        print('Merchant: request deposit to bank')
        # inform bank to verify and deposit
        # deposit.txt includes all the chunk info Merchant received, and signature
        with open(depositfile, 'w') as f:
            for i in range(self.bank.k):
                # print(chunkinfos[i][0], chunkinfos[i][1], signatures[i], file=f)
                print(*chunkinfos[i], signatures[i], file=f)

        success = self.bank.depositMerchant(self.acctNum, depositfile='deposit.txt')
        if not success:
            print("Merchant: deposit request was declined by bank")
        else:
            self.bills.append({'chunks':chunkinfos, 'signatures': signatures})
        

def test_signature(bank):
    s = bank.createSignature(1234)
    valid = bank.verifySignature(1234, s)
    print(f"{s} is {valid}")

def Problem6Part6():
    print("\nMIT PRIMES CS 2023 Problem 6 Part 6:")
    bank = Bank()
    # test_signature(bank)
    alice = Customer(bank)
    bob = Merchant(bank)

    bill1 = alice.generateBill()
    bill2 = alice.generateBill()
    alice.sendBillToMerchant(bob, bill1)   # first time is valid
    alice.sendBillToMerchant(bob, bill1)   # double spend
    alice.sendBillToMerchant(bob, bill2)   # first time is valid
    alice.sendBillToMerchant(bob, bill2)   # double spend


# problem 6 part 6 in menu format
def Problem6Part6_Menu():
    print("\nMIT PRIMES CS 2023 Problem 6 Part 6:")
    bank = Bank()
    # test_signature(bank)
    alice = Customer(bank)
    bob = Merchant(bank)

    alice.generateBill()
    alice.sendBillToMerchant(bob)   # first time is valid
    alice.sendBillToMerchant(bob)   # double spend

if __name__ == '__main__':
    Problem1Part6()
    Problem1Part8()
    Problem1Part9()
    Problem2Part5()
    Problem3Part1()
    Problem5Part4()
    # test_HashFunction()
    Problem6Part6()
    # Problem6Part6_Menu()
