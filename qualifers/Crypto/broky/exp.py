import os

os.chdir("./Crypto/broky")

from Crypto.PublicKey import RSA
from Crypto.Util.number import long_to_bytes, bytes_to_long

n = 174776634499365185044152993509362624036904353007427805459068176329835550069164957428014245129075350521665501113613732156274308708416158135093542590677545505977327257686941870374910044600757349485405575480034556717469583373661251050825191173966631184463407966953014469657004165922729869240061652972104818333329
e = 65537
p = 13220311437306051037966153711856858730980155743517642596833982288504794306032205070914072726758118520978501154561694973924426687814544691058721727225563177
q = p

#Utility functions
def egcd(a, b):
    '''
    Helper function for `modinv`.
    Implements the Extended Euclidean Algorithm (source: https://www.geeksforgeeks.org/multiplicative-inverse-under-modulo-m/)
    to get ax + by = gcd(a,b) and uses that equation to get
    result for modular inverse of a mod b.
    '''
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    '''
    Given a value `a` and `m`, find the modular inverse such that
    mod_inverse * a = 1 (mod m)
    '''
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m

phi = (p)*(p-1) #Different from normal RSA
d_old = modinv(e,phi)
#Alternatively...
d = pow(e,-1,phi)
print("d:",d)

print("[+] Performing checks")
assert(d_old==d)
assert(p*q==n)
assert(e*d%phi==1)

#Doesn't work due to p==q
#public_key = RSA.construct([n,e,d,p,q])
#print(public_key)
