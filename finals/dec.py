from hashlib import sha256
from Crypto.Cipher import AES
from base64 import standard_b64decode, standard_b64encode
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Random.random import randint
from Crypto.Util.Padding import pad, unpad
import subprocess

j = {
    "inc": [
        {
            "p": "h3rl/Q==",
            "g": "Ag==",
            "A": "QpFOyA=="
        },
        {
            "rpc": "6+lX9noxcSrRAnTbQMYdPg=="
        },
        {
            "rpc": "15AsYtxN//27mQ/lDUAJOjApyeXQx65dFso1oP7w8Qw="
        }
    ],
    "out": [
        {
            "B": "Ph6IeA=="
        },
        {
            "return": "GkSU2VwQyFe5Jt0Vd0cfxw=="
        },
        {
            "return": "TMxn+S2kBNd/4YsXYhtH0qgvBmUZiArgyTNOCqPsuFQOwcAo4SjQ4T4K14JvHvBX"
        }
    ]
}

def long_to_base64(n):
    return standard_b64encode(long_to_bytes(n)).decode()

def encrypt(cipher, msg):
    return standard_b64encode(cipher.encrypt(pad(msg, 16))).decode()

def base64_to_long(e):
    return bytes_to_long(standard_b64decode(e))

def decrypt(cipher, e):
    return unpad(cipher.decrypt(standard_b64decode(e)), 16)

p = base64_to_long(j['inc'][0]['p'])
g = base64_to_long(j['inc'][0]['g'])
A = base64_to_long(j['inc'][0]['A'])
print(p,g,A)
B = base64_to_long("Ph6IeA==")
print("B",B)
b = 620620105
print(pow(g,b,p))

shared = pow(A, b, p)
shared = sha256(long_to_bytes(shared)).digest()
cipher = AES.new(shared, AES.MODE_ECB)
print(decrypt(cipher, j['out'][1]['return']))
print(decrypt(cipher, j['out'][2]['return']))
exit(1)
print(pow(2,p))
print("Calculating done")

for i in range(2,p):
    if i % 10000 == 0:
        percent += 1
        print(percent,"% completed")
    val *= 2
    if val % p == true_B:
        print(i)
        break

