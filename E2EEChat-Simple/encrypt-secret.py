from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

def decode_base64(b64):
    return base64.b64decode(b64)

def encode_base64(p):
    return base64.b64encode(p).decode('ascii')

def read_from_base64():
    return [ decode_base64(input()), decode_base64(input()) ]

def encrypt_secret(secret, pubkey):
    # PKCS#1 OAEP를 이용한 RSA 암호화 구현
    print("secret")
    print(secret)
    print(type(secret))
    key = RSA.import_key(pubkey)
    cipher = PKCS1_OAEP.new(key)
    return_str = cipher.encrypt(secret)
    return_str = encode_base64(return_str)
    print("====encrypt secret return_str : ========")
    print(return_str)
    print(type(return_str))
    return return_str

[secret, pubkey] = read_from_base64()
cipher_str = encrypt_secret(secret, pubkey)

print(cipher_str)