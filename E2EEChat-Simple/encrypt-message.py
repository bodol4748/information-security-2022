from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
import base64

def decode_base64(b64):
    return base64.b64decode(b64)

def encode_base64(p):
    return base64.b64encode(p).decode('ascii')

def read_from_base64():
    return [ decode_base64(input()), input() ]

def pad_message(msg):
    # paded_msg = pad(msg, 16)
    BS = 16
    paded_msg = lambda m: msg + (BS - len(msg.encode('utf-8')) % BS) * chr(BS - len(msg.encode('utf-8')) % BS)
    # = msg.encode('utf-8') # 메세지 패딩 구현
    return paded_msg

def encrypt_message(key, iv, msg):
    # AES 256 암호화 구현
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return_msg = encode_base64(cipher.encrypt(msg))
    return return_msg

[secretkey, message] = read_from_base64()

message = pad_message(message)
randomiv = get_random_bytes(16) # 16바이트 (128비트 IV 랜덤 생성)

randomiv_str = encode_base64(randomiv)
cipher_str = encrypt_message(secretkey, randomiv, message)

print(randomiv_str + '!' + cipher_str)