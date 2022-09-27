# Simplified DES (Data Encryption Standard) 
# S-DES Algorithm Template Code for CNU Information Security 2022

# This code requires "bitarray" package.
# Install with: pip install bitarray

from ctypes import ArgumentError
import re
from bitarray import bitarray, util as ba_util

# Initial Permutation (IP)
IP = [ 1, 5, 2, 0, 3, 7, 4, 6 ]

# Inverse of Initial Permutation (or Final Permutation)
IP_1 = [ 3, 0, 2, 4, 6, 1, 7, 5]

# Expansion (4bits -> 8bits)
EP = [ 3, 0, 1, 2, 1, 2, 3, 0 ]

# SBox (S0)
S0 = [
    [ 1, 0, 3, 2 ],
    [ 3, 2, 1, 0 ],
    [ 0, 2, 1, 3 ],
    [ 3, 1, 3, 2 ]
]

# SBox (S1)
S1 = [
    [ 0, 1, 2, 3 ],
    [ 2, 0, 1, 3 ],
    [ 3, 0, 1, 0 ],
    [ 2, 1, 0, 3 ]
]

# Permutation (P4)
P4 = [ 1, 3, 2, 0 ]

# Permutation (P10)
P10 = [ 2, 4, 1, 6, 3, 9, 0, 8, 7, 5 ]

# Permutation (P8)
P8 = [ 5, 2, 6, 3, 7, 4, 9, 8 ]

#### DES Start

MODE_ENCRYPT = 1
MODE_DECRYPT = 2

'''
schedule_keys: generate round keys for round function
returns array of round keys.
keep in mind that total rounds of S-DES is 2.
'''
def schedule_keys(key: bitarray) -> [bitarray]:
    round_keys = []
    permuted_key = bitarray()

    for i in P10:
        permuted_key.append(key[i])
    # print("permuted_key : " , permuted_key)
    permuted_key_left = permuted_key[0:5]
    permuted_key_right = permuted_key[5:10]
    # print("permuted_key_left : " , permuted_key_left)
    # print("permuted_key_right : " , permuted_key_right)

    for i in range(1, 3):
        # shift for each round
        # round 1: shift 1, round 2: shift 2
        # shifting will be accumulated for each rounds
        permuted_key_left = permuted_key_left[i:] + permuted_key_left[0:i]
        permuted_key_right = permuted_key_right[i:] + permuted_key_right[0:i]

        # merge and permutate with P8
        merge_permutation = permuted_key_left + permuted_key_right
        round_key = bitarray()

        for j in P8:
            round_key.append(merge_permutation[j])

        round_keys.append(round_key)
    # print("round_keys : ", round_keys)
    return round_keys

'''
round: round function
returns the output of round function
'''
def round(text: bitarray, round_key: bitarray) -> bitarray:
    # implement round function
    expanded = bitarray()
    for i in EP:
        expanded.append(text[i])
    # print("len of expanded : ", len(expanded), " len of key : ", round_key)
    expanded ^= round_key

    # S0
    s0_row = expanded[0:4]
    s0_sel_row = (s0_row[0] << 1) + s0_row[3]
    s0_sel_col = (s0_row[1] << 1) + s0_row[2]
    s0_result = ba_util.int2ba(S0[s0_sel_row][s0_sel_col], length=2)

    # S1
    s1_row = expanded[4:8]
    s1_sel_row = (s1_row[0] << 1) + s1_row[3]
    s1_sel_col = (s1_row[1] << 1) + s1_row[2]
    s1_result = ba_util.int2ba(S1[s1_sel_row][s1_sel_col], length=2)

    pre_perm4 = s0_result + s1_result
    
    result = bitarray()
    for i in P4:
        result.append(pre_perm4[i])

    return result

'''
sdes: encrypts/decrypts plaintext or ciphertext.
mode determines that this function do encryption or decryption.
     MODE_ENCRYPT or MODE_DECRYPT available.
'''
def sdes(text: bitarray, key: bitarray, mode) -> bitarray:
    schedule = schedule_keys(key)
    # print('P8 : ', schedule[0], 'P8 again : ', schedule[1])
    subkey1 = schedule[0]
    subkey2 = schedule[1]

    result = bitarray()

    # 암호화를 하는 경우
    if mode == MODE_ENCRYPT :
        # Initial permutation of text
        permuted_text = bitarray()
        for i in range(0, len(IP)):
            permuted_text.append(text[IP[i]])
        # print("permuted_text : ", permuted_text)

        # First split
        permuted_text_left = permuted_text[:4]
        permuted_text_right = permuted_text[4:]
        # print("permuted_text_left : " , permuted_text_left)
        # print("permuted_text_right : " , permuted_text_right)

        # First Round
        first_round = round(permuted_text_right, subkey1)
        temp = permuted_text_right
        permuted_text_right = permuted_text_left ^ first_round
        permuted_text_left = temp

        # Second Round
        second_round = round(permuted_text_right, subkey2)
        temp_xor = bitarray()
        for i in range(0, len(second_round)) :
            temp_xor.append(second_round[i] ^ permuted_text_left[i])
        total = temp_xor + permuted_text_right

        for i in IP_1 :
            result.append(total[i])

    # 복호화를 하는 경우
    else :
        permuted_text = bitarray()
        for i in range(0, len(IP)):
            permuted_text.append(text[IP[i]])
        # print("permuted_text : ", permuted_text)

        # First split
        permuted_text_left = permuted_text[:4]
        permuted_text_right = permuted_text[4:]
        # print("permuted_text_left : ", permuted_text_left)
        # print("permuted_text_right : ", permuted_text_right)

        # First Round
        first_round = round(permuted_text_right, subkey2)
        temp = permuted_text_right
        permuted_text_right = permuted_text_left ^ first_round
        permuted_text_left = temp

        # Second Round
        second_round = round(permuted_text_right, subkey1)
        temp_xor = bitarray()
        for i in range(0, len(second_round)) :
            temp_xor.append(second_round[i] ^ permuted_text_left[i])
        total = temp_xor + permuted_text_right

        for i in IP_1:
            result.append(total[i])



    # Place your own implementation of S-DES Here
    
    return result

# def sw(total_bitary : bitarray) -> bitarray :
#     return total_bitary[4:] + total_bitary[:4]
#
# def make_number_for_sbox(half : bitarray, kind) -> list :
#     return [half[0] * 2 + half[3], half[1] * 2 + half[2]]
#
# def s1_or_s2(num1 : int, num2 : int, kindOfS : int) -> bitarray : # num1 이 가로 num2가 세로
#     result = bitarray()
#     if kindOfS == 0 :
#         find_num = S0[num1][num2]
#         result.append(find_num//2)
#         result.append(find_num%2)
#     else :
#         find_num = S1[num1][num2]
#         result.append(find_num//2)
#         result.append(find_num%2)
#     return result

#### DES Sample Program Start

plaintext = input("[*] Input Plaintext in Binary (8bits): ")
key = input("[*] Input Key in Binary (10bits): ")

# Plaintext must be 8 bits and Key must be 10 bits.
if len(plaintext) != 8 or len(key) != 10:
    raise ArgumentError("Input Length Error!!!")

if re.search("[^01]", plaintext) or re.search("[^01]", key):
    raise ArgumentError("Inputs must be in binary!!!")

bits_plaintext = bitarray(plaintext)
bits_key = bitarray(key)

print(f"Plaintext: {bits_plaintext}")
print(f"Key: {bits_key}")

result_encrypt = sdes(bits_plaintext, bits_key, MODE_ENCRYPT)

print(f"Encrypted: {result_encrypt}")

result_decrypt = sdes(result_encrypt, bits_key, MODE_DECRYPT)

print(f"Decrypted: {result_decrypt}, Expected: {bits_plaintext}")

if result_decrypt != bits_plaintext:
    print(f"S-DES FAILED...")
else:
    print(f"S-DES SUCCESS!!!")
