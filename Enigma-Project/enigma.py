# Enigma Template Code for CNU Information Security 2022
# Resources from https://www.cryptomuseum.com/crypto/enigma

# This Enigma code implements Enigma I, which is utilized by 
# Wehrmacht and Luftwaffe, Nazi Germany. 
# This version of Enigma does not contain wheel settings, skipped for
# adjusting difficulty of the assignment.

from copy import deepcopy
from ctypes import ArgumentError

# Enigma Components
ETW = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

WHEELS = {
    "I" : {
        "wire": "EKMFLGDQVZNTOWYHXUSPAIBRCJ",
        "turn": 16
    },
    "II": {
        "wire": "AJDKSIRUXBLHWTMCQGZNPYFVOE",
        "turn": 4
    },
    "III": {
        "wire": "BDFHJLCPRTXVZNYEIWGAKMUSQO",
        "turn": 21
    }
}

UKW = {
    "A": "EJMZALYXVBWFCRQUONTSPIKHGD",
    "B": "YRUHQSLDPXNGOKMIEBFZCWVJAT",
    "C": "FVPJIAOYEDRZXWGCTKUQSBNMHL"
}

# Enigma Settings
SETTINGS = {
    "UKW": None,
    "WHEELS": [],
    "WHEEL_POS": [],
    "ETW": ETW,
    "PLUGBOARD": []
}

def apply_settings(ukw, wheel, wheel_pos, plugboard):
    if not ukw in UKW:
        raise ArgumentError(f"UKW {ukw} does not exist!")
    SETTINGS["UKW"] = UKW[ukw]

    wheels = wheel.split(' ')
    for wh in wheels:
        if not wh in WHEELS:
            raise ArgumentError(f"WHEEL {wh} does not exist!")
        SETTINGS["WHEELS"].append(WHEELS[wh])

    wheel_poses = wheel_pos.split(' ')
    for wp in wheel_poses:
        if not wp in ETW:
            raise ArgumentError(f"WHEEL position must be in A-Z!")
        SETTINGS["WHEEL_POS"].append(ord(wp) - ord('A'))
    
    plugboard_setup = plugboard.split(' ')
    for ps in plugboard_setup:
        if not len(ps) == 2 or not ps.isupper():
            raise ArgumentError(f"Each plugboard setting must be sized in 2 and caplitalized; {ps} is invalid")
        SETTINGS["PLUGBOARD"].append(ps)

# Enigma Logics Start

# Plugboard
def pass_plugboard(input):
    for plug in SETTINGS["PLUGBOARD"]:
        if str.startswith(plug, input):
            return plug[1]
        elif str.endswith(plug, input):
            return plug[0]
  
    return input

# ETW
def pass_etw(input):
    return SETTINGS["ETW"][ord(input) - ord('A')]

# Wheels
def pass_wheels(input, reverse = False):
    # Implement Wheel Logics
    # Keep in mind that reflected signals pass wheels in reverse order

    # reverse Yes or No
    wheel_order = [2, 1, 0]
    if (reverse) :
        wheel_order = [0, 1, 2]
    
    for wheel_num in wheel_order :
        if (reverse) :
            wheel = SETTINGS["WHEELS"][wheel_num]
            # print("it changed " , input , " to ")
            
            minus_pos = SETTINGS["WHEEL_POS"][wheel_order[wheel_num-1]]
            # print("minus_pos is " , minus_pos)

            input = wheel['wire'][ord(input) - ord('A') + SETTINGS["WHEEL_POS"][wheel_num] - minus_pos]
            input = wheel['wire'][wheel['wire'].find(input)]
            # print(SETTINGS["WHEEL_POS"][wheel_num] - minus_pos)
            # print(input)
        wheel = SETTINGS["WHEELS"][wheel_num]
        # print("it changed " , input , " to ")
        
        minus_pos = SETTINGS["WHEEL_POS"][wheel_order[wheel_num-1]]
        # print("minus_pos is " , minus_pos)

        input = wheel['wire'][ord(input) - ord('A') + SETTINGS["WHEEL_POS"][wheel_num] - minus_pos]
        # print(SETTINGS["WHEEL_POS"][wheel_num] - minus_pos)
        # print(input)
    return input

# UKW
def pass_ukw(input):
    return SETTINGS["UKW"][ord(input) - ord('A')]

# Wheel Rotation
def rotate_wheels():
    # Implement Wheel Rotation Logics

    # Wheel 1 rotate everytime when user push the Alpha key
    push_wheel_alpha(2)
    
    # When the wheel 1's turn and wheel 1's pos same, Wheel 2 rotate
    for index_of_wheels in range(0, 3) : 
        wheel_I = SETTINGS["WHEEL_POS"][2 - index_of_wheels]
        if wheel_I == SETTINGS["WHEELS"][2 - index_of_wheels]["turn"]:
            if 2 - index_of_wheels != 0 :
                push_wheel_alpha(index_of_wheels)

    pass

def push_wheel_alpha(wheel_I_count) :
    # print("Now wheel " , wheel_I_count , "is rotating ")
    # wire_alpha = SETTINGS["WHEELS"][wheel_I_count]["wire"] 
    # SETTINGS["WHEELS"][wheel_I_count]["wire"]  = wire_alpha[1:] + wire_alpha[0]
    # print(SETTINGS["WHEELS"][wheel_I_count]["wire"])
    SETTINGS["WHEEL_POS"][wheel_I_count] = SETTINGS["WHEEL_POS"][wheel_I_count] + 1
    if SETTINGS["WHEEL_POS"][wheel_I_count] == 26 :
        SETTINGS["WHEEL_POS"][wheel_I_count] == 0

# Enigma Exec Start
plaintext = input("Plaintext to Encode: ")
ukw_select = input("Set Reflector (A, B, C): ")
wheel_select = input("Set Wheel Sequence L->R (I, II, III): ")
wheel_pos_select = input("Set Wheel Position L->R (A~Z): ")
plugboard_setup = input("Plugboard Setup: ")

apply_settings(ukw_select, wheel_select, wheel_pos_select, plugboard_setup)

for ch in plaintext:
    rotate_wheels()

    encoded_ch = ch

    encoded_ch = pass_plugboard(encoded_ch)
    encoded_ch = pass_etw(encoded_ch)
    encoded_ch = pass_wheels(encoded_ch)
    encoded_ch = pass_ukw(encoded_ch)
    encoded_ch = pass_wheels(encoded_ch, reverse = True)
    encoded_ch = pass_plugboard(encoded_ch)

    print(encoded_ch, end='')
