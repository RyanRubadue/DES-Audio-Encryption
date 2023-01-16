# Authored by Klayton Hacker, Ryan Rubadue

from ArrayData import *


# performs initial permutation on string of bits
def initial_permutation(state):
    update_state = ""
    for index in range(len(initial_permutation_table)):
        update_state = update_state + state[initial_permutation_table[index] - 1]
    return update_state


# performs final permutation on string of bits
def final_permutation(state):
    update_state = ""
    for index in range(len(final_permutation_table)):
        update_state = update_state + state[final_permutation_table[index] - 1]
    return update_state


# performs permutation (P-box) on string of bits
def p_box_permutation(state):
    update_state = ""
    for index in range(len(permutation_table)):
        update_state = update_state + state[permutation_table[index] - 1]
    return update_state


# performs permutation (P-box) on string of bits
def expansion(state):
    update_state = ""
    for index in range(len(expansion_table)):
        update_state = update_state + state[expansion_table[index] - 1]
    return update_state


# Shift each bit in s to the left num_shifts times
def shift_left(state, num_shifts):
    update_state = ""
    update_state += state[num_shifts: len(state)]
    update_state += state[0:num_shifts]
    return update_state


# Shift each bit in s to the right num_shifts times
def shift_right(state, num_shifts):
    update_state = ""
    update_state += state[len(state) - num_shifts: len(state)]
    update_state += state[0: len(state) - num_shifts]
    return update_state


def s_box(state):
    update_state = ""
    for index in range(0, len(state) - 5, 6):
        # row is outer 2 bits of the 6 bit section
        row = state[index] + state[index + 5]
        # column is inner 4 bits of 6 bit section
        column = state[index + 1:index + 5]

        s_box_num = int(index / 6)
        row_dec = int(row, 2)
        col_dec = int(column, 2)
        # get sbox val and append it in binary
        val_dec = s_box_tables[s_box_num][row_dec * 16 + col_dec]
        append = format(val_dec, "b")
        while len(append) < 4:
            append = str(0) + append
        update_state = update_state + append
    return update_state


# gets left half of string of bits
def get_left_bits(state):
    half_len = int(len(state) / 2)
    return state[:half_len]


# gets right half of string of bits
def get_right_bits(state):
    half_len = int(len(state) / 2)
    return state[half_len:]


# xor operation for two strings of binary
def xor(a, b):
    if len(a) != len(b):
        return "error"
    update_state = ""
    for index in range(len(a)):
        update_state += str(int(a[index] != b[index]))
    return update_state


# performs one round of des encryption
def des_round(state, subkey):
    left = get_left_bits(state)
    right = get_right_bits(state)

    # perform feistel structure with right bits
    right_update = expansion(right)
    right_update = xor(right_update, subkey)
    right_update = s_box(right_update)
    right_update = p_box_permutation(right_update)

    # xor left and function output
    left_update = xor(left, right_update)
    # swap left and right values return the state
    update_state = right + left_update
    return update_state


# # # # # # # # # # # # # # # # # # # #
# Below are mostly the key functions  #
# # # # # # # # # # # # # # # # # # # #


# performs initial permutation for keys on string of bits
def key_initial_permutation(key_state):
    update_state = ""
    for index in range(len(parity_bit_drop_table)):
        update_state = update_state + key_state[parity_bit_drop_table[index] - 1]
    return update_state


# performs compression permutation for keys on string of bits
def key_compression_permutation(key_state):
    update_state = ""
    for index in range(len(compression_table)):
        update_state = update_state + key_state[compression_table[index] - 1]
    return update_state


# generates a sub key based upon the round of DES its in
def sub_key_generator(round_num):
    key_state = key_initial_permutation(initial_key)
    left_state = get_left_bits(key_state)
    right_state = get_right_bits(key_state)
    for index in range(round_num):
        left_state = shift_left(left_state, shift_arr[index])
        right_state = shift_left(right_state, shift_arr[index])
    key_state = left_state + right_state
    sub_key = key_compression_permutation(key_state)
    return sub_key


def to_binary(string):
    letters = []
    for index in string:
        letters.append(ord(index))
    bin_str = ""
    for index in letters:
        letter_bin = str(int(bin(index)[2:]))
        while len(letter_bin) < 8:
            letter_bin = str(0) + letter_bin
        bin_str = bin_str + letter_bin
    return bin_str


def check_valid_hex(hexdata):
    if len(hexdata) != 16:
        return 0
    try:
        int(hexdata, 16)
        return 1
    except ValueError:
        return 0


def des_encryption(hexdata, demo):
    if not check_valid_hex(hexdata):
        return hexdata, 0
    scale = 16
    num_of_bits = 8
    bin_string = str(bin(int(hexdata, scale))[2:].zfill(num_of_bits))
    while len(bin_string) < 64:
        bin_string = str(0) + bin_string

    init = initial_permutation(bin_string)
    if demo:
        print("\nInitial Permutation:", hex(int(init, 2)), "\n")

    # 16 rounds of DES
    state = init
    for index in range(16):
        state = des_round(state, sub_key_generator(index + 1))
        if demo:
            print("Round", index+1, ": ", hex(int(state, 2)))

    # final swap left and right
    left = get_left_bits(state)
    right = get_right_bits(state)
    state = right + left
    # print("Round", 16, ": ", hex(int(state, 2)))

    state = final_permutation(state)

    decimal_representation = int(state, 2)
    hex_string = str(hex(decimal_representation))[2:]
    return hex_string, 1


def des_decryption(hexdata, demo):
    scale = 16
    num_of_bits = 8
    bin_string = str(bin(int(hexdata, scale))[2:].zfill(num_of_bits))
    while len(bin_string) < 64:
        bin_string = str(0) + bin_string

    init = initial_permutation(bin_string)

    # 16 rounds of DES
    state = init
    for index in range(16, 0, -1):
        state = des_round(state, sub_key_generator(index))
        if demo:
            print("Round", (16 - index) % 16 + 1, ": ", hex(int(state, 2)))

    # final swap left and right
    left = get_left_bits(state)
    right = get_right_bits(state)
    state = right + left

    state = final_permutation(state)

    decimal_representation = int(state, 2)
    hex_string = str(hex(decimal_representation))[2:]
    return hex_string


def demoDES():
    plain_text = "675a69675e5a6b5a"
    print("Plain Text: ", plain_text)
    print("Key: ", initial_key)

    cypher_text, _ = des_encryption(plain_text, 1)
    print("\nEncrypted Hex String: ", cypher_text, "\n\n")

    decrypted_cypher_text = des_decryption(cypher_text, 1)
    print("\nDecrypted Hex String: ", decrypted_cypher_text)
