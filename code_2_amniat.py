from multiprocessing import Process, Queue

IP = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
]

IP_INV = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
]

EXPANSION_TABLE = [
    32, 1, 2, 3, 4, 5, 4, 5,
    6, 7, 8, 9, 8, 9, 10, 11,
    12, 13, 12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21, 20, 21,
    22, 23, 24, 25, 24, 25, 26, 27,
    28, 29, 28, 29, 30, 31, 32, 1
]

PERMUTATION_TABLE = [
    16, 7, 20, 21, 29, 12, 28, 17,
    1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9,
    19, 13, 30, 6, 22, 11, 4, 25
]

SHIFTS = [
    1, 1, 2, 2, 2, 2, 2, 2,
    1, 2, 2, 2, 2, 2, 2, 1,
    1, 2, 2, 2, 2, 2  
]
S_BOX1 = [
    [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
    [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
    [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
    [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
]

S_BOX2 = [
    [1, 15, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
    [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
    [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
    [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
]

def generate_round_keys(key):
    round_keys = []
    for i in range(22):
        shift_amount = SHIFTS[i % len(SHIFTS)]
        shifted_key = key[shift_amount:] + key[:shift_amount]
        round_key = shifted_key[:48]
        round_keys.append(round_key)
    return round_keys


def initial_permutation(block):
    permutation = [block[idx - 1] for idx in IP]
    return permutation

def final_permutation(block):
    permutation = [block[idx - 1] for idx in IP_INV]
    return permutation

def expansion(block):
    expanded_block = [block[idx - 1] for idx in EXPANSION_TABLE]
    return expanded_block

def permutation(block):
    permuted_block = [block[idx - 1] for idx in PERMUTATION_TABLE]
    return permuted_block

def xor_blocks(block1, block2):
    return [b1 ^ b2 for b1, b2 in zip(block1, block2)]

def s_boxs(s_box, input_bits):
    row = (input_bits[0] << 1) + input_bits[5]
    col = (input_bits[1] << 3) + (input_bits[2] << 2) + (input_bits[3] << 1) + input_bits[4]
    return s_box[row][col]

def feistel_function(block, round_key):
    expanded_block = expansion(block)
    xored_block = xor_blocks(expanded_block, round_key)
    chunks = [xored_block[i:i+6] for i in range(0, len(xored_block), 6)]
    s_box1_output = [s_boxs(S_BOX1, chunk) for chunk in chunks[:4]]
    s_box2_output = [s_boxs(S_BOX2, chunk) for chunk in chunks[4:]]
    combined_s_box_output = s_box1_output + s_box2_output
    binary_output = [int(bit) for output in combined_s_box_output for bit in bin(output)[2:].zfill(4)]
    permuted_block = permutation(binary_output)
    return permuted_block

def Myencrypt(block, key):
    round_keys = generate_round_keys(key)
    block = initial_permutation(block)
    left_half = block[:32]
    right_half = block[32:]
    for round_num in range(22):
        new_right_half = xor_blocks(left_half, feistel_function(right_half, round_keys[round_num]))
        left_half = right_half
        right_half = new_right_half

    combined = final_permutation(right_half + left_half)
    return combined

def Mydecrypt(block, key):
    round_keys = generate_round_keys(key)
    block = initial_permutation(block)
    left_half = block[:32]
    right_half = block[32:]
    for round_num in range(21, -1, -1):
        new_right_half = xor_blocks(left_half, feistel_function(right_half, round_keys[round_num]))
        left_half = right_half
        right_half = new_right_half

    combined = final_permutation(right_half + left_half)
    return combined


def binary_to_hex(binary):
    binary_str = ''.join(map(str, binary))
    hex_str = hex(int(binary_str, 2))[2:].upper()
    return hex_str.zfill(len(binary_str) // 4)

def hex_to_binary(hex_str):
    binary_str = bin(int(hex_str, 16))[2:].zfill(len(hex_str) * 4)
    binary_list = list(map(int, binary_str))
    return binary_list

def plaintext_to_binary(plaintext):
    binary_string = ''.join(format(ord(char), '08b') for char in plaintext)
    padding_length = 64 - (len(binary_string) % 64)
    padded_binary_string = binary_string + '0' * padding_length
    return padded_binary_string


def My_encrypt_decrypt_block1(block1, key1, queue_encrypt, queue_decrypt):
    for i in range(0, len(block1), 64):
        block = block1[i:i+64]
        input_part1 = [int(bit) for bit in block]
        key_part1 = hex_to_binary(key1)
        encrypted_block1 = Myencrypt(input_part1, key_part1)
        encrypted_hex_block1 = binary_to_hex(encrypted_block1)
        queue_encrypt.put(encrypted_hex_block1)
        decrypted_block1 = Mydecrypt(encrypted_block1, key_part1)
        decrypted_str1 = binary_to_string(decrypted_block1)
        queue_decrypt.put(decrypted_str1)


def My_encrypt_decrypt_block2(block2, key2, queue_encrypt, queue_decrypt):
    for i in range(0, len(block2), 64):
        block = block2[i:i+64]
        input_part2 = [int(bit) for bit in block]
        key_part2 = hex_to_binary(key2)
        encrypted_block2 = Myencrypt(input_part2, key_part2)
        encrypted_hex_block2 = binary_to_hex(encrypted_block2)
        queue_encrypt.put(encrypted_hex_block2)
        decrypted_block2 = Mydecrypt(encrypted_block2, key_part2)
        decrypted_str2 = binary_to_string(decrypted_block2)
        queue_decrypt.put(decrypted_str2)


def binary_to_string(binary_list):
    binary_str = ''.join(map(str, binary_list))
    characters = [binary_str[i:i+8] for i in range(0, len(binary_str), 8)]
    return ''.join(chr(int(char, 2)) for char in characters)

def partition(plaintext,key):
   
    key1 = key[:16]
    key2 = key[16:]

    plaintext_binary = plaintext_to_binary(plaintext)
    queue_encrypt_block1 = Queue()
    queue_decrypt_block1 = Queue()
    queue_encrypt_block2 = Queue()
    queue_decrypt_block2 = Queue()
    
    process_block1 = Process(target=My_encrypt_decrypt_block1, args=(plaintext_binary[:64], key1, queue_encrypt_block1, queue_decrypt_block1))
    process_block2 = Process(target=My_encrypt_decrypt_block2, args=(plaintext_binary[64:], key2, queue_encrypt_block2, queue_decrypt_block2))

    process_block1.start()
    process_block2.start()

    process_block1.join()
    process_block2.join()

    encrypted_hex_block1 = queue_encrypt_block1.get()
    decrypted_str1 = queue_decrypt_block1.get()
    encrypted_hex_block2 = queue_encrypt_block2.get()
    decrypted_str2 = queue_decrypt_block2.get()



    print("plain text : ",plaintext)

    print("Encrypted Block 1:", encrypted_hex_block1)
    print("Encrypted Block 2:", encrypted_hex_block2)
    
    print("Decrypted Block 1:", decrypted_str1)
    print("Decrypted Block 2:", decrypted_str2)
    
    finalResult = decrypted_str1 + decrypted_str2
    
    print("Final Decrypted cyphertext:", finalResult)
    

if __name__ == "__main__":
    plaintext = "shahid beheshti"
    key = "1133457799BBCDFF2233457799BBCDFF"
    partition(plaintext, key)