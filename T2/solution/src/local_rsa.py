import os
import random
import base64
import hashlib
from math import ceil


# Returns the greatest common divisor of both a and b (Euclid's Algorithm)
def greatest_common_divisor(a: int, b: int) -> int:
    while a != 0:
        a, b = b % a, a

    return b


# Returns the modular inverse of a % m, which is the number x such that a * x % m = 1
def find_mod_inverse(a: int, m: int) -> int | None:
    # No modular inverse if a and m aren't relatively prime
    if greatest_common_divisor(a, m) != 1:
        return None

    u1, u2, u3 = 1, 0, a
    v1, v2, v3 = 0, 1, m

    while v3 != 0:
        q = u3 // v3
        v1, v2, v3, u1, u2, u3 = (u1 - q * v1), (u2 - q * v2), (u3 - q * v3), v1, v2, v3

    return u1 % m


# Checks if provided number is prime using Rabin-Miller Algorithm
def rabin_miller(num: int) -> bool:
    s = num - 1
    t = 0

    # While 's' is even, keep halving it and count how many times it was halved
    while s % 2 == 0:
        s = s // 2
        t += 1

    # Checks if the provided number isn't prime 5 times
    for trials in range(5):
        a = random.randrange(2, num - 1)
        v = pow(a, s, num)

        # Test is not applicable if 'v' is 1.
        if v != 1:
            i = 0
            while v != (num - 1):
                if i == t - 1:
                    return False
                else:
                    i = i + 1
                    v = (v ** 2) % num

        return True


# Checks is provided number is prime, first trying a quick prime number check before calling rabin_miller()
def is_prime(num: int) -> bool:
    # 0, 1, and negative numbers are not prime
    if num < 2:
        return False

    # Fetch low primes list
    low_primes = []
    for line in open("../primes/low_primes.txt", "r").readlines():
        low_primes.append(int(line))

    # If it's in the list, it's obviously (a small) prime
    if num in low_primes:
        return True

    # See if any of the low prime numbers can divide the provided number
    for prime in low_primes:
        if num % prime == 0:
            return False

    # rabin_miller() is finally called to determine if the provided number is prime
    return rabin_miller(num)


# Return a (pseudo) random number of keysize bits in size
def generate_large_number(keysize: int = 1024) -> int:
    return random.randrange(2 ** (keysize - 1), 2 ** keysize)


# Return a random prime number of keysize bits in size
def generate_large_prime(keysize: int = 1024) -> int:
    while True:
        num = generate_large_number(keysize)
        if is_prime(num):
            return num


# Generates the private/public key pair
def generate_key(key_size: int = 1024) -> tuple:
    # Create two prime numbers 'p' and 'q'
    p = generate_large_prime(key_size)
    q = generate_large_prime(key_size)

    # Calculate n = p * q
    n = p * q

    # Create a number e that is relatively prime to (p-1)*(q-1).
    while True:
        e = random.randrange(2 ** (key_size - 1), 2 ** key_size)
        if greatest_common_divisor(e, (p - 1) * (q - 1)) == 1:
            break

    # Calculate d, the mod inverse of e.
    d = find_mod_inverse(e, (p - 1) * (q - 1))
    public_key = (n, e)
    private_key = (n, d)

    return public_key, private_key


# Saves the private and public key files to disk
def rsa_generate_asymmetric_key_files(name: str, key_size: int = 1024) -> dict:
    public_key, private_key = generate_key(key_size)

    # Save public key to file
    with open(f'./output/keys/{name}_public.txt', 'wb') as f:
        f.write(base64.encodebytes(f'{key_size},{public_key[0]},{public_key[1]}'.encode()))

    # Save private key to file
    with open(f'./output/keys/{name}_private.txt', 'wb') as f:
        f.write(base64.encodebytes(f'{key_size},{private_key[0]},{private_key[1]}'.encode()))

    return {
        'public_key': (key_size, public_key[0], public_key[1]),
        'private_key': (key_size, private_key[0], private_key[1])
    }


# Reads the RSA key from a file and returns the info as a (size, n, e/d) tuple
def read_key_file(key_filename):
    with open(key_filename, 'rb') as f:
        content = base64.decodebytes(f.read()).decode()

    key_size, n, e_or_d = content.split(',')
    return int(key_size), int(n), int(e_or_d)


# SHA-1 hashing function for mask generation
def sha1(input_value: bytes) -> bytes:
    hasher = hashlib.sha1()
    hasher.update(input_value)
    return hasher.digest()


# Mask generation function for OAEP encoding
def mgf1(seed: bytes, mask_length: int) -> bytes:
    mask = b''
    hash_length = len(sha1(b''))
    for i in range(0, ceil(mask_length / hash_length)):
        mask += sha1(seed + i.to_bytes(4, byteorder='big'))

    return mask[:mask_length]


# XOR function of two byte arrays for OAEP encoding
def xor(data: bytes, mask: bytes) -> bytes:
    masked = b''
    data_length = len(data)
    mask_length = len(mask)
    for i in range(max(data_length, mask_length)):
        if i < data_length and i < mask_length:
            masked += (data[i] ^ mask[i]).to_bytes(1, byteorder='big')
        elif i < data_length:
            masked += data[i].to_bytes(1, byteorder='big')
        else:
            break

    return masked


# Apply optimal asymmetric encryption padding encoding to message
def oaep_encode(message: bytes, key_length: int) -> bytes:
    label_hash = sha1(b'')
    hash_length = len(label_hash)
    message_length = len(message)
    ps = b'\x00' * (key_length - message_length - 2 * hash_length - 2)
    db = label_hash + ps + b'\x01' + message
    seed = os.urandom(hash_length)
    db_mask = mgf1(seed, key_length - hash_length - 1)
    masked_db = xor(db, db_mask)
    seed_mask = mgf1(masked_db, hash_length)
    masked_seed = xor(seed, seed_mask)

    return b'\x00' + masked_seed + masked_db


# Remove optimal asymmetric encryption padding encoding from message
def oaep_decode(message: bytes, key_length: int) -> bytes:
    label_hash = sha1(b'')
    hash_length = len(label_hash)
    _, masked_seed, masked_db = message[:1], message[1:1 + hash_length], message[1 + hash_length:]
    seed_mask = mgf1(masked_db, hash_length)
    seed = xor(masked_seed, seed_mask)
    db_mask = mgf1(seed, key_length - hash_length - 1)
    db = xor(masked_db, db_mask)
    _lhash = db[:hash_length]
    i = hash_length
    while i < len(db):
        if db[i] == 0:
            i += 1
            continue
        else:
            i += 1
            break
    decoded_message = db[i:]

    return decoded_message


# Encrypt message using RSA public key
def encrypt(message: int, public_key: (int, int, int)) -> int:
    _, n, e = public_key

    return pow(message, e, n)


# Encrypt message using RSA private key
def decrypt(cipher: int, private_key: (int, int, int)) -> int:
    _, n, d = private_key

    return pow(cipher, d, n)


# Encrypt byte array without padding (OAEP)
def encrypt_raw(message: bytes, public_key: (int, int, int)) -> bytes:
    cipher = encrypt(int.from_bytes(message, byteorder='big'), public_key)

    return cipher.to_bytes(public_key[0] // 4, byteorder='big')


# Decrypt byte array without padding (OAEP)
def decrypt_raw(cipher: bytes, private_key: (int, int, int)) -> bytes:
    message = decrypt(int.from_bytes(cipher, byteorder='big'), private_key)

    return message.to_bytes(private_key[0] // 4, byteorder='big')


# Encrypt byte array with padding (OAEP)
def rsa_encrypt_oaep(message: bytes, key_name: str) -> bytes:
    public_key = read_key_file(key_name)

    return encrypt_raw(oaep_encode(message, public_key[0] // 4), public_key)


# Decrypt byte array with padding (OAEP)
def rsa_decrypt_oaep(cipher: bytes, key_name: str) -> bytes:
    private_key = read_key_file(key_name)

    return oaep_decode(decrypt_raw(cipher, private_key), private_key[0] // 4)


# Signs message (encrypts with private key)
def rsa_sign(message: str, key_name: str) -> int:
    message_hash = int.from_bytes(hashlib.new("sha3_512", message.encode()).digest(), byteorder='big')
    private_key = read_key_file(key_name)

    return decrypt(message_hash, private_key)


# Checks signature (encrypts with public key)
def rsa_check_sign(signature: int, message: bytes, key_name: str) -> bool:
    message_hash = int.from_bytes(hashlib.new("sha3_512", message).digest(), byteorder='big')
    public_key = read_key_file(key_name)

    return message_hash == encrypt(signature, public_key)
