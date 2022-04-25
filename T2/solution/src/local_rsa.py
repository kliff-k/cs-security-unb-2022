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

    low_primes = []

    for line in open("./primes/low_primes.txt", "r").readlines():
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

    # Create keys directory if it does not exist
    os.makedirs(os.path.dirname('./keys'), exist_ok=True)

    # Save public key to file
    with open(f'./keys/{name}_public.txt', 'w') as f:
        f.write('%s,%s,%s' % (key_size, public_key[0], public_key[1]))

    # Save private key to file
    with open(f'./keys/{name}_private.txt', 'w') as f:
        f.write('%s,%s,%s' % (key_size, private_key[0], private_key[1]))

    return {
        'public_key': (key_size, public_key[0], public_key[1]),
        'private_key': (key_size, private_key[0], private_key[1])
    }




# Given the filename of a file that contains a public or private key,
# return the key as a (n,e) or (n,d) tuple value.
def read_key_file(keyFilename, decode_base=False):
    with open(keyFilename, 'rb') as f:
        if decode_base:
            content = base64.decodebytes(f.read()).decode()
        else:
            content = f.read().decode()

    keySize, n, EorD = content.split(',')
    return (int(EorD), int(n))


def get_key_len(key: (int, int)) -> int:
    '''Get the number of octets of the public/private key modulus'''
    _, n = key
    return n.bit_length() // 8


def sha1(m: bytes) -> bytes:
    '''SHA-1 hash function'''
    hasher = hashlib.sha1()
    hasher.update(m)
    return hasher.digest()


def mgf1(seed: bytes, mlen: int) -> bytes:
    '''MGF1 mask generation function with SHA-1'''
    t = b''
    hlen = len(sha1(b''))
    for c in range(0, ceil(mlen / hlen)):
        _c = c.to_bytes(4, byteorder='big')
        t += sha1(seed + _c)
    return t[:mlen]


def xor(data: bytes, mask: bytes) -> bytes:
    '''Byte-by-byte XOR of two byte arrays'''
    masked = b''
    ldata = len(data)
    lmask = len(mask)
    for i in range(max(ldata, lmask)):
        if i < ldata and i < lmask:
            masked += (data[i] ^ mask[i]).to_bytes(1, byteorder='big')
        elif i < ldata:
            masked += data[i].to_bytes(1, byteorder='big')
        else:
            break
    return masked


def oaep_encode(m: bytes, k: int, label: bytes = b'') -> bytes:
    '''EME-OAEP encoding'''
    mlen = len(m)
    lhash = sha1(label)
    hlen = len(lhash)
    ps = b'\x00' * (k - mlen - 2 * hlen - 2)
    db = lhash + ps + b'\x01' + m
    seed = os.urandom(hlen)
    db_mask = mgf1(seed, k - hlen - 1)
    masked_db = xor(db, db_mask)
    seed_mask = mgf1(masked_db, hlen)
    masked_seed = xor(seed, seed_mask)
    return b'\x00' + masked_seed + masked_db


def oaep_decode(c: bytes, k: int, label: bytes = b'') -> bytes:
    '''EME-OAEP decoding'''
    clen = len(c)
    lhash = sha1(label)
    hlen = len(lhash)
    _, masked_seed, masked_db = c[:1], c[1:1 + hlen], c[1 + hlen:]
    seed_mask = mgf1(masked_db, hlen)
    seed = xor(masked_seed, seed_mask)
    db_mask = mgf1(seed, k - hlen - 1)
    db = xor(masked_db, db_mask)
    _lhash = db[:hlen]
    assert lhash == _lhash
    i = hlen
    while i < len(db):
        if db[i] == 0:
            i += 1
            continue
        elif db[i] == 1:
            i += 1
            break
        else:
            raise Exception()
    m = db[i:]
    return m


def encrypt(m: int, public_key: (int, int)) -> int:
    '''Encrypt an integer using RSA public key'''
    e, n = public_key
    return pow(m, e, n)


def encrypt_raw(m: bytes, public_key: (int, int)) -> bytes:
    '''Encrypt a byte array without padding'''
    k = get_key_len(public_key)
    c = encrypt(int.from_bytes(m, byteorder='big'), public_key)
    return c.to_bytes(k, byteorder='big')


def decrypt(c: int, private_key: (int, int)) -> int:
    '''Decrypt an integer using RSA private key'''
    d, n = private_key
    return pow(c, d, n)


def decrypt_raw(c: bytes, private_key: (int, int)) -> bytes:
    '''Decrypt a cipher byte array without padding'''
    k = get_key_len(private_key)
    m = decrypt(int.from_bytes(c, byteorder='big'), private_key)
    return m.to_bytes(k, byteorder='big')


def rsa_encrypt_oaep(m: bytes, key_name: str, decode_base=False) -> bytes:
    '''Encrypt a byte array with OAEP padding'''
    public_key = read_key_file(key_name, decode_base)
    hlen = 20  # SHA-1 hash length
    k = get_key_len(public_key)
    assert len(m) <= k - hlen - 2
    return encrypt_raw(oaep_encode(m, k), public_key)


def rsa_decrypt_oaep(c: bytes, key_name: str, raw: bool = False) -> bytes:
    '''Decrypt a cipher byte array with OAEP padding'''
    if raw:
        key_raw = key_name.split(',')
        private_key = (int(key_raw[2]), int(key_raw[1]))
    else:
        private_key = read_key_file(key_name)

    k = get_key_len(private_key)
    hlen = 20  # SHA-1 hash length
    assert len(c) == k
    assert k >= 2 * hlen + 2
    return oaep_decode(decrypt_raw(c, private_key), k)


def rsa_sign(message: str, key_name: str) -> int:
    message_hash = int.from_bytes(hashlib.new("sha3_512", message.encode()).digest(), byteorder='big')
    private_key = read_key_file(key_name)

    return decrypt(message_hash, private_key)


def rsa_check_sign(signature: int, message: str, key_name: str) -> bool:
    message_hash = int.from_bytes(hashlib.new("sha3_512", message).digest(), byteorder='big')
    public_key = read_key_file(key_name)

    return message_hash == encrypt(signature, public_key)
