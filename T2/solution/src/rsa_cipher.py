import sys
import base64

# The block size must be less than or equal to the key size
DEFAULT_BLOCK_SIZE = 128  # 128 bytes
BYTE_SIZE = 256  # One byte has 256 different values.


def getBlocksFromText(message, blockSize=DEFAULT_BLOCK_SIZE):
    # Converts a string message to a list of block integers. Each integer
    # represents 128 (or whatever blockSize is set to) string characters.

    messageBytes = message.encode('ascii')  # convert the string to bytes

    blockInts = []
    for blockStart in range(0, len(messageBytes), blockSize):
        # Calculate the block integer for this block of text
        blockInt = 0
        for i in range(blockStart, min(blockStart + blockSize, len(messageBytes))):
            blockInt += messageBytes[i] * (BYTE_SIZE ** (i % blockSize))
        blockInts.append(blockInt)
    return blockInts


def getTextFromBlocks(blockInts, messageLength, blockSize=DEFAULT_BLOCK_SIZE):
    # Converts a list of block integers to the original message string.
    # The original message length is needed to properly convert the last
    # block integer.
    message = []
    for blockInt in blockInts:
        blockMessage = []
        for i in range(blockSize - 1, -1, -1):
            if len(message) + i < messageLength:
                # Decode the message string for the 128 (or whatever
                # blockSize is set to) characters from this block integer.
                asciiNumber = blockInt // (BYTE_SIZE ** i)
                blockInt = blockInt % (BYTE_SIZE ** i)
                blockMessage.insert(0, chr(asciiNumber))
        message.extend(blockMessage)
    return ''.join(message)


def encryptMessage(message, key, blockSize=DEFAULT_BLOCK_SIZE):
    # Converts the message string into a list of block integers, and then
    # encrypts each block integer. Pass the PUBLIC key to encrypt.
    encryptedBlocks = []
    n, e = key

    for block in getBlocksFromText(message, blockSize):
        # ciphertext = plaintext ^ e mod n
        encryptedBlocks.append(pow(block, e, n))
    return encryptedBlocks


def decryptMessage(encryptedBlocks, messageLength, key, blockSize=DEFAULT_BLOCK_SIZE):
    # Decrypts a list of encrypted block ints into the original message
    # string. The original message length is required to properly decrypt
    # the last block. Be sure to pass the PRIVATE key to decrypt.
    decryptedBlocks = []
    n, d = key
    for block in encryptedBlocks:
        # plaintext = ciphertext ^ d mod n
        decryptedBlocks.append(pow(block, d, n))
    return getTextFromBlocks(decryptedBlocks, messageLength, blockSize)


def readKeyFile(keyFilename):
    # Given the filename of a file that contains a public or private key,
    # return the key as a (n,e) or (n,d) tuple value.
    fo = open(keyFilename)
    content = fo.read()
    fo.close()
    keySize, n, EorD = content.split(',')
    return (int(keySize), int(n), int(EorD))


def encryptAndWriteToFile(messageFilename, keyFilename, message, blockSize=DEFAULT_BLOCK_SIZE):
    # Using a key from a key file, encrypt the message and save it to a
    # file. Returns the encrypted message string.
    keySize, n, e = readKeyFile('./keys/' + keyFilename + '_private.txt')

    # Check that key size is greater than block size.
    if keySize < blockSize * 8:  # * 8 to convert bytes to bits
        sys.exit(
            'ERROR: Block size is %s bits and key size is %s bits. The RSA cipher requires the block size to be equal to or greater than the key size. Either decrease the block size or use different keys.' % (
                blockSize * 8, keySize))

    # Encrypt the message
    encryptedBlocks = encryptMessage(message, (n, e), blockSize)

    # Convert the large int values to one string value.
    for i in range(len(encryptedBlocks)):
        encryptedBlocks[i] = str(encryptedBlocks[i])
    encryptedContent = ','.join(encryptedBlocks)

    # Write out the encrypted string to the output file.
    encryptedContent = '%s_%s_%s' % (len(message), blockSize, encryptedContent)
    fo = open(messageFilename, 'w')
    fo.write(encryptedContent)
    fo.close()
    # Also return the encrypted string.
    return encryptedContent


def readFromFileAndDecrypt(messageFilename, keyFilename):
    # Using a key from a key file, read an encrypted message from a file
    # and then decrypt it. Returns the decrypted message string.
    keySize, n, d = readKeyFile('./keys/' + keyFilename + '_public.txt')

    # Read in the message length and the encrypted message from the file.
    fo = open(messageFilename)
    content = fo.read()
    messageLength, blockSize, encryptedMessage = content.split('_')
    messageLength = int(messageLength)
    blockSize = int(blockSize)

    # Check that key size is greater than block size.
    if keySize < blockSize * 8:  # * 8 to convert bytes to bits
        sys.exit(
            'ERROR: Block size is %s bits and key size is %s bits. The RSA cipher requires the block size to be equal to or greater than the key size. Did you specify the correct key file and encrypted file?' % (
                blockSize * 8, keySize))

    # Convert the encrypted message into large int values.
    encryptedBlocks = []
    for block in encryptedMessage.split(','):
        encryptedBlocks.append(int(block))

    # Decrypt the large int values.
    return decryptMessage(encryptedBlocks, messageLength, (n, d), blockSize)


from math import sqrt, ceil
import os
import copy
import hashlib
import random
from typing import Tuple, Callable

Key = Tuple[int, int]


def readKeyFileRaw(keyFilename, decode_base=False):
    # Given the filename of a file that contains a public or private key,
    # return the key as a (n,e) or (n,d) tuple value.
    with open(keyFilename, 'rb') as f:
        if decode_base:
            content = base64.decodebytes(f.read()).decode()
        else:
            content = f.read().decode()

    keySize, n, EorD = content.split(',')
    return (int(EorD), int(n))


def euclid(a: int, b: int) -> int:
    '''Calculate the GCD of a and b using Euclid's algorithm'''
    while b != 0:
        a, b = b, a % b
    return a


def extend_euclid(a: int, b: int) -> int:
    '''Use Euclid's extended algorithm to calculate integer x, y that satisfies
    a * x + b * y = euclid(a, b)'''
    if b == 0:
        return 1, 0, a
    else:
        x, y, q = extend_euclid(b, a % b)
        return y, x - (a // b) * y, q


def modinv(a: int, b: int) -> int:
    '''Calculate the Modular Inverse'''
    # d * e = 1 (mod phi) <=> d * e + k * phi = 1
    x, y, q = extend_euclid(a, b)
    if q != 1:
        return None
    else:
        return x % b


def is_prime_trial_division(n: int) -> bool:
    '''Test if a given integer n is a prime number using trial division'''
    if n == 2:
        return True
    if n < 2 or n % 2 == 0:
        return False
    for i in range(3, ceil(sqrt(n)), 2):
        if n % i == 0:
            return False
    return True


# prime numbers with 1000
known_primes = [2] + \
               [x for x in range(3, 1000, 2) if is_prime_trial_division(x)]


def is_prime_miller_rabin(n: int, precision: int) -> bool:
    '''Test if a given integer n is a prime number using miller-rabin test
    https://rosettacode.org/wiki/Miller%E2%80%93Rabin_primality_test#Python:_Probably_correct_answers
    '''

    def try_composite(a, d, s):
        if pow(a, d, n) == 1:
            return False
        for i in range(s):
            if pow(a, pow(2, i) * d, n) == n - 1:
                return False
        return True

    if n % 2 == 0:
        return False
    d, s = n - 1, 0
    while d % 2 == 0:
        d, s = d >> 1, s + 1
    # Returns exact according to http://primes.utm.edu/prove/prove2_3.html
    if n < 1373653:
        return not any(try_composite(a, d, s) for a in known_primes[:2])
    if n < 25326001:
        return not any(try_composite(a, d, s) for a in known_primes[:3])
    if n < 118670087467:
        if n == 3215031751:
            return False
        return not any(try_composite(a, d, s) for a in known_primes[:4])
    if n < 2152302898747:
        return not any(try_composite(a, d, s) for a in known_primes[:5])
    if n < 3474749660383:
        return not any(try_composite(a, d, s) for a in known_primes[:6])
    if n < 341550071728321:
        return not any(try_composite(a, d, s) for a in known_primes[:7])
    return not any(try_composite(a, d, s) for a in known_primes[:precision])


def is_prime(n: int, precision: int = 16) -> bool:
    '''Test if a given integer is a prime number'''
    assert n > 0
    if n in known_primes:
        return True
    elif n < 100000:
        return is_prime_trial_division(n)
    else:
        return is_prime_miller_rabin(n, precision)


def keygen(p: int, q: int, e: int = None) -> Tuple[Key, Key]:
    '''Create public key (exponenet e, modulus n) and private key
    (exponent d, modulus n)'''
    assert is_prime(p) and is_prime(q)
    assert p != q
    n = p * q
    phi = (p - 1) * (q - 1)
    if e != None:
        assert euclid(phi, e) == 1
    else:
        while True:
            e = random.randrange(1, phi)
            if euclid(e, phi) == 1:
                break
    d = modinv(e, phi)
    return ((e, n), (d, n))


def get_key_len(key: Key) -> int:
    '''Get the number of octets of the public/private key modulus'''
    _, n = key
    return n.bit_length() // 8


def os2ip(x: bytes) -> int:
    '''Converts an octet string to a nonnegative integer'''
    return int.from_bytes(x, byteorder='big')


def i2osp(x: int, xlen: int) -> bytes:
    '''Converts a nonnegative integer to an octet string of a specified length'''
    return x.to_bytes(xlen, byteorder='big')


def sha1(m: bytes) -> bytes:
    '''SHA-1 hash function'''
    hasher = hashlib.sha1()
    hasher.update(m)
    return hasher.digest()


def mgf1(seed: bytes, mlen: int, f_hash: Callable = sha1) -> bytes:
    '''MGF1 mask generation function with SHA-1'''
    t = b''
    hlen = len(f_hash(b''))
    for c in range(0, ceil(mlen / hlen)):
        _c = i2osp(c, 4)
        t += f_hash(seed + _c)
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


def oaep_encode(m: bytes, k: int, label: bytes = b'',
                f_hash: Callable = sha1, f_mgf: Callable = mgf1) -> bytes:
    '''EME-OAEP encoding'''
    mlen = len(m)
    lhash = f_hash(label)
    hlen = len(lhash)
    ps = b'\x00' * (k - mlen - 2 * hlen - 2)
    db = lhash + ps + b'\x01' + m
    seed = os.urandom(hlen)
    db_mask = f_mgf(seed, k - hlen - 1, f_hash)
    masked_db = xor(db, db_mask)
    seed_mask = f_mgf(masked_db, hlen, f_hash)
    masked_seed = xor(seed, seed_mask)
    return b'\x00' + masked_seed + masked_db


def oaep_decode(c: bytes, k: int, label: bytes = b'',
                f_hash: Callable = sha1, f_mgf: Callable = mgf1) -> bytes:
    '''EME-OAEP decoding'''
    clen = len(c)
    lhash = f_hash(label)
    hlen = len(lhash)
    _, masked_seed, masked_db = c[:1], c[1:1 + hlen], c[1 + hlen:]
    seed_mask = f_mgf(masked_db, hlen, f_hash)
    seed = xor(masked_seed, seed_mask)
    db_mask = f_mgf(seed, k - hlen - 1, f_hash)
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


def encrypt(m: int, public_key: Key) -> int:
    '''Encrypt an integer using RSA public key'''
    e, n = public_key
    return pow(m, e, n)


def encrypt_raw(m: bytes, public_key: Key) -> bytes:
    '''Encrypt a byte array without padding'''
    k = get_key_len(public_key)
    c = encrypt(os2ip(m), public_key)
    return i2osp(c, k)


def encrypt_oaep(m: bytes, key_name: str, decode_base=False) -> bytes:
    '''Encrypt a byte array with OAEP padding'''
    public_key = readKeyFileRaw(key_name, decode_base)
    hlen = 20  # SHA-1 hash length
    k = get_key_len(public_key)
    assert len(m) <= k - hlen - 2
    return encrypt_raw(oaep_encode(m, k), public_key)


def decrypt(c: int, private_key: Key) -> int:
    '''Decrypt an integer using RSA private key'''
    d, n = private_key
    return pow(c, d, n)


def decrypt_raw(c: bytes, private_key: Key) -> bytes:
    '''Decrypt a cipher byte array without padding'''
    k = get_key_len(private_key)
    m = decrypt(os2ip(c), private_key)
    return i2osp(m, k)


def decrypt_oaep(c: bytes, key_name: str, raw=False) -> bytes:
    '''Decrypt a cipher byte array with OAEP padding'''
    if raw:
        key_raw = key_name.split(',')
        private_key = (int(key_raw[2]), int(key_raw[1]))
    else:
        private_key = readKeyFileRaw(key_name)

    k = get_key_len(private_key)
    hlen = 20  # SHA-1 hash length
    assert len(c) == k
    assert k >= 2 * hlen + 2
    return oaep_decode(decrypt_raw(c, private_key), k)


def sign(c: int, key_name: str) -> int:
    private_key = readKeyFileRaw(key_name)
    return decrypt(c, private_key)


def check_sign(c: int, key_name: str) -> int:
    public_key = readKeyFileRaw(key_name)
    return encrypt(c, public_key)
