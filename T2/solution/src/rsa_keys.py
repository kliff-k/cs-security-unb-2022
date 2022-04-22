import random
import os


# Returns the greatest common divisor of both a and b (Euclid's Algorithm)
def greatest_common_divisor(a, b):
    while a != 0:
        a, b = b % a, a

    return b


# Returns the modular inverse of a % m, which is the number x such that a * x % m = 1
def find_mod_inverse(a, m):
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
def rabin_miller(num):
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
def is_prime(num):
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
def generate_large_number(keysize=1024):
    return random.randrange(2 ** (keysize - 1), 2 ** keysize)


# Return a random prime number of keysize bits in size
def generate_large_prime(keysize=1024):
    while True:
        num = generate_large_number(keysize)
        if is_prime(num):
            return num


# Generates the private/public key pair
def generate_key(key_size):
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
def make_symmetric_key_files(name, key_size):

    public_key, private_key = generate_key(key_size)

    # Create keys directory if it does not exist
    os.makedirs(os.path.dirname('./keys'), exist_ok=True)

    # Save public key to file
    fo = open('./keys/%s_public.txt' % name, 'w')
    fo.write('%s,%s,%s' % (key_size, public_key[0], public_key[1]))
    fo.close()

    # Save private key to file
    fo = open('./keys/%s_private.txt' % name, 'w')
    fo.write('%s,%s,%s' % (key_size, private_key[0], private_key[1]))
    fo.close()

    return {
            'public_key': (key_size, public_key[0], public_key[1]),
            'private_key': (key_size, private_key[0], private_key[1])
            }
