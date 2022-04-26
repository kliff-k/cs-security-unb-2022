import os
import string
import random


# A counter object used to keep track of the value used by the AES CTR encryption / decryption
class Counter(object):
    def __init__(self, initial_value=1):

        # Convert the value into an array of bytes
        self._counter = [((initial_value >> i) % 256) for i in range(128 - 8, -1, -8)]

    value = property(lambda self: self._counter)

    # Increments the counter and ensures an overflow rolls it back to 0
    def increment(self):
        for i in range(len(self._counter) - 1, -1, -1):
            self._counter[i] += 1

            if self._counter[i] < 256:
                break

            # Carry the one
            self._counter[i] = 0

        # Overflow
        else:
            self._counter = [0] * len(self._counter)


def aes_generate_symmetric_key_file(name: str, key_size: int) -> str:
    # Key character list
    characters = list(string.ascii_letters + string.digits + "!@#$%^&*()")

    # Shuffles the characters
    random.shuffle(characters)

    # Picks random characters from the list
    password = []
    for i in range(key_size):
        password.append(random.choice(characters))

    # Shuffles the resultant password
    random.shuffle(password)

    # Converts the list to string and save to file
    with open(f'./output/keys/{name}_session.txt', 'w') as f:
        f.write("".join(password))

    # Returns password as string
    return "".join(password)


# Since AES is symmetric, the same process is used to encrypt / decrypt messages
def aes_process(plaintext: bytes, key: bytes) -> bytes:
    # The key length is important here
    if len(key) not in (16, 24, 32):
        raise ValueError('Invalid key size')

    counter = Counter()
    remaining_counter = []

    # Increments the counter for the encryption based on the key
    while len(remaining_counter) < len(plaintext):
        remaining_counter += counter.value
        counter.increment()

    # Encrypts and sends back the result in bytes
    encrypted = [(p ^ c) for (p, c) in zip(plaintext, remaining_counter)]

    return bytes(encrypted)
