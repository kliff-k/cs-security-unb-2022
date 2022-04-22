import os
import string
import random

# Key character list
characters = list(string.ascii_letters + string.digits + "!@#$%^&*()")


def make_asymmetric_key_file(name, key_size):
    # Shuffles the characters
    random.shuffle(characters)

    # Picks random characters from the list
    password = []
    for i in range(key_size):
        password.append(random.choice(characters))

    # Shuffles the resultant password
    random.shuffle(password)

    # Create keys directory if it does not exist
    os.makedirs(os.path.dirname('./keys'), exist_ok=True)

    # Converts the list to string and save to file
    fo = open('./keys/%s_session.txt' % name, 'w')
    fo.write('%s' % "".join(password))
    fo.close()

    return "".join(password)
