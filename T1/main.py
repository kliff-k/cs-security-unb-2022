# Imports
# re: Regular expressions used to match non alpha-ascii characters and clean up the message
# functools: Reduce used on several lists to help calculate sums
import re
import functools


# Encrypts/decrypts a given plain text using a key through Vigenere's cypher
def vigenere(raw_text, raw_key, operation):
    # Text and Key are changed into upper case to simplify the encryption / decryption
    text = raw_text.upper()
    key = raw_key.upper()

    # Keep count of characters skipped so the matrix used stays constant
    skipped_characters = 0

    # Ciphered/deciphered string
    message = ""

    # Go through each character in the text
    for index, value in enumerate(list(text.upper())):
        # Don't shift non-alphabetic ascii characters
        if not re.match("[a-zA-Z]", value):
            skipped_characters += 1
            message += value
            continue

        # Take the ascii value of the relevant key character
        key_character = ord(key[(index - skipped_characters) % len(key)])

        if operation == 'encode':
            # The ascii values of both text and key characters are added...
            character_value = (ord(value) + key_character)
        else:
            # ... or subtracted
            character_value = (ord(value) - key_character + 26)

        # modulo by the length of the alphabet;
        # added to the beginning of the (upper case) ascii alphabet position (A);
        # this way the new value can be found without building a static matrix
        message += chr(ord('A') + (character_value % 26))

    return message


# Recovers a Vigenere's cypher key using frequency analysis
def recover(raw_text, max_key_len, language='english'):
    slim = re.sub('[^a-zA-Z]+', '', raw_text).upper()
    key_len = estimate_key_length(slim, max_key_len)
    coset = cosets(slim, key_len)
    shifted_coset = []
    key = ""

    for value in coset:
        shifted_coset.append(coset_shift(value, language))
    for value in shifted_coset:
        key += chr(ord('A') + value)

    message = vigenere(raw_text, key, 'decrypt')
    return key, message


# Give an estimate of a potential key length of a cipher text. The algorithm
# works by finding which coset length has the greatest index of coincidence.
def estimate_key_length(cipher_text, max_len):
    index_array = [0] * max_len
    indices = []
    cis = []

    for index, value in enumerate(index_array):
        distributed_array = cosets(cipher_text, index + 1)
        for dist_index in distributed_array:
            cis.append(coincidence_index(dist_index))

        indices.append(functools.reduce(lambda a, b: a + b, cis, 0) / len(cis))

    return indices.index(max(indices)) + 1


# Split the ciperhtext into a given number of groups with the letters
# distributed uniformly in a sequential and round-robin fashion
def cosets(text, num):
    sets = [[] for _ in range(num)]
    chars = list(text)

    for index, value in enumerate(chars):
        sets[index % num].append(value)

    return sets


# Index of coincidence for a coset
def coincidence_index(coset):
    fc = frequency_count(coset)
    elements = []
    for value in fc:
        elements.append(value * (value - 1))

    element_sum = functools.reduce(lambda acc, x: acc + x, elements)

    return element_sum / (len(coset) * (len(coset) - 1))


# Frequency count of a coset
def frequency_count(coset):
    counts = [0] * 26
    for letter in coset:
        counts[ord(letter) - ord('A')] += 1

    return counts


# Computes the shift of a coset by finding the smallest chi-squared test
# against the actual frequency of letters in the english alphabet.
# Reference: https://pages.mtu.edu/~shene/NSF-4/Tutorial/VIG/Vig-Recover.html
def coset_shift(coset, language):
    if language == 'english':
        # English frequency
        freq = [
            0.08167,
            0.01492,
            0.02782,
            0.04253,
            0.12702,
            0.02228,
            0.02015,
            0.06094,
            0.06996,
            0.00153,
            0.00772,
            0.04025,
            0.02406,
            0.06749,
            0.07507,
            0.01929,
            0.00095,
            0.05987,
            0.06327,
            0.09056,
            0.02758,
            0.00978,
            0.0236,
            0.0015,
            0.01974,
            0.00074
        ]
    else:
        # Portuguese frequency
        freq = [
            0.1463,
            0.0104,
            0.0388,
            0.0499,
            0.1257,
            0.0102,
            0.0130,
            0.0128,
            0.0618,
            0.0040,
            0.0002,
            0.0278,
            0.0474,
            0.0505,
            0.1073,
            0.0252,
            0.0120,
            0.0653,
            0.0781,
            0.0434,
            0.0463,
            0.0167,
            0.0001,
            0.0021,
            0.0001,
            0.0047
        ]

    index_array = [0] * 26

    chi = []
    for index, value in enumerate(index_array):
        shift_array = []
        shift_codes = []
        fc_list = []
        shift = []
        for element in coset:
            shift_array.append(ord(element) - index)
        for element in shift_array:
            shift_codes.append(ord('Z') - ((ord('Z') - element) % 26))
        for element in shift_codes:
            shift.append(chr(element))

        fc = frequency_count(shift)

        for shift_index, element in enumerate(fc):
            fc_list.append((element / len(coset) - freq[shift_index]) ** 2 / freq[shift_index])

        chi.append(functools.reduce(lambda acc, x: acc + x, fc_list))

    return chi.index(min(chi))


if __name__ == '__main__':
    user_input = 0
    while not user_input:
        print('Escolha uma operação')
        print('1 - Encryptar')
        print('2 - Decryptar')
        print('3 - Recuperar chave')
        print('4 - Sair')
        user_input = input('Opção:')
        print('')

        match user_input:
            case '1':
                plain_text = input('Digite o texto a ser encriptado:')
                plain_key = input('Digite a chave a ser utilizada:')
                result = vigenere(plain_text, plain_key, 'encrypt')
                print('Mensagem encriptada:')
                print(f'{result}')
                print('')
                user_input = 0
            case '2':
                plain_text = input('Digite o texto a ser decriptado:')
                plain_key = input('Digite a chave a ser utilizada:')
                result = vigenere(plain_text, plain_key, 'decrypt')
                print('Mensagem decriptada:')
                print(f'{result}')
                print('')
                user_input = 0
            case '3':
                plain_text = input('Digite o texto a ser analisado:')
                plain_key_length = int(input('Digite o tamanho máximo da chave:'))
                plain_language = input('[Opcional] Linguagem da mensagem (english/portuguese) {Default = ENGLISH}:')
                plain_language = plain_language if plain_language != '' else 'english'
                recovered_key, result = recover(plain_text, plain_key_length, plain_language)
                print('Chave encontrada:')
                print(f'{recovered_key}')
                print('Mensagem decriptada:')
                print(f'{result}')
                print('')
                user_input = 0
            case '4':
                exit(0)
            case _:
                user_input = 0
                print('')
