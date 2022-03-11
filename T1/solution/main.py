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
def recover(raw_text, max_key_length, language='english'):
    # Trims the text from non-cyphered characters
    slim = re.sub('[^a-zA-Z]+', '', raw_text).upper()

    # Estimates key length
    key_len = estimate_key_length(slim, max_key_length)

    # Generates co-sets of the text characters
    coset = cosets(slim, key_len)

    shifted_coset = []
    key = ""

    # Shift the co-sets to find each key character code
    for value in coset:
        shifted_coset.append(coset_shift(value, language))

    # Append each character back into the key string
    for value in shifted_coset:
        key += chr(ord('A') + value)

    # Return the key and deciphered message
    message = vigenere(raw_text, key, 'decrypt')
    return key, message


# Returns the estimated key length for a given text
# based on which co-set length displays the highest index of coincidence
def estimate_key_length(cypher_text, max_length):
    index_array = [0] * max_length
    coincidence_indexes = []
    total_index = []

    # Generates the co-set of cypher character for each possible key length
    # until the max defined length (max_length)
    for index, value in enumerate(index_array):
        distributed_array = cosets(cypher_text, index + 1)

        # Generates a list of coincidence indexes for each co-set
        for dist_index in distributed_array:
            coincidence_indexes.append(coincidence_index(dist_index))

        # Reduces the list of coincidence indexes summing its values
        total_index.append(
            functools.reduce(lambda acc, ele: acc + ele, coincidence_indexes, 0) / len(coincidence_indexes)
        )

    # Returns the highest index
    return total_index.index(max(total_index)) + 1


# Split the cypher text into a given number of groups with the letters
# distributed uniformly in a sequential and round-robin fashion
def cosets(text, num):
    # Matrix of sets
    sets = [[] for _ in range(num)]
    chars = list(text)

    # Sequential distribution
    for index, value in enumerate(chars):
        sets[index % num].append(value)

    return sets


# Returns the index of coincidence for a coset
# Reference: https://en.wikipedia.org/wiki/Index_of_coincidence
def coincidence_index(coset):
    # Obtains the frequency count for each character
    fc = frequency_count(coset)
    elements = []

    # Distribute frequency
    for value in fc:
        elements.append(value * (value - 1))

    # Sums the incidence
    element_sum = functools.reduce(lambda acc, ele: acc + ele, elements)

    return element_sum / (len(coset) * (len(coset) - 1))


# Frequency count of a co-set
def frequency_count(coset):
    counts = [0] * 26

    # Increment counter for each letter in the co-set
    for letter in coset:
        counts[ord(letter) - ord('A')] += 1

    return counts


# Computes the shift of a coset by finding the smallest chi-squared test
# against the actual frequency of letters in the alphabet.
# Reference: https://pages.mtu.edu/~shene/NSF-4/Tutorial/VIG/Vig-Recover.html
def coset_shift(coset, language):
    freq = []
    if language == 'english':
        # English letter frequency
        for line in open("frequencies/english.txt", "r").readlines():
            freq.append(float(line))
    else:
        # Portuguese letter frequency
        for line in open("frequencies/portuguese.txt", "r").readlines():
            freq.append(float(line))

    index_array = [0] * 26

    chi = []
    for index, value in enumerate(index_array):
        shift_array = []
        shift_codes = []
        fc_list = []
        shift = []

        # Shift elements by each letter
        for element in coset:
            shift_array.append(ord(element) - index)
        for element in shift_array:
            shift_codes.append(ord('Z') - ((ord('Z') - element) % 26))
        for element in shift_codes:
            shift.append(chr(element))

        fc = frequency_count(shift)

        # Chi-square test list
        for shift_index, element in enumerate(fc):
            fc_list.append((element / len(coset) - freq[shift_index]) ** 2 / freq[shift_index])

        # Sum test list
        chi.append(functools.reduce(lambda acc, x: acc + x, fc_list))

    # Return index of lower value (chi-squared test)
    return chi.index(min(chi))


# Main function, displays menu, captures user input and return the results
if __name__ == '__main__':
    user_input = 0

    # Main loop
    while not user_input:
        # Main menu
        print('Escolha uma operação')
        print('1 - Encryptar')
        print('2 - Decryptar')
        print('3 - Recuperar chave')
        print('4 - Sair')
        user_input = input('Opção:')
        print('')

        match user_input:
            # Encrypt
            case '1':
                plain_text = input('Digite o texto a ser encriptado:')
                plain_key = input('Digite a chave a ser utilizada:')
                result = vigenere(plain_text, plain_key, 'encrypt')
                print('Mensagem encriptada:')
                print(f'{result}')
                print('')
                user_input = 0
            # Decrypt
            case '2':
                plain_text = input('Digite o texto a ser decriptado:')
                plain_key = input('Digite a chave a ser utilizada:')
                result = vigenere(plain_text, plain_key, 'decrypt')
                print('Mensagem decriptada:')
                print(f'{result}')
                print('')
                user_input = 0
            # Recover key
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
            # Exit program
            case '4':
                exit(0)
            # Default (invalid option)
            case _:
                user_input = 0
                print('')
