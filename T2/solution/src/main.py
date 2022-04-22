# Imports
from aes_keys import make_asymmetric_key_file
from rsa_keys import make_symmetric_key_files
import aes_cipher
import rsa_cipher
import base64
import hashlib

# Public key
# AES_CTR_session_key(message)
# RSA_private_key(session_key)
# RSA_private_key(hash(message))

# TODO: Use f-strings everywhere
# TODO: Use with open(filename) as f: everywhere

# Main function, displays menu, captures user input and return the results
if __name__ == '__main__':

    # Start comunication session
    print("Iniciar sessão\n")
    input()

    # Generate RSA keys
    print('Gerando chaves assimétricas (RSA)')
    rsa_keys = make_symmetric_key_files('rsa', 1024)

    print("Chaves geradas\n")
    input()

    # Save payload to file
    print('Enviando chave pública para destinatário')
    payload = ",".join([str(value) for value in rsa_keys['public_key']]).encode()
    with open('./messages/public_key_payload.txt', 'wb') as f:
        f.write(base64.encodebytes(payload))

    print("Arquivo enviado\n")
    input()

    print("# -------- Destinatário -------- #")

    # Generate AES keys
    print("Arquivo recebido, gerando chave simétrica (AES)\n")
    aes_key = make_asymmetric_key_file('aes', 32)

    print("Chave geradas\n")
    input()

    # Cipher session key (RSA)
    print("Cifrando chave de simétrica de sessão (RSA)\n")
    rsa_ciphered_session_key = rsa_cipher.encrypt_oaep(aes_key.encode(), './messages/public_key_payload.txt', True)

    print("Chave cifrada\n")
    input()

    # Save payload to file
    print('Enviando chave simétrica para remetente')
    with open('./messages/session_key_payload.txt', 'wb') as f:
        f.write(base64.encodebytes(rsa_ciphered_session_key))

    print("Chave enviada\n")
    input()

    print("# -------- Remetente -------- #")

    print("Chave recebida, decifrando conteúdo (RSA)\n")
    with open('./messages/session_key_payload.txt', 'rb') as f:
        rsa_ciphered_payload = base64.decodebytes(f.read())
    rsa_deciphered_session_key = rsa_cipher.decrypt_oaep(rsa_ciphered_payload, './keys/rsa_private.txt')

    print("Chave decifrada\n")
    input()

    message = input('Digite a mensagem a ser enviada:')
    print('')

    # Generate message hash
    print("Calculando hash da mensagem (SHA3 512)")
    message_hash = int.from_bytes(hashlib.new("sha3_512", message.encode()).digest(), byteorder='big')

    # Cipher message hash (RSA)
    print("Gerando assinatura (RSA)")
    rsa_message_signature = rsa_cipher.sign(message_hash, './keys/rsa_private.txt')

    # Cipher message (AES)
    print("Cifrando mensagem (AES CTR)")
    aes = aes_cipher.AESModeOfOperationCTR(rsa_deciphered_session_key)
    aes_ciphered_message = aes.process(message)

    # Build payload
    payload = "$|$".encode().join([aes_ciphered_message, str(rsa_message_signature).encode()])

    # Save payload to file
    print('Enviando mensagem cifrada para o destinatário')
    with open('./messages/message_payload.txt', 'wb') as f:
        f.write(base64.encodebytes(payload))

    print("Arquivo enviado\n")
    input()

    print("# -------- Destinatário -------- #")

    print("Mensagem recebida, decifrando mensagem\n")

    # Recover and parse payload
    with open('./messages/message_payload.txt', 'rb') as f:
        payload = base64.decodebytes(f.read()).split("$|$".encode())

    (aes_ciphered_payload, rsa_payload_signature) = payload

    aes = aes_cipher.AESModeOfOperationCTR(aes_key.encode())
    aes_deciphered_message = aes.process(aes_ciphered_payload)

    print(f"Mensagem decifrada:\n{aes_deciphered_message.decode()}")
    input()

    # Generate message hash
    print("Calculando hash da mensagem (SHA3 512)")
    message_hash = int.from_bytes(hashlib.new("sha3_512", aes_deciphered_message).digest(), byteorder='big')
    check_payload_signature = rsa_cipher.check_sign(int(rsa_payload_signature), './keys/rsa_public.txt')

    print("Verificando assinatura")

    if message_hash == check_payload_signature:
        print("Assinatura válida")
    else:
        print("Assinatura inválida")

    exit(0)
