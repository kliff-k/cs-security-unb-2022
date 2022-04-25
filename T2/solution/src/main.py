# Imports
import base64
from local_aes import aes_process, aes_generate_symmetric_key_file
from local_rsa import rsa_encrypt_oaep, rsa_decrypt_oaep, rsa_sign, rsa_check_sign, rsa_generate_asymmetric_key_files

# Main function, captures user input and return the results
if __name__ == '__main__':

    # Start comunication session
    print("Iniciar sessão\n")
    input()

    # Generate RSA keys
    print('Gerando chaves assimétricas (RSA)')
    rsa_keys = rsa_generate_asymmetric_key_files('rsa', 1024)

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
    aes_key = aes_generate_symmetric_key_file('aes', 32)

    print("Chave geradas\n")
    input()

    # Cipher session key (RSA)
    print("Cifrando chave de simétrica de sessão (RSA)\n")
    rsa_ciphered_session_key = rsa_encrypt_oaep(aes_key.encode(), './messages/public_key_payload.txt', True)

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
    rsa_deciphered_session_key = rsa_decrypt_oaep(rsa_ciphered_payload, './keys/rsa_private.txt')

    print("Chave decifrada\n")
    input()

    # Capture user message
    message = input('Digite a mensagem a ser enviada:')
    print('')

    # Generate signature
    print("Gerando assinatura (RSA)")
    rsa_message_signature = rsa_sign(message, './keys/rsa_private.txt')

    # Cipher message (AES)
    print("Cifrando mensagem (AES CTR)")
    aes_ciphered_message = aes_process(message.encode(), rsa_deciphered_session_key)

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

    aes_deciphered_message = aes_process(aes_ciphered_payload, aes_key.encode())

    print(f"Mensagem decifrada:\n{aes_deciphered_message.decode()}")
    input()

    # Validade signature
    print("Verificando assinatura")
    if rsa_check_sign(int(rsa_payload_signature), aes_deciphered_message, './keys/rsa_public.txt'):
        print("Assinatura válida")
    else:
        print("Assinatura inválida")

    exit(0)
