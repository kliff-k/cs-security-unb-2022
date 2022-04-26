# Imports
import os
import base64
from local_aes import aes_process, aes_generate_symmetric_key_file
from local_rsa import rsa_encrypt_oaep, rsa_decrypt_oaep, rsa_sign, rsa_check_sign, rsa_generate_asymmetric_key_files


def sender_stage_1():
    print("\n# -------- Remetente -------- #\n")

    # Capture user message
    message = input("Digite a mensagem a ser enviada:")
    with open('./output/messages/raw_message.txt', 'w') as f:
        f.write(message)

    # Generate RSA keys
    print("Gerando chaves assimétricas (RSA)... ", end="")
    rsa_keys = rsa_generate_asymmetric_key_files("rsa", 1024)
    print("OK!")

    # Save payload to file
    print("Enviando chave pública para destinatário... ", end="")
    payload = ",".join([str(value) for value in rsa_keys['public_key']]).encode()
    with open('./output/messages/public_key_payload.txt', 'wb') as f:
        f.write(base64.encodebytes(payload))
    print("OK!")


def receiver_stage_1():
    print("\n# -------- Destinatário -------- #\n")

    # Generate AES keys
    print("Arquivo recebido, gerando chave simétrica (AES)... ", end="")
    aes_key = aes_generate_symmetric_key_file("aes", 32)
    print("OK!")

    # Cipher session key (RSA)
    print("Cifrando chave de simétrica de sessão (RSA)... ", end="")
    rsa_ciphered_session_key = rsa_encrypt_oaep(aes_key.encode(), "./output/messages/public_key_payload.txt")
    print("OK!")

    # Save payload to file
    print("Enviando chave simétrica para remetente... ", end="")
    with open("./output/messages/session_key_payload.txt", "wb") as f:
        f.write(base64.encodebytes(rsa_ciphered_session_key))
    print("OK!")


def sender_stage_2():
    print("\n# -------- Remetente -------- #\n")

    # Recover message
    with open('./output/messages/raw_message.txt', 'r') as f:
        message = f.read()

    # Decrypt session key
    print("Chave recebida, decifrando conteúdo (RSA)... ", end="")
    with open("./output/messages/session_key_payload.txt", "rb") as f:
        rsa_ciphered_payload = base64.decodebytes(f.read())
    rsa_deciphered_session_key = rsa_decrypt_oaep(rsa_ciphered_payload, "./output/keys/rsa_private.txt")
    print("OK!")

    # Generate signature
    print("Gerando assinatura (RSA)... ", end="")
    rsa_message_signature = rsa_sign(message, "./output/keys/rsa_private.txt")
    print("OK!")

    # Cipher message (AES)
    print("Cifrando mensagem (AES CTR)... ", end="")
    aes_ciphered_message = aes_process(message.encode(), rsa_deciphered_session_key)
    print("OK!")

    # Save payload to file
    print("Enviando mensagem cifrada para o destinatário... ", end="")
    payload = "$|$".encode().join([aes_ciphered_message, str(rsa_message_signature).encode()])
    with open("./output/messages/message_payload.txt", "wb") as f:
        f.write(base64.encodebytes(payload))
    print("OK!")


def receiver_stage_2():
    print("\n# -------- Destinatário -------- #\n")

    # Recover AES key
    with open('./output/keys/aes_session.txt', 'r') as f:
        aes_key = f.read()

    # Recover and parse payload
    print("Mensagem recebida, decifrando mensagem... ", end="")
    with open("./output/messages/message_payload.txt", "rb") as f:
        payload = base64.decodebytes(f.read()).split("$|$".encode())
    (aes_ciphered_payload, rsa_payload_signature) = payload
    aes_deciphered_message = aes_process(aes_ciphered_payload, aes_key.encode())
    print("OK!")

    print(f"\nMensagem decifrada: {aes_deciphered_message.decode()}\n")

    # Validate signature
    print("Verificando assinatura... ", end="")
    if rsa_check_sign(int(rsa_payload_signature), aes_deciphered_message, "./output/keys/rsa_public.txt"):
        print("Assinatura válida!")
    else:
        print("Assinatura inválida!")


# Main function, captures user input and return the results
if __name__ == '__main__':
    # Make required directories
    os.makedirs('./output', exist_ok=True)
    os.makedirs('./output/messages', exist_ok=True)
    os.makedirs('./output/keys', exist_ok=True)

    # Start communication session
    input("Pressione ENTER para iniciar sessão")

    sender_stage_1()

    input("Pressione ENTER para seguir o fluxo")

    receiver_stage_1()

    input("Pressione ENTER para seguir o fluxo")

    sender_stage_2()

    input("Pressione ENTER para seguir o fluxo")

    receiver_stage_2()

    # End communication session
    input("Pressione ENTER para finalizar sessão")
