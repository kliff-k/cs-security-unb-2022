# Comunicação por cryptosistema híbrido

###### Hector Rocha Margittay - 19/0014172
###### Murilo da Silva Mascarenhas de Moraes - 16/0139180

## AES CTR + RSA (OEAP)

### Comunicação

O sistema foi estruturado como uma pequena demonstração de comunicação entre dois participantes (remetente e destinatário) utilizando um cryptosistema híbrido.
RSA será utilizado para o envio seguro de uma chave de sessão (AES) que será utilizada para comunicações subsequentes.

Para simular a comunicação sem ter que executar diversos binários, todas as mensagens serão "enviadas" por arquivo.
Cada etapa está contida em uma função própria para que nenhum resultado seja utilizado fora do seu escopo, garantindo que cada mensagem seja devidamente estruturada e interpretada.

#### Etapa 1:

Após capturar a mensagem que será cifrada e eventualmente enviada para o usuário em etapa futura, geramos o par de chaves publica/privada.
Para este fim, geramos 2 números pseudo aleatórios de um tamanho mínimo (1024 bits).
Checamos a primalidade destes números primeiramente com uma divisão por primos pequenos, e depois seguimos com o algorítimo de Miller-Rabin[^1].

```python
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
```

Em caso de falha, o processo é repetido até o par de primos `p,q` for encontrado.
`n` é então definido como o produto de `p,q`, 
`e` por meio de geração aleatória até encontramos um primo relativo a `p,q`,
 por fim `d` é composto do inverso multiplicativo modular entre `e, (p - 1) * (q - 1)`

```python
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
```

As chaves são estruturadas como `{tamanhoDaChave},{n},{e_ou_d}` e salvas na pasta `./keys/`.
"Enviamos" a chave pública, codificando-a em base64 no arquivo `public_key_payload.txt` dentro da pasta `/messages/`.

#### Etapa 2:

Geramos uma chave de sessão de 32 caracteres para ser utilizada na comunicação entre os 2 participantes usando um embaralhamento simples de caracteres.

```python
    # Key character list
    characters = list(string.ascii_letters + string.digits + "!@#$%^&*()")

    # Shuffles the characters
    random.shuffle(characters)
    
    # Picks random characters from the list
    password = []
    for i in range(key_size):
        password.append(random.choice(characters))
```

Encriptamos esta chave (`session_key`) usando a chave pública enviada previamente da forma `mensagem^e mod n`.
OAEP[^2] (optimal asymmetric encryption padding) é utilizado na mensagem antes da cifração.

```python
def oaep_encode(message: bytes, key_length: int) -> bytes:
    label_hash = sha1(b'')
    hash_length = len(label_hash)
    message_length = len(message)
    ps = b'\x00' * (key_length - message_length - 2 * hash_length - 2)
    db = label_hash + ps + b'\x01' + message
    seed = os.urandom(hash_length)
    db_mask = mgf1(seed, key_length - hash_length - 1)
    masked_db = xor(db, db_mask)
    seed_mask = mgf1(masked_db, hash_length)
    masked_seed = xor(seed, seed_mask)

    return b'\x00' + masked_seed + masked_db
```

A chave cifrada é enviada de volta para o remetente, novamente codificada em base64 (`session_key_payload.txt`).

#### Etapa 3:

A assinatura da mensagem é gerada cifrando o hash da mensagem (`sha3 512 bits`) com a chave privada.

```python
# Signs message (encrypts with private key)
def rsa_sign(message: str, key_name: str) -> int:
    message_hash = int.from_bytes(hashlib.new("sha3_512", message.encode()).digest(), byteorder='big')
    private_key = read_key_file(key_name)

    return encrypt(message_hash, private_key)
```

A chave de sessão é decifrada com a chave privada na forma `cifra^d mod n`.

Esta chave é então utilizada para cifrar a mensagem original e sua assinatura concatenada utilizando AES-CTR[^3] (Counter Mode).

```python
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
```

O resultado é "enviado" para o destinatário original, codificado em base64 (`message_payload.txt`).

#### Etapa 4:

Finalmente, o payload é decodificado usando utilizando o mesmo método AES, já que ele é simétrico.

Separando a assinatura da mensagem original, podemos encripta-la utilizando a chave pública, e comparar com o hash da mensagem calculado localmente.

```python
# Checks signature (encrypts with public key)
def rsa_check_sign(signature: int, message: bytes, key_name: str) -> bool:
    message_hash = int.from_bytes(hashlib.new("sha3_512", message).digest(), byteorder='big')
    public_key = read_key_file(key_name)

    return message_hash == encrypt(signature, public_key)
```

Caso sejam iguais, a assinatura é genuina.

[^1]: http://inventwithpython.com/hacking/chapter24.html
[^2]: https://gist.github.com/ppoffice/e10e0a418d5dafdd5efe9495e962d3d2
[^3]: https://github.com/ricmoo/pyaes