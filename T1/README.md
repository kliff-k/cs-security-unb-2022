# Cifra de Vigenère

###### Hector Rocha Margittay - 19/0014172
###### Murilo da Silva Mascarenhas de Moraes - 16/0139180

## Cifra

Para cifrar/decifrar mensagens, primeiro nos limitamos a caracteres em caixa alta (upper case).
Após transformar o texto `raw_text` e chave `raw_key` em caixa alta, 
utilizamos um laço que percorre os caracteres do texto `text` verificando se o caractere é ascii alfabético.

Caso não seja, adicionamos ele sem tratamento na mensagem (de)codificada e incrementamos o contador
de caracteres ignorados `skipped_characters` para não interferir na posição das letras cifradas subsequentes.

Obtemos o valor ascii do caractere da chave `key_character` adequada para a posição atual (`ord(...)`) com base no seu índice menos a quantidade de caracteres ignorados.
Utilizando o módulo do tamanho da chave, percorremos todas as posições da chave em ródizio, de forma a simular a repetição
da chave até o tamanho da mensagem.

O resultado é somado ao valor ascii da letra atual da mensagem em caso de cifração, e subtraído (mais o tamanho do alfabeto) em caso de decifração.

Por fim, o módulo deste valor com o tamanho do alfabeto é somado à posição ascii do início da tabela ascii (`ord(A)`) a fim de
obter a nova posição da matriz de Vigenère, sem ter que construí-la manualmente e referencia-la.

O valor ascii é retornado para o seu caractere equivalente (`chr(...)`) e concatenado à mensagem.


```python
def vigenere(raw_text, raw_key, operation):
    text = raw_text.upper()
    key = raw_key.upper()
    skipped_characters = 0
    message = ""

    for index, value in enumerate(list(text.upper())):
        if not re.match("[a-zA-Z]", value):
            skipped_characters += 1
            message += value
            continue

        key_character = ord(key[(index - skipped_characters) % len(key)])

        if operation == 'encode':
            character_value = (ord(value) + key_character)
        else:
            character_value = (ord(value) - key_character + 26)

        message += chr(ord('A') + (character_value % 26))

    return message
```


## Ataque

O ataque utiliza análise de frequência para recuperar a chave com base em um texto cifrado.
Um tamanho máximo da chave é necessário para limitar as tentativas, assim como a linguagem esperada da mensagem
já que a frenquência das letras utilizadas são diferentes em cada língua. Assumimos inglês como padrão, porém 
português também pode ser passado como parâmetro.

Novamente reduzimos a mensagem a somente caracteres em caixa alta, e removemos os caracteres não cifrados.

Com o texto reduzido e o tamanho máximo da chave, estimamos o seu tamanho correto gerando co-conjuntos das
letras presentes no texto, de tamanho 1 até o máximo definido pelo usuário. Os co-conjuntos são analisados
para encontrar seu índice de coincidência[^1]. Selecionamos o co-conjunto com o maior índice como estimativa
do tamanho da chave.

Ao se obter o provável tamanho da chave, geramos co-conjuntos das letras presentes na mensagem com este tamanho .
Estes co-conjuntos são então deslocados até encontramos o menor valor do teste χ² (chi-quadrado)[^2] contra as frequências das
letras do alfabeto/linguagem.

Percorremos então a lista de cada índice obtido pelo teste, retornando seu valor para sua representação ascii,
recuperando (possivelmente) a chave utilizada.


```python
def recover(raw_text, max_key_length, language='english'):
    slim = re.sub('[^a-zA-Z]+', '', raw_text).upper()
    key_len = estimate_key_length(slim, max_key_length)
    coset = cosets(slim, key_len)
    shifted_coset = []
    key = ""

    for value in coset:
        shifted_coset.append(coset_shift(value, language))

    for value in shifted_coset:
        key += chr(ord('A') + value)

    message = vigenere(raw_text, key, 'decrypt')
    return key, message
```

## Considerações

* Não implementamos solução para UTF-8, logo, caracteres não-ascii são ignorados.
* Para simplificar o tratamento do input do usuário, as mensagens não suportam quebras de linha.
* Não tentamos descobrir qual é a lingua da mensagem, deixando o usuário informar ou descobrir na tentativa e erro.
  * Implementar uma lógica não desviaria muito do trabalho feito, já que poderiamos utilizar o texte χ² em todas as listas de frequências disponíveis ao programa (inglês/português) e selecionar o resultado que melhor pontua.
* O foco do projeto era não construir vetores estáticos (tanto para o comprimento da chave quanto a matriz de Vigenère), e automatizar o deslocamento dos co-conjuntos para não necessitar de participação do usuário (inspirado pela implementação de Nick Babcock)[^3]

[^1]: https://pt.wikipedia.org/wiki/Index_of_coincidence
[^2]: https://pages.mtu.edu/~shene/NSF-4/Tutorial/VIG/Vig-Recover.html
[^3]: https://vigenere.nickb.dev/
