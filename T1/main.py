import re
import functools


# Perform the vigenere cipher on given plaintext with a key
def encrypt(text, raw_key):
    key = raw_key.upper()
    skip_spaces = 0
    cypher = ""

    for index, value in enumerate(list(text.upper())):
        if not re.match("[a-zA-Z]", value):
            skip_spaces += 1
            cypher += value
            continue

        key_char = ord(key[(index - skip_spaces) % len(key)])
        c = (ord(value) + key_char) % 26
        cypher += chr(ord('A') + c)

    return cypher


# Decrypt vigenere ciphertext with a given key
def decrypt(text, raw_key):
    key = raw_key.upper()
    skip_spaces = 0
    message = ""

    for index, value in enumerate(list(text.upper())):
        if not re.match("[a-zA-Z]", value):
            skip_spaces += 1
            message += value
            continue

        key_char = ord(key[(index - skip_spaces) % len(key)])
        c = (ord(value) - key_char + 26) % 26
        message += chr(ord('A') + c)

    return message

# Frequency count of a coset
def frequency_count(coset):
    counts = [0] * 26
    for letter in coset:
        counts[ord(letter) - ord('A')] += 1

    return counts


# Computes the shift of a coset by finding the smallest chi-squared test
# against the actual frequency of letters in the english alphabet.
# Reference: https://pages.mtu.edu/~shene/NSF-4/Tutorial/VIG/Vig-Recover.html
def coset_shift(coset):
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

    # Portuguese frequency
    # freq = [
    #     0.1463,
    #     0.0104,
    #     0.0388,
    #     0.0499,
    #     0.1257,
    #     0.0102,
    #     0.0130,
    #     0.0128,
    #     0.0618,
    #     0.0040,
    #     0.0002,
    #     0.0278,
    #     0.0474,
    #     0.0505,
    #     0.1073,
    #     0.0252,
    #     0.0120,
    #     0.0653,
    #     0.0781,
    #     0.0434,
    #     0.0463,
    #     0.0167,
    #     0.0001,
    #     0.0021,
    #     0.0001,
    #     0.0047
    # ]

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

# Index of coincidence for a coset
def coincidence_index(coset):
    fc = frequency_count(coset)
    elements = []
    for value in fc:
        elements.append(value * (value - 1))

    element_sum = functools.reduce(lambda acc, x: acc + x, elements)

    return element_sum / (len(coset) * (len(coset) - 1))


# Split the ciperhtext into a given number of groups with the letters
# distributed uniformly in a sequential and round-robin fashion
def cosets(text, num):
    result = [[] for _ in range(num)]
    chars = list(text)

    for index, value in enumerate(chars):
        result[index % num].append(value)

    return result


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


def recover(cipher_text, max_key_len):
    slim = re.sub('[^a-zA-Z]+', '', cipher_text).upper()
    key_len = estimate_key_length(slim, max_key_len)
    coset = cosets(slim, key_len)
    shifted_coset = []
    key = ""

    for value in coset:
        shifted_coset.append(coset_shift(value))
    for value in shifted_coset:
        key += chr(ord('A') + value)

    plain_text = decrypt(cipher_text, key)
    return key, plain_text


if __name__ == '__main__':
    res = encrypt('asd zxc', 'hello')
    print(f'{res}')
    res = decrypt('hwo klj', 'hello')
    print(f'{res}')
    recovered_key, res = recover("""tpsja kexis ttgztpb wq ssmil tfdxf vsetw ytafrttw btzf pcbroxdzo zn tqac wix, bwfd s, je ahvup sd pcbqqxff lfzed d avu ytwoxavneh sg p aznst qaghv. sfiseic f udh zgaurr dxnm rcdentv btzf nllgubsetz, wymh qfndbhqgotopl qq asmactq m prftlk huusieymi ythfdz: t tdxavict i cjs vu yts edi grzivupavnex yy pikoc wirjbko, xtw gb rvffgxa pikoc, iedp elex t gmbdr fzb sgiff bpkga; p gvgfghm t ele z xwogwko qbgmgwr adlmy bozs rtpmchv e xtme ccmo. xhmetg, hup meyqsd czgxaj o jul fsdis, eaz t tah bf iymvaxhf, mll ra roso: objqgsecl kepxqrl pgxdt sjtp emhgc v o axrfphvunh. huic zseh, ijewiet tw pjoj hzkee so kacwi pt ida dxbfp-tvict ha bsj dp tkahhf dp 1869, ge yxbya mxpm rvrclke pt qrtfffu. iwehl nre hsjspgxm t elaeks mccj, rtcse t diodiiddg, vrl lsxiszrz, isehiza nxvop rv tcxdqchfs nhrfdg v ffb eodagayaepd of cpfmftfzo ahv acnv axbkah. cezp tquvcj! vpkhmss v qfx rmd vfugx gmghrs yxq mciecthw. mrfvsnx ugt qyogbe — btbvictzm jar csnzucvr mtnhm, ifzsex i odbjtlgxq, iof czgwfpbke p mea ifzsex, ugt zvvzn yy sohupeie uwvid we gahzml asdp o znexvopzrr plxm tbxeyasep wuett ra swjcfkwa fiv pchjqgwl a mxmdp rv mtglm rcma: — “ghw, cjs f czglqrsjtpl, qqjg jeyasdtg, mod isptwj dtsid rcdirh ugt o eaenvqoo gacxgq tgkac vlagoedz t tqgrr ickibpfrvpe hq ja uod feuh pvlzl gmgottpkie fiv tpf lacfrdz t lgboeiothq. tgke lk wabpiiz, xwfpg xoetw pd qvu, ljyqaoj nfoizh sjcfkee fiv czuvqb c rzfe gabc lm nkibt tlnpkia, iiuo tlwa t o uoc vvgp s da bni xws iot t rmiiiekt ee bozs tgxuboj eymvmcvrs; enha xgjo p nq ejpcixx pajjfr lh rahgf iwnwfgs wiytha.” qcd e qbix pazgz! gea, cof mp tvdtdvnoh hmh jznex ebdzzcpl ugt zye oxmjtw. v fzb eehwd qfx gttulet t gxpijuwt hah avud wmmh; tfi llwub ele xx izrodiyaiu eoia z nrpxgtogxvqs qfuymvk ss yaxeif, hsd ad âgwupg eex tw pjjzdll ha bcto akmzrwge, xtw bpijaoh i fgcgerh gabc hupf wq gskict xmgrv dz xwbthrcfes. fpfue p tfagfvctws. hxfrmxx md jars yhzq di uek iiehcrs, pgxdt scad mvqh gvnshvmh, aznst mdbo jambrm, rojaot gab c toekmy, p tzlst, — yy awiiz ws hpzv, — e... exrtpa ganbizrwr! dljyu p dfunh pttg uicxm cjsd ect e ftftetke etbyoct. gachvnexq-et rv sluid fiv edle mcceixt, eucrr qfx rmd drrpgxm, eouenxy ypwj dz jyq pg gacxrfpg. v vpkhmss, gaoxgqj arid. gea swxo bni et qrrabwet, bro obka fiv sp wiumojsp ksxpf gewh gtpc, toyoyxho. eex h qqj csieh idp qfidt exiodeymi pgodaebgm... ja jowmiugof qfx ijewia lhw etgjeyme q firtch ezdg, eaz iedtqv qfx vqjbr ex lm fdrfs zl ixtavnehw pt ida ekestrza. p wepd ele dbq, a fiv mpgse rcevtglm p sjsl tracwda pke meoieyme-xd. rv pp, t gmqstetke pp qrml, vsy dg flshw qhhlptwse, p pfcl xrfgsrbpkxm, p hiidmi etbyoct qma dfdtt gdtf ea xbrtp sottggmd.""", 20)
    print(f'{recovered_key}')
    print(f'{res}')

