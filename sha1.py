import numpy as np

# Resources: https://md5decrypt.net/en/Sha1/#answer
# https://en.wikipedia.org/wiki/SHA-1
# https://www.metamorphosite.com/one-way-hash-encryption-sha1-data-software




def decimalToBinaryFixLength(_length, _decimal):
	binNum = bin(int(_decimal))[2:]
	outputNum = [int(item) for item in binNum]
	if len(outputNum) < _length:
		outputNum = np.concatenate((np.zeros((_length-len(outputNum),)),np.array(outputNum)))
	else:
		outputNum = np.array(outputNum)
	return [int(i) for i in outputNum]

def binarytoint(bi):
    return int(''.join([str(i) for i in bi]), 2)

def leftRotate(n, d):  
    return n[d:] + n[:d]

def SHA1(message):
    hex_message = []
    for i in message:
        hex_message.append(ord(i))
    hex_message.append(0x80)
    for i in range(len(hex_message)):
        hex_message[i] = decimalToBinaryFixLength(8, hex_message[i])
    A = 0x67452301
    B = 0xefcdab89
    C = 0x98badcfe
    D = 0x10325476
    E = 0xc3d2e1f0
    buffer = [decimalToBinaryFixLength(32, A), decimalToBinaryFixLength(32, B), decimalToBinaryFixLength(32, C), \
        decimalToBinaryFixLength(32, D), decimalToBinaryFixLength(32, E)]
    #print(buffer)
    while (len(hex_message) * 8) % 512 != 448:
        hex_message.append(decimalToBinaryFixLength(8, 0x00))
    #print(hex_message)
    length = decimalToBinaryFixLength(64, len(message)*8)
    for i in range(8):
        hex_message.append(length[8*i:8*i+8])
    #print(len(hex_message), hex_message)

    chunks = int((len(hex_message) * 8) / 512)
       

    for i in range(chunks):
        chunk = hex_message[i*64:i*64+64]
        words = []
        j = 0 
        while j < len(chunk):
            words.append(chunk[j] + chunk[j+1] + chunk[j+2] + chunk[j+3])
            j += 4
        #print(len(words), words)

        for i in range(16, 80):
            words.append(leftRotate([(words[i-3][j]^words[i-8][j]^words[i-14][j]^words[i-16][j]) for j in range(32)], 1))

        #for i, j in enumerate(words):
        #    print(str(i) + ": " + ''.join([str(k) for k in j]))        

        #print(len(words), words)

        a = buffer[0]
        b = buffer[1]
        c = buffer[2]
        d = buffer[3]
        e = buffer[4]


        for i in range(80):
            if 0 <= i and i <= 19:
                f = [(b[i] and c[i]) or ((not b[i]) and d[i]) for i in range(32)]
                k = decimalToBinaryFixLength(32, 0x5A827999)
            elif 20 <= i and i <= 39:
                f = [(b[i] ^ c[i]) ^ d[i] for i in range(32)]
                k = decimalToBinaryFixLength(32, 0x6ED9EBA1)
            elif 40 <= i and i <= 59:
                f = [(b[i] and c[i]) or (b[i] and d[i]) or (c[i] and d[i]) for i in range(32)] 
                k = decimalToBinaryFixLength(32, 0x8F1BBCDC)
            else:
                f = [(b[i] ^ c[i]) ^ d[i] for i in range(32)]
                k = decimalToBinaryFixLength(32, 0xCA62C1D6)

            f = [int(i) for i in f]
            temp = leftRotate(a, 5)
            #print(temp, binarytoint(temp), f)
            temp = binarytoint(temp) + binarytoint(f)
            temp = decimalToBinaryFixLength(32, temp)
            temp = [1] * (33 - len(temp)) + temp

            temp = binarytoint(temp) + binarytoint(e)
            temp = decimalToBinaryFixLength(34, temp)
            temp = [1] * (34 - len(temp)) + temp

            temp = binarytoint(temp) + binarytoint(k)
            temp = decimalToBinaryFixLength(35, temp)
            temp = [1] * (35 - len(temp)) + temp

            temp = binarytoint(temp) + binarytoint(words[i])
            temp = decimalToBinaryFixLength(36, temp)
            temp = [1] * (36 - len(temp)) + temp

            temp = temp[4:]

            e = d.copy()
            d = c.copy()
            c = leftRotate(b, 30).copy()
            b = a.copy()
            a = temp.copy()


        buffer[0] = decimalToBinaryFixLength(32, binarytoint(buffer[0]) + binarytoint(a))
        buffer[0] = buffer[0][len(buffer[0]) - 32:]
        buffer[1] = decimalToBinaryFixLength(32, binarytoint(buffer[1]) + binarytoint(b))
        buffer[1] = buffer[1][len(buffer[1]) - 32:]
        buffer[2] = decimalToBinaryFixLength(32, binarytoint(buffer[2]) + binarytoint(c))
        buffer[2] = buffer[2][len(buffer[2]) - 32:]
        buffer[3] = decimalToBinaryFixLength(32, binarytoint(buffer[3]) + binarytoint(d))
        buffer[3] = buffer[3][len(buffer[3]) - 32:]
        buffer[4] = decimalToBinaryFixLength(32, binarytoint(buffer[4]) + binarytoint(e))
        buffer[4] = buffer[4][len(buffer[4]) - 32:]
        #print(buffer[0], len(buffer[0]))
        #print(buffer[1], len(buffer[1]))
        #print(buffer[2], len(buffer[2]))
        #print(buffer[3], len(buffer[3]))
        #print(buffer[4], len(buffer[4]))

    # NEED TO PAD HEX
    a = hex(binarytoint(buffer[0])).replace("0x", "") 
    b = hex(binarytoint(buffer[1])).replace("0x", "") 
    c = hex(binarytoint(buffer[2])).replace("0x", "") 
    d = hex(binarytoint(buffer[3])).replace("0x", "")
    e = hex(binarytoint(buffer[4])).replace("0x", "")
    #print(len(a), a, len(b), b, len(c), c, len(d), d, len(e), e)
    ret = a + b + c + d + e
    return ret





if __name__ == "__main__":
    t = SHA1("A Test")
    print(t)
    i = input()
    print(SHA1(i))
