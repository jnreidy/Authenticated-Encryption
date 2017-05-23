import binascii
from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor

#operations on the 4 32-bit words
def qround(a, b, c, d):
    a = int(a, 16)
    b = int(b, 16)
    c = int(c, 16)
    d = int(d, 16)
    a += b
    d = d^a
    d = int((hex(d)[6:] + hex(d)[2:6]), 16)
    c += d
    b ^= c
    b = int((hex(b)[5:] + hex(b)[2:5]), 16)
    a += b
    d ^= a
    d = int((hex(d)[4:] + hex(d)[2:4]), 16)
    c += d
    b ^= c
    b = int((hex(b)[4:] + hex(b)[2:4]), 16)
    a = hex(a)[2:10]
    b = hex(b)[2:10]
    c = hex(c)[2:10]
    d = hex(d)[2:10]
    return (a, b, c, d)


#run a qround on each of the columns
def columnrounds(state):
    for i in range(4):
        (a, b, c, d) = qround(state[0+i], state[4+i], state[8+i], state[12+i])
        state[0+i] = a
        state[4+i] = b
        state[8+i] = c
        state[12+i] = d
    return state


#run a qround on each of the diagonals
def diagonalrounds(state):
    (a, b, c, d) = qround(state[0], state[5], state[10], state[15])
    state[0] = a
    state[5] = b
    state[10] = c
    state[15] = d
    (a, b, c, d) = qround(state[1], state[6], state[11], state[12])
    state[1] = a
    state[6] = b
    state[11] = c
    state[12] = d
    (a, b, c, d) = qround(state[2], state[7], state[8], state[13])
    state[2] = a
    state[7] = b
    state[8] = c
    state[13] = d
    (a, b, c, d) = qround(state[0], state[5], state[10], state[15])
    state[3] = a
    state[4] = b
    state[9] = c
    state[14] = d
    return state


#create the stream cipher
def chacha_block(key, nonce, counter):
    constants = '617078653320646e79622d32'
    string_state = constants + counter + key + nonce
    state = []
    for i in range(16):
        c = i*8
        state += [string_state[c:c+8]]
    current_state = state
    for i in range(10):
        current_state = columnrounds(current_state)
        current_state = diagonalrounds(current_state)
    end_state = ''
    for i in range(16):
        end_state += current_state[i]
    return hex(int(end_state, 16) + int(string_state, 16))[2:]

#encrypts plaintext up to 2^32*512 bits
#plaintext must be in hex form
def encrypt(key, nonce, plaintext):
    counter = '00000000'
    cipher_text = ''

    blocks = len(plaintext)//512
    for i in range(blocks):
        cipher_stream = chacha_block(key, nonce, counter)
        pt = plaintext[512*i:512*i+512]
        cipher_text += hex(int(pt, 16) ^ int(cipher_stream, 16))
        inc = hex(i)[2:]
        counter = counter[:-len(inc)] + inc
    if len(plaintext) % 512 != 0:
        cipher_stream_end = chacha_block(key, nonce, counter)
        cipher_text += hex(int(plaintext[blocks*512:], 16) ^ int(cipher_stream_end[:len(plaintext)%512], 16))
    return cipher_text


#AES CMAC Mode can only take an input of 32 bytes
#produces nonce that will be used for encrypt function
def CMAC(key, plaintext):
    bcipher = AES.new(key[0:16], AES.MODE_ECB)
    x = hex(int(binascii.hexlify(bcipher.encrypt(plaintext[0:16])), 16))
    key1 = plaintext[16:32] + key[16:32]
    tag = bcipher.encrypt(strxor(str.encode(x[2:]), str.encode(key1)))
    return hex(int(binascii.hexlify(tag), 16))[2:34]

