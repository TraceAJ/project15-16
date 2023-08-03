import hashlib
import random
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Random import get_random_bytes

# SM2 Signature 
N = int('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123', 16)
A = int('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54120', 16)
B = int('28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93', 16)
Gx = int('32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE171E6A43503C9E18D', 16)
Gy = int('BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0', 16)
P = int('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF', 16)


def point_addition(x1, y1, x2, y2):
    lam = ((y2 - y1) * pow(x2 - x1, N - 2, N)) % N
    x3 = (lam * lam - x1 - x2) % N
    y3 = (lam * (x1 - x3) - y1) % N
    return x3, y3


def point_double(x, y):
    lam = ((3 * x * x + A) * pow(2 * y, N - 2, N)) % N
    x3 = (lam * lam - 2 * x) % N
    y3 = (lam * (x - x3) - y) % N
    return x3, y3


def point_mul(k, x, y):
    result = (0, 0)
    while k:
        if k & 1:
            result = point_addition(result[0], result[1], x, y)
        x, y = point_double(x, y)
        k >>= 1
    return result


def sm3_hash(msg):
    block_size = 64
    msg = bytearray(msg)

    msg_len = len(msg)
    index = msg_len % block_size
    padding_len = block_size - index if index != 0 else 64

    msg += b'\x80' + bytearray(padding_len - 1)  # Padding
    msg += int.to_bytes(msg_len * 8, 8, 'big')  # Length

    iv = bytearray(32)
    T = [0] * 8
    for i in range(0, len(msg), block_size):
        W = [(msg[i + j] << 24) + (msg[i + j + 1] << 16) +
             (msg[i + j + 2] << 8) + msg[i + j + 3]
             for j in range(0, block_size, 4)]

        V = iv[:]
        for j in range(64):
            if j < 16:
                W[j] ^= int.from_bytes(V[4:8], 'big')
            else:
                W[j] = sm3_p1(W[j - 16] ^ W[j - 9] ^ (W[j - 3] << 15) ^
                              (W[j - 3] >> 17)) ^ (W[j - 13] << 7) ^ \
                       (W[j - 13] >> 25) ^ W[j - 6] ^ (W[j - 6] << 3) ^ \
                       (W[j - 6] >> 29) ^ W[j - 16] ^ (W[j - 14] << 7) ^ \
                       (W[j - 14] >> 25) ^ W[j - 11] ^ (W[j - 11] << 3) ^ \
                       (W[j - 11] >> 29)

            SS1 = ((V[0] << 12) + V[1]) ^ V[2]
            TT1 = (sm3_ffj(V[0]) + V[3] + sm3_p0[j]) & 0xFFFFFFFF
            YY = sm3_p0(TT1)
            SS2 = (YY + SS1) & 0xFFFFFFFF
            TT2 = (sm3_ggj(V[4]) + V[7] + sm3_p0[j]) & 0xFFFFFFFF
            V = [TT1, SS1, V[1], V[2], sm3_p1(V[3]), TT2, SS2, sm3_p0(V[6])]

        for j in range(8):
            T[j] ^= V[j]

    return b''.join([int.to_bytes(t, 4, 'big') for t in T])


def sm3_ffj(x):
    return x ^ (x << 9) ^ (x << 17) ^ (x >> 25)


def sm3_ggj(x):
    return x ^ (x << 15) ^ (x << 23) ^ (x >> 9)


def sm3_p0(x):
    return x ^ ((x << 9) | (x >> 23)) ^ ((x << 17) | (x >> 15))


def sm3_p1(x):
    return x ^ ((x << 15) | (x >> 17)) ^ ((x << 23) | (x >> 9))


def encrypt_data(data, key):
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(data, 16))
    return iv + ciphertext


def decrypt_data(encrypted_data, key):
    iv = encrypted_data[:16]
    data = encrypted_data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(data), 16)
    return decrypted_data


def generate_keypair():
    private_key = random.randint(1, N - 2)
    public_key = point_mul(private_key, Gx, Gy)
    return private_key, public_key


def sign(private_key, msg):
    z = int.from_bytes(sm3_hash(msg), 'big')
    while True:
        k = random.randint(1, N - 2)
        x, y = point_mul(k, Gx, Gy)
        r = (z + x) % N
        if r == 0 or (r + k) % N == 0:
            continue
        s = (pow((N + 1) // 4, N - 2, N) * (k - r * private_key)) % N
        if s != 0:
            break
    return r, s


def verify(public_key, msg, signature):
    r, s = signature
    if not (0 < r < N and 0 < s < N):
        return False
    e = int.from_bytes(sm3_hash(msg), 'big')
    t = (r + s) % N
    if t == 0:
        return False
    x, y = point_addition(
        *point_mul(s, Gx, Gy), *point_mul(t, *public_key))
    if (r + x) % N == 0:
        return False
    return (e + x) % N == r


def network_send(data):
    pass


def network_receive():
    data = b''  # 用于存储接收到的数据
    return data


# 签名过程
def sign_with_network(private_key, msg):
    signature = sign(private_key, msg)

    signature_bytes = int.to_bytes(signature[0], 32, 'big') + int.to_bytes(signature[1], 32, 'big')

    encrypted_signature = encrypt_data(signature_bytes, private_key.to_bytes(32, 'big'))

    network_send(encrypted_signature)

    received_data = network_receive()

    decrypted_data = decrypt_data(received_data, private_key.to_bytes(32, 'big'))

    received_signature = (int.from_bytes(decrypted_data[:32], 'big'), int.from_bytes(decrypted_data[32:], 'big'))

    return received_signature


private_key, public_key = generate_keypair()
msg = b'This is a test message.'
received_signature = sign_with_network(private_key, msg)
is_valid = verify(public_key, msg, received_signature)
print('Signature is valid:', is_valid)
