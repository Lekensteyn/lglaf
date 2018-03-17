import struct
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from lglaf import int_as_byte


def key_transform(old_key):
    new_key = b''
    old_key = bytearray(old_key)
    for x in range(32, 0, -1):
        c = old_key[x-1]
        new_key += int_as_byte(c - (x % 0x0C))
    return new_key


def xor_key(key, kilo_challenge):
    # Reserve key
    key_xor = b''
    pos = 0
    challenge = struct.unpack('>I', kilo_challenge)[0]
    for i in range(8):
        k = struct.unpack('<I', key[pos:pos + 4])[0]
        key_xor += struct.pack('<I', k ^ challenge)
        pos += 4
    return key_xor


def encrypt_kilo_challenge(encryption_key, kilo_challenge):
    plaintext = b''
    for k in range(0, 16):
        # Assemble 0x00 0x01 0x02 ... 0x1F byte-array
        plaintext += int_as_byte(k)
    encryption_key = key_transform(encryption_key)
    xored_key = xor_key(encryption_key, kilo_challenge)
    obj = Cipher(algorithms.AES(xored_key), modes.ECB(),
                 backend=default_backend()).encryptor()
    return obj.update(plaintext) + obj.finalize()
