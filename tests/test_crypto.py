from binascii import unhexlify
import laf_crypto


def test_transform(laf_key):
    transformed = laf_crypto.key_transform(laf_key)
    assert transformed == b'dqoev)ohnsWu\\bk`oiicmZ_lpqe\\ealp'

def test_xor_key(laf_key):
    transformed_key = b'dqoev)ohnsWu\\bk`oiicmZ_lpqe\\ealp'
    challenge = unhexlify(b'f29ae130')
    xored_key = laf_crypto.xor_key(transformed_key, challenge)
    assert xored_key == b'T\x90\xf5\x97F\xc8\xf5\x9a^\x92\xcd\x87l\x83\xf1\x92_\x88\xf3\x91]\xbb\xc5\x9e@\x90\xff\xaeU\x80\xf6\x82'

def test_challenge(laf_key):
    resp = laf_crypto.encrypt_kilo_challenge(laf_key, unhexlify(b'f29ae130'))
    assert resp == unhexlify(b'2f47ca81ebeee6f414263c0542c8d132')
