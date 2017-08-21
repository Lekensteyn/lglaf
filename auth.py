#!/usr/bin/env python
#
# Challenge/Response for communication with LG devices in download mode (LAF).
#
# Copyright (C) 2015 Peter Wu <peter@lekensteyn.nl>
# Licensed under the MIT license <http://opensource.org/licenses/MIT>.

from Crypto.Cipher import AES
from contextlib import closing, contextmanager
import lglaf,argparse,logging,struct

_logger = logging.getLogger("auth")

parser = argparse.ArgumentParser()
parser = argparse.ArgumentParser(description='LG LAF Download Mode utility')
parser.add_argument("--auth", action="store_true", help="auth LAF")
parser.add_argument("--debug", action='store_true', help="Enable debug messages")

def key_transform(old_key):
    new_key = ''
    for x in range(32,0,-1):
        new_key += chr(ord(old_key[x-1]) - (x % 0x0C))
    return new_key

def key_xoring(key2_t, kilo_challenge):
    key2_t_xor = ''
    i = 0
    while i <= 28:
        key2_t_xor += chr(ord(key2_t[i]) ^ ord(kilo_challenge[3]))
        key2_t_xor += chr(ord(key2_t[i+1]) ^ ord(kilo_challenge[2]))
        key2_t_xor += chr(ord(key2_t[i+2]) ^ ord(kilo_challenge[1]))
        key2_t_xor += chr(ord(key2_t[i+3]) ^ ord(kilo_challenge[0]))
        i = i + 4
    return key2_t_xor

def do_aes_encrypt(key2_t_xor):
    plaintext = b''
    for k in range(0,16):
        plaintext += chr(k)
    obj = AES.new(key2_t_xor, AES.MODE_ECB)
    return obj.encrypt(plaintext)

def do_challenge_response(comm):
    request_kilo = lglaf.make_request(b'KILO', args=[b'CENT', b'\0\0\0\0', b'\0\0\0\0', b'\0\0\0\0'])
    kilo_header, kilo_response = comm.call(request_kilo)
    kilo_challenge = kilo_header[8:12]
    chalstring = ":".join("{:02x}".format(ord(k)) for k in kilo_challenge)
    _logger.debug("Challenge: %s" %chalstring)
    key2 = b'qndiakxxuiemdklseqid~a~niq,zjuxl' # if this doesnt work try 'lgowvqnltpvtgogwswqn~n~mtjjjqxro'
    kilo_response = do_aes_encrypt(key_xoring(key_transform(key2), kilo_challenge))
    respstring = ":".join("{:02x}".format(ord(m)) for m in kilo_response)
    _logger.debug("Response: %s" %respstring)
    request_kilo_metr =  lglaf.make_request(b'KILO', args=[b'METR', b'\0\0\0\0', b'\x02\0\0\0', b'\0\0\0\0'], body=bytes(kilo_response))
    metr_header, metr_response = comm.call(request_kilo_metr)

def main():
    args = parser.parse_args()
    logging.basicConfig(format='%(name)s: %(levelname)s: %(message)s',
            level=logging.DEBUG if args.debug else logging.INFO)

    comm = lglaf.autodetect_device()
    with closing(comm):
        do_challenge_response(comm)
        lglaf.try_hello(comm)

if __name__ == '__main__':
    try:
        main()
    except OSError as e:
        # Ignore when stdout is closed in a pipe
        if e.errno != 32:
            raise

