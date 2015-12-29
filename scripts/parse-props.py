#!/usr/bin/env python
# Parse property file.
#
# Usage:
#
#   lglaf.py -c '!INFO GPRO \x08\x0b\0\0' > props.bin
#   scripts/parse-props.py props.bin

import argparse, sys, struct

def stringify(resp):
    if not isinstance(resp, str):
        try: resp = resp.decode('ascii')
        except: pass
    return resp

def get_str(data, shadow, offset):
    resp = b''
    #while True:
    while offset < len(data):
        b = data[offset:offset+1]
        shadow[offset] = 's'
        if b == b'\0':
            break
        resp += b
        offset += 1
    return stringify(resp)

def get_chr(data, shadow, offset):
    b = data[offset:offset+1]
    shadow[offset] = 'c'
    return stringify(b)

def get_int(data, shadow, offset):
    d = struct.unpack_from('<I', data, offset)[0]
    for off in range(offset, offset+4):
        shadow[off] = 'd'
    return d

# Description of the contents
keys = [
    (0x3f9, get_str, "download cable"),
    (0x42b, get_int, "battery level"),
    (0x010, get_chr, "download type"),
    (0x021, get_int, "download speed"),
    (0x403, get_str, "usb version"),
    (0x417, get_str, "hardware revision"),
    (0x029, get_str, "download sw version"),
    (0x14f, get_str, "device sw version"),
    (0x42f, get_chr, "secure device"),
    (0x4e8, get_str, "laf sw version"),
    (0x24f, get_str, "device factory version"),
    (0x528, get_str, "device factory out version"),
    (0x3db, get_str, "pid"),
    (0x3c7, get_str, "imei"),
    (0x131, get_str, "model name"),
    (0x430, get_str, "device build type"),
    (0x43a, get_str, "chipset platform"),
    (0x44e, get_str, "target_operator"),
    (0x462, get_str, "target_country"),
    (0x4fc, get_int, "ap_factory_reset_status"),
    (0x500, get_int, "cp_factory_reset_status"),
    (0x504, get_int, "isDownloadNotFinish"),
    (0x508, get_int, "qem"),
    (0x628, get_str, "cupss swfv"),
    (0x728, get_int, "is one binary dual plan"),
    (0x72c, get_int, "memory size"),
    (0x730, get_str, "memory_id"),
    (0x39f, get_str, "bootloader_ver"),
]

def debug_other(data, shadow):
    for offset, shadow_type in enumerate(shadow):
        data_byte = data[offset:offset+1]
        if not shadow_type and data_byte != b'\0':
            print("Unprocessed byte at 0x%03x: %r" % (offset, data_byte))
            shadow[offset] = '*'

def print_shadow(shadow):
    for offset in range(0, len(shadow), 32):
        line1 = ''.join(c or '.' for c in shadow[offset:offset+16])
        line2 = ''.join(c or '.' for c in shadow[offset+16:offset+32])
        print("%03x: %-16s %-16s" % (offset, line1, line2))

def parse_data(data):
    version = struct.unpack_from('<I', data)[0]
    expected_length = 0x00000b08
    assert version == expected_length, 'Unknown version: 0x%08x' % version
    assert len(data) == expected_length

    # Set to non-None when processed
    shadow = [None] * len(data)
    for offset, getter, description in keys:
        resp = getter(data, shadow, offset)
        print("%-26s = %r" % (description, resp))

    return data, shadow

def open_local_readable(path):
    if path == '-':
        try: return sys.stdin.buffer
        except: return sys.stdin
    else:
        return open(path, "rb")

parser = argparse.ArgumentParser()
parser.add_argument("--debug", action='store_true', help="Enable debug messages")
parser.add_argument("file",
        help="2824 byte properties dump file (or '-' for stdin)")

def main():
    args = parser.parse_args()
    data = open_local_readable(args.file).read()
    data, shadow = parse_data(data)
    if args.debug:
        debug_other(data, shadow)
        print_shadow(shadow)

if __name__ == '__main__':
    main()
