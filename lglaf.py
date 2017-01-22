#!/usr/bin/env python
#
# Interactive shell for communication with LG devices in download mode (LAF).
#
# Copyright (C) 2015 Peter Wu <peter@lekensteyn.nl>
# Licensed under the MIT license <http://opensource.org/licenses/MIT>.

from __future__ import print_function
from contextlib import closing
from Crypto.Cipher import AES
import argparse, logging, re, struct, sys

# Enhanced prompt with history
try: import readline
except ImportError: pass
# Try USB interface
try: import usb.core, usb.util
except ImportError: pass
# Windows registry for serial port detection
try: import winreg
except ImportError:
    try: import _winreg as winreg
    except ImportError: winreg = None

_logger = logging.getLogger("LGLAF.py")

# Python 2/3 compat
try: input = raw_input
except: pass
if '\0' == b'\0': int_as_byte = chr
else: int_as_byte = lambda x: bytes([x])

_ESCAPE_PATTERN = re.compile(b'''\\\\(
x[0-9a-fA-F]{2} |
[0-7]{1,3} |
.)''', re.VERBOSE)
_ESCAPE_MAP = {
    b'n': b'\n',
    b'r': b'\r',
    b't': b'\t',
}
_ESCAPED_CHARS = b'"\\\''
def text_unescape(text):
    """Converts a string with escape sequences to bytes."""
    text_bin = text.encode("utf8")
    def sub_char(m):
        what = m.group(1)
        if what[0:1] == b'x' and len(what) == 3:
            return int_as_byte(int(what[1:], 16))
        elif what[0:1] in b'01234567':
            return int_as_byte(int(what, 8))
        elif what in _ESCAPE_MAP:
            return _ESCAPE_MAP[what]
        elif what in _ESCAPED_CHARS:
            return what
        else:
            raise RuntimeError('Unknown escape sequence \\%s' %
                    what.decode('utf8'))
    return re.sub(_ESCAPE_PATTERN, sub_char, text_bin)

def parse_number_or_escape(text):
    try:
        return int(text, 0) if text else 0
    except ValueError:
        return text_unescape(text)

### Protocol-related stuff

def crc16(data):
    """CRC-16-CCITT computation with LSB-first and inversion."""
    crc = 0xffff
    for byte in data:
        crc ^= byte
        for bits in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0x8408
            else:
                crc >>= 1
    return crc ^ 0xffff

def invert_dword(dword_bin):
    dword = struct.unpack("I", dword_bin)[0]
    return struct.pack("I", dword ^ 0xffffffff)

def make_request(cmd, args=[], body=b''):
    if not isinstance(cmd, bytes):
        cmd = cmd.encode('ascii')
    assert isinstance(body, bytes), "body must be bytes"

    # Header: command, args, ... body size, header crc16, inverted command
    header = bytearray(0x20)
    def set_header(offset, val):
        if isinstance(val, int):
            val = struct.pack('<I', val)
        assert len(val) == 4, "Header field requires a DWORD, got %s %r" % \
                (type(val).__name__, val)
        header[offset:offset+4] = val

    set_header(0, cmd)
    assert len(args) <= 4, "Header cannot have more than 4 arguments"
    for i, arg in enumerate(args):
        set_header(4 * (i + 1), arg)

    # 0x14: body length
    set_header(0x14, len(body))
    # 0x1c: Inverted command
    set_header(0x1c, invert_dword(cmd))
    # Header finished (with CRC placeholder), append body...
    header += body
    # finish with CRC for header and body
    set_header(0x18, crc16(header))
    return bytes(header)

def validate_message(payload, ignore_crc=False):
    if len(payload) < 0x20:
        raise RuntimeError("Invalid header length: %d" % len(payload))
    if not ignore_crc:
        crc = struct.unpack_from('<I', payload, 0x18)[0]
        payload_before_crc = bytearray(payload)
        payload_before_crc[0x18:0x18+4] = b'\0\0\0\0'
        crc_exp = crc16(payload_before_crc)
        if crc_exp != crc:
            raise RuntimeError("Expected CRC %04x, found %04x" % (crc_exp, crc))
    tail_exp = invert_dword(payload[0:4])
    tail = payload[0x1c:0x1c+4]
    if tail_exp != tail:
        raise RuntimeError("Expected trailer %r, found %r" % (tail_exp, tail))

def make_exec_request(shell_command):
    # Allow use of shell constructs such as piping and reports syntax errors
    # such as unterminated quotes. Remaining limitation: repetitive spaces are
    # still eaten.
    argv = b'sh -c eval\t"$*"</dev/null\t2>&1 -- '
    argv += shell_command.encode('ascii')
    if len(argv) > 255:
        raise RuntimeError("Command length %d is larger than 255" % len(argv))
    return make_request(b'EXEC', body=argv + b'\0')


### USB or serial port communication

class Communication(object):
    def __init__(self):
        self.read_buffer = b''
    def read(self, n, timeout=None):
        """Reads exactly n bytes."""
        need = n - len(self.read_buffer)
        while need > 0:
            buff = self._read(need, timeout=timeout)
            self.read_buffer += buff
            if not buff:
                raise EOFError
            need -= len(buff)
        data, self.read_buffer = self.read_buffer[0:n], self.read_buffer[n:]
        return data
    def _read(self, n, timeout=None):
        """Try one read, possibly returning less or more than n bytes."""
        raise NotImplementedError
    def write(self, data):
        raise NotImplementedError
    def close(self):
        raise NotImplementedError
    def reset(self):
        self.read_buffer = b''
    def call(self, payload):
        """Sends a command and returns its response."""
        validate_message(payload)
        self.write(payload)
        header = self.read(0x20)
        validate_message(header, ignore_crc=True)
        cmd = header[0:4]
        size = struct.unpack_from('<I', header, 0x14)[0]
        # could validate CRC and inverted command here...
        data = self.read(size) if size else b''
        if cmd == b'FAIL':
            errCode = struct.unpack_from('<I', header, 4)
            raise RuntimeError('Command failed with error code %#x' % errCode)
        if cmd != payload[0:4]:
            raise RuntimeError("Unexpected response: %r" % header)
        return header, data

class FileCommunication(Communication):
    def __init__(self, file_path):
        super(FileCommunication, self).__init__()
        if sys.version_info[0] >= 3:
            self.f = open(file_path, 'r+b', buffering=0)
        else:
            self.f = open(file_path, 'r+b')
    def _read(self, n, timeout=None):
        return self.f.read(n)
    def write(self, data):
        self.f.write(data)
    def close(self):
        self.f.close()

class USBCommunication(Communication):
    VENDOR_ID_LG = 0x1004
    # Read timeout. Set to 0 to disable timeouts
    READ_TIMEOUT_MS = 60000
    def __init__(self):
        super(USBCommunication, self).__init__()
        # Match device using heuristics on the interface/endpoint descriptors,
        # this avoids hardcoding idProduct.
        self.usbdev = usb.core.find(idVendor=self.VENDOR_ID_LG,
                custom_match = self._match_device)
        if self.usbdev is None:
            raise RuntimeError("USB device not found")
        cfg = usb.util.find_descriptor(self.usbdev,
                custom_match=self._match_configuration)
        current_cfg = self.usbdev.get_active_configuration()
        if cfg.bConfigurationValue != current_cfg.bConfigurationValue:
            try:
                cfg.set()
            except usb.core.USBError as e:
                _logger.warning("Failed to set configuration, "
                        "has a kernel driver claimed the interface?")
                raise e
        for intf in cfg:
            if self.usbdev.is_kernel_driver_active(intf.bInterfaceNumber):
                _logger.debug("Detaching kernel driver for intf %d",
                        intf.bInterfaceNumber)
                self.usbdev.detach_kernel_driver(intf.bInterfaceNumber)
            if self._match_interface(intf):
                self._set_interface(intf)
        assert self.ep_in
        assert self.ep_out
    def _match_device(self, device):
        return any(
            usb.util.find_descriptor(cfg, custom_match=self._match_interface)
            for cfg in device
        )
    def _set_interface(self, intf):
        for ep in intf:
            ep_dir = usb.util.endpoint_direction(ep.bEndpointAddress)
            if ep_dir == usb.util.ENDPOINT_IN:
                self.ep_in = ep.bEndpointAddress
            else:
                self.ep_out = ep.bEndpointAddress
        _logger.debug("Using endpoints %02x (IN), %02x (OUT)",
                self.ep_in, self.ep_out)
    def _match_interface(self, intf):
        return intf.bInterfaceClass == 255 and \
            intf.bInterfaceSubClass == 255 and \
            intf.bInterfaceProtocol == 255 and \
            intf.bNumEndpoints == 2 and all(
            usb.util.endpoint_type(ep.bmAttributes) ==
                usb.util.ENDPOINT_TYPE_BULK
            for ep in intf
        )
    def _match_configuration(self, config):
        return usb.util.find_descriptor(config,
                custom_match=self._match_interface)
    def _read(self, n, timeout=None):
        if timeout is None:
            timeout = self.READ_TIMEOUT_MS
        # device seems to use 16 KiB buffers.
        array = self.usbdev.read(self.ep_in, 2**14, timeout=timeout)
        try: return array.tobytes()
        except: return array.tostring()
    def write(self, data):
        # Reset read buffer for response
        if self.read_buffer:
            _logger.warn('non-empty read buffer %r', self.read_buffer)
            self.read_buffer = b''
        self.usbdev.write(self.ep_out, data)
    def close(self):
        usb.util.dispose_resources(self.usbdev)

def try_hello(comm):
    """
    Tests whether the device speaks the expected protocol. If desynchronization
    is detected, tries to read as much data as possible.
    """
    # Wait for at most 5 seconds for a response... it shouldn't take that long
    # and otherwise something is wrong.
    HELLO_READ_TIMEOUT = 5000

    hello_request = make_request(b'HELO', args=[b'\1\0\0\1'])
    comm.write(hello_request)
    data = comm.read(0x20, timeout=HELLO_READ_TIMEOUT)
    if data[0:4] != b'HELO':
        # Unexpected response, maybe some stale data from a previous execution?
        while data[0:4] != b'HELO':
            try:
                validate_message(data, ignore_crc=True)
                size = struct.unpack_from('<I', data, 0x14)[0]
                comm.read(size, timeout=HELLO_READ_TIMEOUT)
            except RuntimeError: pass
            # Flush read buffer
            comm.reset()
            data = comm.read(0x20, timeout=HELLO_READ_TIMEOUT)
        # Just to be sure, send another HELO request.
        comm.call(hello_request)


def detect_serial_path():
    try:
        path = r'HARDWARE\DEVICEMAP\SERIALCOMM'
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as key:
            for i in range(winreg.QueryInfoKey(key)[1]):
                name, value, value_type = winreg.EnumValue(key, i)
                # match both \Device\LGANDNETDIAG1 and \Device\LGVZANDNETDIAG1
                name = name.upper()
                if name.startswith(r'\DEVICE\LG') and name.endswith('ANDNETDIAG1'):
                    return value
    except OSError: pass
    return None

def autodetect_device():
    if winreg is not None and 'usb.core' not in sys.modules:
        serial_path = detect_serial_path()
        _logger.debug("Using serial port: %s", serial_path)
        if not serial_path:
            raise RuntimeError("Device not found, try installing LG drivers")
        return FileCommunication(serial_path)
    else:
        if 'usb.core' not in sys.modules:
            raise RuntimeError("Please install PyUSB for USB support")
        return USBCommunication()


### Interactive loop

def get_commands(command):
    if command:
        yield command
        return
    # Happened on Win32/Py3.4.4 when: echo ls | lglaf.py --serial com4
    if sys.stdin is None:
        raise RuntimeError('No console input available!')
    if sys.stdin.isatty():
        print("LGLAF.py by Peter Wu (https://lekensteyn.nl/lglaf)\n"
                "Type a shell command to execute or \"exit\" to leave.",
                file=sys.stderr)
        prompt = '# '
    else:
        prompt = ''
    try:
        while True:
            line = input(prompt)
            if line == "exit":
                break
            if line:
                yield line
    except EOFError:
        if prompt:
            print("", file=sys.stderr)

def command_to_payload(command):
    # Handle '!' as special commands, treat others as shell command
    if command[0] != '!':
        return make_exec_request(command)
    command = command[1:]
    # !command [arg1[,arg2[,arg3[,arg4]]]] [body]
    # args are treated as integers (decimal or hex)
    # body is treated as string (escape sequences are supported)
    command, args, body = (command.split(' ', 2) + ['', ''])[0:3]
    command = text_unescape(command)
    args = list(map(parse_number_or_escape, args.split(',') + [0, 0, 0]))[0:4]
    body = text_unescape(body)
    return make_request(command, args, body)

parser = argparse.ArgumentParser(description='LG LAF Download Mode utility')
parser.add_argument("--skip-hello", action="store_true",
        help="Immediately send commands, skip HELO message")
parser.add_argument("-c", "--command", help='Shell command to execute')
parser.add_argument("--serial", metavar="PATH", dest="serial_path",
        help="Path to serial device (e.g. COM4).")
parser.add_argument("--debug", action='store_true', help="Enable debug messages")
parser.add_argument("--unlock", action="store_true", help="Unlock LAF")

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
    request_kilo = make_request(b'KILO', args=[b'CENT', b'\0\0\0\0', b'\0\0\0\0', b'\0\0\0\0'])
    kilo_header, kilo_response = comm.call(request_kilo)
    kilo_challenge = kilo_header[8:12]
    chalstring = ":".join("{:02x}".format(ord(k)) for k in kilo_challenge)
    _logger.debug("Challenge: %s" %chalstring)
    key2 = 'qndiakxxuiemdklseqid~a~niq,zjuxl' # if this doesnt work try 'lgowvqnltpvtgogwswqn~n~mtjjjqxro'
    kilo_response = do_aes_encrypt(key_xoring(key_transform(key2), kilo_challenge))
    respstring = ":".join("{:02x}".format(ord(m)) for m in kilo_response)
    _logger.debug("Response: %s" %respstring)
    request_kilo_metr =  make_request(b'KILO', args=[b'METR', b'\0\0\0\0', b'\x02\0\0\0', b'\0\0\0\0'], body=bytes(kilo_response))
    metr_header, metr_response = comm.call(request_kilo_metr)

def main():
    args = parser.parse_args()
    logging.basicConfig(format='%(name)s: %(levelname)s: %(message)s',
            level=logging.DEBUG if args.debug else logging.INFO)

    # Binary stdout (output data from device as-is)
    try: stdout_bin = sys.stdout.buffer
    except: stdout_bin = sys.stdout

    if args.serial_path:
        comm = FileCommunication(args.serial_path)
    else:
        comm = autodetect_device()

    with closing(comm):
	if args.unlock:
            do_challenge_response(comm)
        if not args.skip_hello:
            try_hello(comm)
            _logger.debug("Hello done, proceeding with commands")
        for command in get_commands(args.command):
            try:
                payload = command_to_payload(command)
                header, response = comm.call(payload)
                # For debugging, print header
                if command[0] == '!':
                    _logger.debug('Header: %s',
                            ' '.join(repr(header[i:i+4]).replace("\\x00", "\\0")
                        for i in range(0, len(header), 4)))
                stdout_bin.write(response)
            except Exception as e:
                _logger.warn(e)
                if args.debug:
                    import traceback; traceback.print_exc()

if __name__ == '__main__':
    main()
