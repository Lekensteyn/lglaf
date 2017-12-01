#!/usr/bin/env python
#
# Dumps the contents of a file.
#
# Copyright (C) 2016 Peter Wu <peter@lekensteyn.nl>
# Licensed under the MIT license <http://opensource.org/licenses/MIT>.

from contextlib import closing, contextmanager
import argparse, logging, os, struct, sys
import lglaf

_logger = logging.getLogger("dump-file")

def read_uint32(data, offset):
    return struct.unpack_from('<I', data, offset)[0]

def get_file_size(comm, path):
    shell_command = b'ls -ld ' + path.encode('utf8') + b'\0'
    output = comm.call(lglaf.make_request(b'EXEC', body=shell_command))[1]
    output = output.decode('utf8')
    if not len(output):
        raise RuntimeError("Cannot find file %s" % path)
    # Example output: "-rwxr-x--- root     root       496888 1970-01-01 00:00 lafd"
    # Accommodate for varying ls output
    fields = output.split()
    if len(fields) >= 7:
        for field in fields[3:]:
            if field.isdigit():
                return int(field)

    _logger.debug("ls output: %s", output)
    raise RuntimeError("Cannot find filesize for path %s" % path)

@contextmanager
def laf_open_ro(comm, filename):
    filename = filename.encode('utf8') + b'\0'
    # Open a single file in readonly mode
    open_cmd = lglaf.make_request(b'OPEN', body=filename)
    open_header = comm.call(open_cmd)[0]
    fd_num = read_uint32(open_header, 4)
    try:
        yield fd_num
    finally:
        close_cmd = lglaf.make_request(b'CLSE', args=[fd_num])
        comm.call(close_cmd)

def laf_read(comm, fd_num, offset, size):
    """Read size bytes at the given block offset."""
    read_cmd = lglaf.make_request(b'READ', args=[fd_num, offset, size])
    header, response = comm.call(read_cmd)
    # Ensure that response fd, offset and length are sane (match the request)
    assert read_cmd[4:4+12] == header[4:4+12], "Unexpected read response"
    assert len(response) == size
    return response

# On Linux, one bulk read returns at most 16 KiB. 32 bytes are part of the first
# header, so remove one block size (512 bytes) to stay within that margin.
# This ensures that whenever the USB communication gets out of sync, it will
# always start with a message header, making recovery easier.
MAX_BLOCK_SIZE = (16 * 1024 - 512) // 512
BLOCK_SIZE = 512

def dump_file(comm, file_fd, output_file, size, offset=0):
    with open_local_writable(output_file) as f:
        while offset < size:
            chunksize = min(size - offset, BLOCK_SIZE * MAX_BLOCK_SIZE)
            data = laf_read(comm, file_fd, offset // BLOCK_SIZE, chunksize)
            f.write(data)
            offset += chunksize
        _logger.info("Wrote %d bytes to %s", size, output_file)

def open_local_writable(path):
    if path == '-':
        try: return sys.stdout.buffer
        except: return sys.stdout
    else:
        return open(path, "wb")

parser = argparse.ArgumentParser()
parser.add_argument("--debug", action='store_true', help="Enable debug messages")
parser.add_argument("--offset", type=int, default=0,
        help="Start reading the file from an offset")
parser.add_argument("--size", type=int,
        help="Override file size (useful for files in /proc)")
parser.add_argument("file", help="File path on the device")
parser.add_argument("output_file",
        help="Local output file (use '-' for stdout)")

def main():
    args = parser.parse_args()
    logging.basicConfig(format='%(asctime)s %(name)s: %(levelname)s: %(message)s',
            level=logging.DEBUG if args.debug else logging.INFO)

    comm = lglaf.autodetect_device()
    with closing(comm):
        lglaf.try_hello(comm)

        # Be careful: a too large read size will result in a hang while LAF
        # tries to read more data, requiring a reset.
        if args.size:
            offset = args.offset
            size = args.size
        else:
            offset = args.offset
            size = get_file_size(comm, args.file)
            if offset > size:
                _logger.warning("Offset %d is larger than the detected size %d",
                        offset, size)
            size -= offset
        if size > 0:
            _logger.debug("File size is %d", size)
            with laf_open_ro(comm, args.file) as file_fd:
                _logger.debug("Opened fd %d for file %s", file_fd, args.file)
                dump_file(comm, file_fd, args.output_file, size, offset)
        else:
            _logger.warning("Not a file or zero size, not writing file")

if __name__ == '__main__':
    try:
        main()
    except OSError as e:
        # Ignore when stdout is closed in a pipe
        if e.errno != 32:
            raise
