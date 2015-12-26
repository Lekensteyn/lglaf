#!/usr/bin/env python
#
# Dump partitions to file.
#
# Copyright (C) 2015 Peter Wu <peter@lekensteyn.nl>
# Licensed under the MIT license <http://opensource.org/licenses/MIT>.

from collections import OrderedDict
from contextlib import closing, contextmanager
import argparse, logging, os, struct
import lglaf

_logger = logging.getLogger(__name__)

def read_uint32(data, offset):
    return struct.unpack_from('<I', data, 4)[0]

def read_partitions(comm):
    output = comm.call(lglaf.make_exec_request('cat /proc/partitions'))[1]
    partitions = OrderedDict()
    for line in output.decode('ascii').split('\n'):
        if not 'mmcblk0p' in line:
            continue
        major, minor, blocks, name = line.split()
        partitions[name] = int(blocks)
    return partitions

@contextmanager
def laf_open_ro(comm, path):
    # Avoid opening the whole partition in read/write mode.
    assert path, "Path must not be empty"
    path_bin = path.encode('ascii') + b'\0'
    open_cmd = lglaf.make_request(b'OPEN', body=path_bin)
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

parser = argparse.ArgumentParser()
parser.add_argument("-d", "--outdir", default=".",
        help="Output directory for disk images.")
# Do not dump partitions larger than this size
# (userdata 11728 MiB, system 2064 MiB, cache 608 MiB, cust 256 MiB)
parser.add_argument("--max-size", type=int, default=65536,
        help="Maximum partition size to dump (in KiB)")
parser.add_argument("--debug", action='store_true', help="Enable debug messages")

# On Linux, one bulk read returns at most 16 KiB. 32 bytes are part of the first
# header, so remove one block size (512 bytes) to stay within that margin.
# This ensures that whenever the USB communication gets out of sync, it will
# always start with a message header, making recovery easier.
MAX_BLOCK_SIZE = (16 * 1024 - 512) // 512

def dump_file(comm, remote_path, local_path, size):
    try:
        offset = os.path.getsize(local_path)
    except OSError:
        offset = 0
    if offset >= size:
        if offset > size:
            _logger.warn("%s: unexpected size %dK > %dK",
                    local_path, offset, size)
        else:
            _logger.info("%s: already retrieved %dK",
                    local_path, size)
        return

    # Read offsets must be a multiple of 512 bytes, enforce this
    BLOCK_SIZE = 512
    unaligned_bytes = offset % BLOCK_SIZE
    offset = BLOCK_SIZE * (offset // BLOCK_SIZE)

    with laf_open_ro(comm, remote_path) as fd_num:
        _logger.debug("Opened fd %d for %s (final size %.2fK, offset %.2fK)",
                fd_num, remote_path, size / 1024, offset / 1024)
        with open(local_path, 'ab') as f:
            # Offset should be aligned to block size. If not, read at most a
            # whole block and drop the leading bytes.
            if unaligned_bytes:
                chunksize = min(size - offset, BLOCK_SIZE)
                data = laf_read(comm, fd_num, offset // BLOCK_SIZE, chunksize)
                f.write(data[unaligned_bytes:])
                offset += BLOCK_SIZE
            while offset < size:
                chunksize = min(size - offset, BLOCK_SIZE * MAX_BLOCK_SIZE)
                data = laf_read(comm, fd_num, offset // BLOCK_SIZE, chunksize)
                f.write(data)
                offset += chunksize

def dump_partitions(comm, outdir, max_size):
    parts = read_partitions(comm)
    for name, size in parts.items():
        if size > max_size:
            _logger.info("Ignoring large partition %s of size %dK" % (name, size))
            continue
        out_path = os.path.join(outdir, "%s.bin" % name)
        dump_file(comm, "/dev/block/%s" % name, out_path, 1024 * size)

def main():
    args = parser.parse_args()
    logging.basicConfig(format='%(asctime)s %(name)s: %(levelname)s: %(message)s',
            level=logging.DEBUG if args.debug else logging.INFO)

    try: os.makedirs(args.outdir)
    except OSError: pass

    comm = lglaf.autodetect_device()
    with closing(comm):
        lglaf.try_hello(comm)
        dump_partitions(comm, args.outdir, args.max_size)

if __name__ == '__main__':
    main()
