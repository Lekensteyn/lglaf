#!/usr/bin/env python
#
# Manage a single partition (info, read, write).
#
# Copyright (C) 2015 Peter Wu <peter@lekensteyn.nl>
# Licensed under the MIT license <http://opensource.org/licenses/MIT>.

from collections import OrderedDict
from contextlib import closing, contextmanager
import argparse, logging, os, struct, sys
import lglaf

_logger = logging.getLogger("partitions")

def read_uint32(data, offset):
    return struct.unpack_from('<I', data, 4)[0]

def cat_file(comm, path):
    shell_command = b'cat ' + path.encode('ascii') + b'\0'
    return comm.call(lglaf.make_request(b'EXEC', body=shell_command))[1]

def partition_info(comm, part_num):
    """Retrieves the partition size and offset within the disk (in bytes)."""
    disk_path = "/sys/block/mmcblk0/mmcblk0p%d" % part_num
    try:
        # Convert sector sizes to bytes.
        start = 512 * int(cat_file(comm, "%s/start" % disk_path))
        size = 512 * int(cat_file(comm, "%s/size" % disk_path))
    except ValueError:
        raise RuntimeError("Partition %d not found" % part_num)
    return start, size

@contextmanager
def laf_open_disk(comm):
    # Open whole disk in read/write mode
    open_cmd = lglaf.make_request(b'OPEN', body=b'\0')
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

def laf_write(comm, fd_num, offset, data):
    """Read size bytes at the given block offset."""
    #_logger.debug("WRTE(0x%05x, #%d)", offset, len(data)); return
    write_cmd = lglaf.make_request(b'WRTE', args=[fd_num, offset], body=data)
    header = comm.call(write_cmd)[0]
    # Response offset (in bytes) must match calculated offset
    calc_offset = (offset * 512) & 0xffffffff
    resp_offset = read_uint32(header, 8)
    assert write_cmd[4:4+4] == header[4:4+4], "Unexpected write response"
    assert calc_offset == resp_offset, \
            "Unexpected write response: %#x != %#x" % (calc_offset, resp_offset)

def open_local_writable(path):
    if path == '-':
        try: return sys.stdout.buffer
        except: return sys.stdout
    else:
        return open(path, "wb")

def open_local_readable(path):
    if path == '-':
        try: return sys.stdin.buffer
        except: return sys.stdin
    else:
        return open(path, "rb")

# On Linux, one bulk read returns at most 16 KiB. 32 bytes are part of the first
# header, so remove one block size (512 bytes) to stay within that margin.
# This ensures that whenever the USB communication gets out of sync, it will
# always start with a message header, making recovery easier.
MAX_BLOCK_SIZE = (16 * 1024 - 512) // 512
BLOCK_SIZE = 512

def dump_partition(comm, disk_fd, local_path, part_offset, part_size):
    # Read offsets must be a multiple of 512 bytes, enforce this
    read_offset = BLOCK_SIZE * (part_offset // BLOCK_SIZE)
    end_offset = part_offset + part_size
    unaligned_bytes = part_offset % BLOCK_SIZE
    _logger.debug("Will read %d bytes at disk offset %d", part_size, part_offset)
    if unaligned_bytes:
        _logger.debug("Unaligned read, read will start at %d", read_offset)

    with open_local_writable(local_path) as f:
        # Offset should be aligned to block size. If not, read at most a
        # whole block and drop the leading bytes.
        if unaligned_bytes:
            chunksize = min(end_offset - read_offset, BLOCK_SIZE)
            data = laf_read(comm, disk_fd, read_offset // BLOCK_SIZE, chunksize)
            f.write(data[unaligned_bytes:])
            read_offset += BLOCK_SIZE

        while read_offset < end_offset:
            chunksize = min(end_offset - read_offset, BLOCK_SIZE * MAX_BLOCK_SIZE)
            data = laf_read(comm, disk_fd, read_offset // BLOCK_SIZE, chunksize)
            f.write(data)
            read_offset += chunksize

def write_partition(comm, disk_fd, local_path, part_offset, part_size):
    write_offset = BLOCK_SIZE * (part_offset // BLOCK_SIZE)
    end_offset = part_offset + part_size
    # TODO support unaligned writes via read/modify/write
    if part_offset % BLOCK_SIZE:
        raise RuntimeError("Unaligned partition writes are not supported yet")

    # Sanity check
    assert part_offset >= 34 * 512, "Will not allow overwriting GPT scheme"

    with open_local_readable(local_path) as f:
        try:
            length = f.seek(0, 2)
        except OSError:
            # Will try to write up to the end of the file.
            _logger.debug("File %s is not seekable, length is unknown",
                    local_path)
        else:
            # Restore position and check if file is small enough
            f.seek(0)
            if length > part_size:
                raise RuntimeError("File size %d is larger than partition "
                        "size %d" % (length, part_size))
            # Some special bytes report 0 (such as /dev/zero)
            if length > 0:
                _logger.debug("Will write %d bytes", length)

        written = 0
        while write_offset < end_offset:
            chunksize = min(end_offset - write_offset, BLOCK_SIZE * MAX_BLOCK_SIZE)
            data = f.read(chunksize)
            if not data:
                break # End of file
            laf_write(comm, disk_fd, write_offset // BLOCK_SIZE, data)
            written += len(data)
            write_offset += chunksize
            if len(data) != chunksize:
                break # Short read, end of file
        _logger.info("Done after writing %d bytes", written)

parser = argparse.ArgumentParser()
parser.add_argument("--debug", action='store_true', help="Enable debug messages")
parser.add_argument("--dump", metavar="LOCAL_PATH",
        help="Dump partition to file ('-' for stdout)")
parser.add_argument("--load", metavar="LOCAL_PATH",
        help="Write file to partition on device ('-' for stdin)")
parser.add_argument("partition_number", type=int,
        help="Partition number (e.g. 1 for block device mmcblk0p1)")

def main():
    args = parser.parse_args()
    logging.basicConfig(format='%(asctime)s %(name)s: %(levelname)s: %(message)s',
            level=logging.DEBUG if args.debug else logging.INFO)
    part_num = args.partition_number

    if args.dump and args.load:
        parser.error("Please specify one action from --dump / --load")

    comm = lglaf.autodetect_device()
    with closing(comm):
        lglaf.try_hello(comm)
        part_offset, part_size = partition_info(comm, part_num)
        _logger.debug("Partition %d at offset %d (%#x) size %d (%#x)",
                part_num, part_offset, part_offset, part_size, part_size)
        with laf_open_disk(comm) as disk_fd:
            _logger.debug("Opened fd %d for disk", disk_fd)
            if args.dump:
                dump_partition(comm, disk_fd, args.dump, part_offset, part_size)
            elif args.load:
                write_partition(comm, disk_fd, args.load, part_offset, part_size)

if __name__ == '__main__':
    try:
        main()
    except OSError as e:
        # Ignore when stdout is closed in a pipe
        if e.errno != 32:
            raise
