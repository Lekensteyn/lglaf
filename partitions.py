#!/usr/bin/env python
#
# Manage a single partition (info, read, write).
#
# Copyright (C) 2015 Peter Wu <peter@lekensteyn.nl>
# Licensed under the MIT license <http://opensource.org/licenses/MIT>.

from __future__ import print_function
from collections import OrderedDict
from contextlib import closing, contextmanager
import argparse, logging, os, io, struct, sys
import lglaf
import gpt

_logger = logging.getLogger("partitions")

GPT_LBA_LEN = 34

def human_readable(sz):
    suffixes = ('', 'Ki', 'Mi', 'Gi', 'Ti')
    for i, suffix in enumerate(suffixes):
        if sz <= 1024**(i+1):
            break
    return '%.1f %sB' % (sz / 1024**i, suffix)

def read_uint32(data, offset):
    return struct.unpack_from('<I', data, offset)[0]

def get_partitions(comm, fd_num):
    """
    Maps partition labels (such as "recovery") to block devices (such as
    "mmcblk0p0"), sorted by the number in the block device.
    """
    read_offset = 0
    end_offset = GPT_LBA_LEN * BLOCK_SIZE

    table_data = b''
    while read_offset < end_offset:
        chunksize = min(end_offset - read_offset, BLOCK_SIZE * MAX_BLOCK_SIZE)
        data = laf_read(comm, fd_num, read_offset // BLOCK_SIZE, chunksize)
        table_data += data
        read_offset += chunksize

    with io.BytesIO(table_data) as table_fd:
        info = gpt.get_disk_partitions_info(table_fd)
    return info

def find_partition(diskinfo, query):
    partno = int(query) if query.isdigit() else None
    for part in diskinfo.gpt.partitions:
        if part.index == partno or part.name == query:
            return part
    raise ValueError("Partition not found: %s" % query)

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

def laf_erase(comm, fd_num, sector_start, sector_count):
    """TRIM some sectors."""
    erase_cmd = lglaf.make_request(b'ERSE',
            args=[fd_num, sector_start, sector_count])
    header, response = comm.call(erase_cmd)
    # Ensure that response fd, start and count are sane (match the request)
    assert erase_cmd[4:4+12] == header[4:4+12], "Unexpected erase response"

def laf_write(comm, fd_num, offset, data):
    """Write size bytes at the given block offset."""
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

def get_partition_info_string(part):
    info = '#   Flags From(#s)   To(#s)     GUID/UID                             Type/Name\n'
    info += ('{n: <3} {flags: ^5} {from_s: <10} {to_s: <10} {guid} {type}\n' + ' ' * 32 + '{uid} {name}').format(
                n=part.index, flags=part.flags, from_s=part.first_lba, to_s=part.last_lba, guid=part.guid,
                type=part.type, uid=part.uid, name=part.name)
    return info

def list_partitions(comm, fd_num, part_filter=None):
    diskinfo = get_partitions(comm, fd_num)
    if part_filter:
        try:
            part = find_partition(diskinfo, part_filter)
            print(get_partition_info_string(part))
        except ValueError as e:
            print('Error: %s' % e)
    else:
        gpt.show_disk_partitions_info(diskinfo)

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
        _logger.info("Wrote %d bytes to %s", part_size, local_path)

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
        _logger.info("Done after writing %d bytes from %s", written, local_path)

def wipe_partition(comm, disk_fd, part_offset, part_size):
    sector_start = part_offset // BLOCK_SIZE
    sector_count = part_size // BLOCK_SIZE

    # Sanity check
    assert sector_start >= 34, "Will not allow overwriting GPT scheme"
    # Discarding no sectors or more than 512 GiB is a bit stupid.
    assert 0 < sector_count < 1024**3, "Invalid sector count %d" % sector_count

    laf_erase(comm, disk_fd, sector_start, sector_count)
    _logger.info("Done with TRIM from sector %d, count %d (%s)",
            sector_start, sector_count, human_readable(part_size))

parser = argparse.ArgumentParser()
parser.add_argument("--debug", action='store_true', help="Enable debug messages")
parser.add_argument("--list", action='store_true',
        help='List available partitions')
parser.add_argument("--dump", metavar="LOCAL_PATH",
        help="Dump partition to file ('-' for stdout)")
parser.add_argument("--restore", metavar="LOCAL_PATH",
        help="Write file to partition on device ('-' for stdin)")
parser.add_argument("--wipe", action='store_true',
        help="TRIMs a partition")
parser.add_argument("partition", nargs='?',
        help="Partition number (e.g. 1 for block device mmcblk0p1)"
        " or partition name (e.g. 'recovery')")
parser.add_argument("--skip-hello", action="store_true",
        help="Immediately send commands, skip HELO message")

def main():
    args = parser.parse_args()
    logging.basicConfig(format='%(asctime)s %(name)s: %(levelname)s: %(message)s',
            level=logging.DEBUG if args.debug else logging.INFO)

    actions = (args.list, args.dump, args.restore, args.wipe)
    if sum(1 if x else 0 for x in actions) != 1:
        parser.error("Please specify one action from"
        " --list / --dump / --restore / --wipe")
    if not args.partition and (args.dump or args.restore or args.wipe):
        parser.error("Please specify a partition")

    comm = lglaf.autodetect_device()
    with closing(comm):
        
        if not args.skip_hello:
            lglaf.try_hello(comm)

        with laf_open_disk(comm) as disk_fd:
            if args.list:
                list_partitions(comm, disk_fd, args.partition)
                return

            diskinfo = get_partitions(comm, disk_fd)
            try:
                part = find_partition(diskinfo, args.partition)
            except ValueError as e:
                parser.error(e)

            info = get_partition_info_string(part)
            _logger.debug("%s", info)

            part_offset = part.first_lba * BLOCK_SIZE
            part_size = (part.last_lba - (part.first_lba - 1)) * BLOCK_SIZE

            _logger.debug("Opened fd %d for disk", disk_fd)
            if args.dump:
                dump_partition(comm, disk_fd, args.dump, part_offset, part_size)
            elif args.restore:
                write_partition(comm, disk_fd, args.restore, part_offset, part_size)
            elif args.wipe:
                wipe_partition(comm, disk_fd, part_offset, part_size)

if __name__ == '__main__':
    try:
        main()
    except OSError as e:
        # Ignore when stdout is closed in a pipe
        if e.errno != 32:
            raise
