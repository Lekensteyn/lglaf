#!/usr/bin/env python
#
# Dump partitions to file.
#
# Copyright (C) 2015 Peter Wu <peter@lekensteyn.nl>
# Licensed under the MIT license <http://opensource.org/licenses/MIT>.

from contextlib import closing
import argparse, logging, os, struct
import lglaf, partitions

_logger = logging.getLogger("extract-partitions")

parser = argparse.ArgumentParser()
parser.add_argument("-d", "--outdir", default=".",
        help="Output directory for disk images.")
# Do not dump partitions larger than this size
# (userdata 11728 MiB, system 2064 MiB, cache 608 MiB, cust 256 MiB)
parser.add_argument("--max-size", metavar="kbytes", type=int, default=65536,
        help="Maximum partition size to dump (in KiB)")
parser.add_argument("--debug", action='store_true', help="Enable debug messages")

def dump_partitions(comm, disk_fd, outdir, max_size):
    parts = partitions.get_partitions(comm)
    for part_label, part_name in parts.items():
        part_offset, part_size = partitions.partition_info(comm, part_name)
        if part_size > max_size:
            _logger.info("Ignoring large partition %s (%s) of size %dK",
                    part_label, part_name, part_size / 1024)
            continue
        out_path = os.path.join(outdir, "%s.bin" % part_name)
        try:
            current_size = os.path.getsize(out_path)
            if current_size > part_size:
                _logger.warn("%s: unexpected size %dK, larger than %dK",
                        out_path, current_size / 1024, part_size / 1024)
                continue
            elif current_size == part_size:
                _logger.info("Skipping partition %s (%s), already found at %s",
                        part_label, part_name, out_path)
                continue
        except OSError: pass
        _logger.info("Dumping partition %s (%s) to %s (%d bytes)",
                part_label, part_name, out_path, part_size)
        partitions.dump_partition(comm, disk_fd, out_path, part_offset, part_size)

def main():
    args = parser.parse_args()
    logging.basicConfig(format='%(asctime)s %(name)s: %(levelname)s: %(message)s',
            level=logging.DEBUG if args.debug else logging.INFO)

    try: os.makedirs(args.outdir)
    except OSError: pass

    comm = lglaf.autodetect_device()
    with closing(comm):
        lglaf.try_hello(comm)
        with partitions.laf_open_disk(comm) as disk_fd:
            _logger.debug("Opened fd %d for disk", disk_fd)
            dump_partitions(comm, disk_fd, args.outdir, args.max_size * 1024)

if __name__ == '__main__':
    main()
