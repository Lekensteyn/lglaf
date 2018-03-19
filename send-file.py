#!/usr/bin/env python
import lglaf

import argparse
import sys


comm = lglaf.autodetect_device()


def make_exec_request(shell_command):
  argv = b'sh -c eval\t"$*"\t -- '
  argv += shell_command.encode('ascii') if isinstance(shell_command, str) else shell_command

  if len(argv) > 255:
    raise RuntimeError("Command length %d is larger than 255" % len(argv))

  return lglaf.make_request(b'EXEC', body=argv + b'\0')


def send_command(cmd):
  cmd = make_exec_request(cmd)
  return comm.call(cmd)[1]


def send_file(src, dst):
  with open(src, 'rb') as fp:
    fp.seek(0, 2)
    size = fp.tell()
    fp.seek(0)

    overhead = len('sh -c eval\t"$*"\t -- printf "">>')
    block_size = (255 - (overhead + len(dst))) // 4
    send_command(b'printf >' + dst.encode('ascii'))
    written = 0

    while True:
      data = fp.read(block_size)
      if not data:
        break

      dlen = len(data)

      if isinstance(data, str):
        data = [ord(ch) for ch in data]

      hexstr = ''.join('\\x{:02x}'.format(ch) for ch in data)
      send_command('printf "{0}">>{1}'.format(hexstr, dst))

      written += dlen
      sys.stderr.write('\rSending... %.2f%% ' % (100.0 * written / size))

    sys.stderr.write('\n')


parser = lglaf.parser

parser.add_argument('local')
parser.add_argument('remote')
args = parser.parse_args()

send_file(args.local, args.remote)
