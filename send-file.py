#!/usr/bin/env python
import lglaf
import sys


comm = lglaf.autodetect_device()


def make_exec_request(shell_command):
  argv = b'sh -c eval\t"$*"\t -- '
  argv += shell_command.encode('ascii')
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

		# 33 = len('sh -c eval\t"$*"\t -- echo -en "">>')
		block_size = (255 - (33 + len(dst))) / 4
		send_command(b'echo -n>' + dst.encode('ascii'))
		writed = 0

		while True:
			data = fp.read(block_size)
			if not data:
				break

			hexstr = b''.join(b'\\x%02x' % ord(ch) for ch in data)
			send_command(b'echo -en "{0}">>{1}'.format(hexstr, dst))

			writed += len(data)
			sys.stderr.write('\rSending... %.2f%% ' % (float(writed) / size * 100))

		sys.stderr.write('\n')



if len(sys.argv) != 3:
	print 'Usage: {0} <local> <remote>'.format(sys.argv[0])
	exit(1)


send_file(sys.argv[1], sys.argv[2])
