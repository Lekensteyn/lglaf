# LG LAF Protocol
This document is a reverse-engineered protocol description for LG Advanced Flash
(LAF), the download mode offered by various LG models. It is based on analysis
on the `Send_Command.exe` utility and `LGD855_20140526_LGFLASHv160.dll` file and
a USB trace using Wireshark and usbmon on Linux. Some commands were found in the
`/sbin/lafd` binary.

This document uses the following conventions for types:

 - `\xaa\xbb\xcc\xdd` denotes a byte pattern `aa bb cc dd`.
 - `0xddccbbaa` denotes a 32-bit integer in hexadecimal format. It represents
   the same byte pattern as `\xaa\xbb\xcc\xdd`.

## Overview
LAF is a simple request/response protocol operating over USB. The USB details
are described at the end of the document, the messages are described below.

Each message consists of a header, followed by an optional body. The header
contains 32-bit DWORDs, integers are encoded in little-endian form:

| Offset (hex) | Offset (dec) | Type | Description
| ----:| --:| ------- | ---
| 0x00 | 0  | char[4] | Command
| 0x04 | 4  | var     | Argument 1
| 0x08 | 8  | var     | Argument 2
| 0x0c | 12 | var     | Argument 3
| 0x10 | 16 | var     | Argument 4
| 0x14 | 20 | int     | Body length
| 0x18 | 24 | int     | CRC-16
| 0x1c | 28 | char[4] | Bit-wise invertion of command at offset 0

Arguments can be integers or character sequences depending on the command.

The CRC field is the CRC-16-CCITT calculation (LSB-first) over the header and
the body with zeroes in place of CRC.

Each request is followed by a response with a matching command field. If an
error occurs, the response contains command is `FAIL` with argument 1 being the
error code and the original request header as body.

## Commands

### OPEN - Open File
Opens a file path.

Arguments:
 - arg1 (response): DWORD file descriptor.
Request body: NUL-terminated file path that should be opened for reading or an
 empty string to open `/dev/block/mmcblk0` in read/write mode.
(at most 276 (0x114) bytes?)

Non-existing files result in FAIL with error code 0x80000001.

### CLSE - Close File
Closes a file descriptor which was returned by the `OPEN` command.

Arguments:
 - arg1: DWORD file descriptor (same in request and response).

Note: this allows you to close any file descriptor that are in use by the `lafd`
process, not just the one returned by `OPEN`. You can discover the current file
descriptors via `ls -l /proc/$pid/fd` where `$pid` is found by `ps | grep lafd`.

### HELO - Hello
Arguments:
 - arg1: DWORD Protocol Version (`\1\0\0\1`) (resp must match req.)
 - arg2 (response): Minimum Protocol Version (`\0\0\x80\0` was observed)

### CTRL - Control
Arguments:
 - arg1: "RSET" (reboots device), "POFF" (powers device off) or "ONRS"

Note: `CTRL(RSET)` with no body is sent by the `Send_Command.exe` utility for
the `LEAVE` command.

LG Flash DLL waits 5000 milliseconds after this command.

### WRTE - Write File
Writes to a file descriptor.

Arguments:
 - arg1: file descriptor (must be open for writing!)
 - arg2 (request): offset in **blocks** (multiple of 512 bytes).
 - arg2 (response): offset in **bytes**.
Request body: the data to be written. Can be of any size (including 1 or 513).

Note: writing to a file descriptor which was opened for reading results in FAIL
with code 0x82000002. This command is likely used for writing to partitions.

Integer overflow in the response offset is ignored. That is, the block offset
30736384 (0x1d50000) is 0x3aa000000 bytes, but will appear as 0xaa000000.

### READ - Read File
Reads from a file descriptor.

Arguments:
 - arg1: file descriptor.
 - arg2: offset in **blocks** (multiple of 512 bytes).
 - arg3: requested length in bytes (at most 8MiB).
 - arg4: "whence" seek mode (see below).
Response body: data in file at given offset and requested length.

Note: be sure not to read past the end of the file (512 * offset + length), this
will hang the communication, requiring a reset (pull out battery)!

Arg4 affects the seek mode, values for request:
 - 0 (`SEEK_SET`) - seek to `512 * offset`.
 - 1 (`SEEK_CUR`) - read from current position (offset argument is ignored).
 - 2 (`SEEK_END`) - kind of useless when all offsets are unsigned...
 - 3 (`SEEK_DATA`) - FAILs with 0x80000001 when used on `/proc/kmsg` or
   `/dev/block/mmcblk0p44`. Works on a regular file though.
The response matches the request (masked with 0x3).

If the length is larger than somewhere between 227 MiB and 228 MiB, an
0x80000001 error will be raised (observed with /dev/block/mmcblk0). Requesting
lengths larger than 8 MiB however already seem to hang the communication.

### ERSE - Erase Block
TRIMs a block (`IOCTL_TRIM_CMD`).

Arguments:
 - arg1: file descriptor (open `/dev/block/mmcblk0` for writing).
 - arg2: start address (in sectors).
 - arg3: count (in sectors).
 - arg4: unknown, set to zero.
Request body: none.

Note: after sending TRIM, reading the block still returned old values. After a
reboot, everything was zeroed out though.

### EXEC - Execute Command
Arguments: none
Request body: NUL-terminated command, at most 255 bytes including terminator.
Response body: standard output of the command.

The command is split on spaces and then passed to `execvp`. In order to see
standard error, use variables and globbing, use a command such as:

    sh -c eval\t"$*"</dev/null\t2>&1 -- echo $PATH

(replace `\t` by tabs)

If you need to read dmesg (or other blocking files), try to put busybox on the
device (e.g. by writing to an unused partition) and execute:

    /data/busybox timeout -s 2 cat /proc/kmsg

The maximum output size appears to be 0x800001 (`LAF_MAX_DATA_PAYLOAD`). Larger
values result in an error. Output is read per byte, not very efficient for large
output...

### INFO
Arguments:
 - arg1: action (`GPRO` - Get Properties, `SPRO` - Set Properties)
Request body: a `laf_property` structure.
Response body: 2824 (0x00000b08) bytes of binary info.

See [scripts/parse-props.py](scripts/parse-props.py) for the structure of the
property body. This structure begins with a DWORD with a version that is
apparently the same as the expected length (2824 or `\x08\x0b\0\0`).

### UNLK - Unlink
Delete a file.

Arguments: none
Request body: NUL-terminated file name

Responds with FAIL code 0x80000001 if the file name is invalid (missing) or
file does not exist. Deleting directories is also not possible, giving the same
FAIL code 0x80000001.

### RSVD - Reserved
Arguments: none

### IOCT - ioctl
Unknown.

### MISC
WRTE, READ or DAER ETRW or ERDA RWET

### KILO
Unknown.

### DIFF
Unknown.

### SNIF
Unknown.
### OPCM
Unknown.
### CHCK
Unknown.
### FUSE
Unknown.
### CRCC
Unknown.
### FAIL
"why call me! someday will be use? error"
### HELO
Unknown.

## USB layer
The LG Windows driver (via `LGMobileDriver_WHQL_Ver_4.0.3.exe`) exposes two
serial ports, `LGANDNETMDM0` and `LGANDNETDIAG1`. The `LGANDNETDIAG1` port is
used for LAF.

The LG G3 (D855) has Vendor ID 0x1004 and Product ID 0x633e.

There is only one configuration descriptor and LAF uses bulk transfers over
endpoints 5 (for input from the device) and endpoint 3 (for output to the
device).

For other descriptors, see [info/lsusb.txt](info/lsusb.txt).
