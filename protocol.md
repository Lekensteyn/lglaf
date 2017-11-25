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

On newer versions, this requires authentication via `KILO` command.

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
Reboot or power off.
Arguments:
 - arg1: sub-command:
    - `POFF`: power off
    - `RSON`: restart lafd
    - `RSET`: reboot with param `oem-90466252` (normal reboot)
    - `ONRS`: reboot with param `oem-02179092`
    - `AATD`: reboot with param `aat_enter`

Note: `CTRL(RSET)` with no body is sent by the `Send_Command.exe` utility for
the `LEAVE` command.

LG Flash DLL waits 5000 milliseconds after this command.

Purpose of `ONRS` and `AATD` are unknown. Both seem to reboot normally. Probably
one is meant to enter fastboot?

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

This can be used to write to already-opened files without authentication, but
lafd doesn't appear to have any files opened for writing by default.

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
lengths larger than 8 MiB however already seem to hang the communication. Length
can be zero to test if a file is readable.

This can be used to read already-opened files without authentication, but lafd
seems to only have PNG files and `/dev/null` open by default. Attempting to read
`/dev/null` hangs communication.

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

On newer versions, this requires authentication via `KILO` command, and few
commands are allowed.

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
Miscellaneous commands.

Arguments:
 - arg1: Subcommand:
    - IDDD: create `/data/idt.cfg` ("indirect config file") and start IDT thread
    - PDDD: unzip DF file
    - QDDD: verify `/system/DFFileList.txt`
    - RDDD: execute `/system/DFFileList.txt`
    - SDDD: LCD test (turns screen grey)
    - TDDD: set properties and disable USB:
        - `ro.boot.laf = MID`
        - `sys.usb.config = none`

### IOCT - ioctl
Perform flash IOCTLs. (XXX document this)

### MISC
Read/write misc parttition.

Arguments:
 - arg1: Subcommand
    - `READ`
    - `WRTE`

XXX document this

### KILO
Challenge/response to authenticate for some commands.

Arguments:
 - arg1: `CENT` or `METR`
 - arg2: challenge/mode

1. Host sends `CENT` with arg2=0
2. Device responds `CENT` with a random value in arg2
3. Host responds `METR` with desired mode in arg2 and challenge response as body
4. Device responds `METR` with no body, or `FAIL`

The response must decrypt to the bytes
`00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F`. TODO: explain protocol

### DIFF
Execute a script of some sort, path specified in message body.

### SNIF
Unknown / looks related to TOT download (TODO: document this)

Arguments:
 - arg1: Subcommand
    - `REQS`
    - `OPEN`
    - `WRTE`
    - `CLSE`
    - `STUS`
    - `IDDD`

### OPCM
Check/Write opcode

NOTE: Supported since Protocol version `0x1000004`

Arguments:
 - arg1: action (`CHEK` - Check opcode, `WRTE` - Write opcode)

### FUSE
Get or set efuse(s) (TODO: document this)

Arguments:
 - arg1: action (`GFUS` - Get efuse state, `SFRS` - Set/blow efuse)

### WRZR
Write zeroes

### CRCC
Calculcate CRC (TODO: document this)

### CHCK
Unknown (TODO: document this)

NOTE: Supported since Protocol version `0x1000003`

Arguments:
 - arg1: Subcommand
    - `TSUM`
    - `CLER`

### SEBP
Set eMMC boot partition (TODO: document this)

### SBLU
Set UFS boot LUN# (TODO: document this)

### MBPT
Manipulate boot partition table (TODO: document this)

### FAIL
Dummy command.

### new versions
TODO: document these commands added in some version:
TOFF, COPY, SLEI, SIGN


## HDLC commands
These are sent through the same interface, but have a different structure:

* The packet must be at least 3 and at most 31 bytes long.
* The last byte must be 0x7E.
* Any 0x7D byte is skipped; the next byte is then XORed with 0x20. eg 0x7D 0x5E
  becomes 0x7E. (Not sure why this is done.)
* The last two bytes of the body are a CRC16.

After decoding, the body is checked for an 0x7E byte (except the very last byte
of the packet); if one is found, all bytes up to and including it are discarded.
This is done before the checksum is validated. (for example, 0x7E marks the
beginning of the body, but can be omitted, in which case the body starts at the
first byte of the packet.)

The first byte of the body is a command:
* 0x06: unknown. Always responds with 0x02?
* 0x0A: Sets misc partition item 0x1C0 and reboots. (XXX investigate)
* 0xEF: webdload_proc
* 0xFA: testmode_proc

Additionally, sending a packet which decodes to an empty body (for example, a
packet of only `0x7E 0x7E 0x7E 0x7E`) restarts lafd. Unsure if this is
intentional.

### webdload_proc
First byte of body (after 0xEF command byte) is subcommand:
* 0x00: returns 0x05 and writes 0x04 at input[3]
* 0xA0: returns device OS version, target operator, model, etc.
* 0xA1, 0xA2, 0xB0, 0xB1, 0xB2, 0xB5: all return all-zero response.

These appear to also read/write some misc partition values.

### testmode_proc
First two bytes (after 0xFA command byte) must be 0x94 0x00. Next byte after
that is subcommand for `laf_testmode_bootloader_unlock_handler`:
* 0x00: Check if unlocked. (`/sys/devices/platform/lge-msm8226-qfprom/unlock`
  contains 0x277F.)
* 0x01: Always returns 0.
* 0x02: Reads hex from `/sys/devices/platform/lge-msm8226-qfprom/unlock-extra`.
* 0x03: Read `/persist/rct`.

Commands 0x00 and 0x02 don't work on some devices, since they have `lge-qfprom`
instead of `lge-msm8226-qfprom` directory.

#### Return data
0xFA 0x94 0x00 followed by response body followed by CRC16 and 0x7E, encoded the
same way as the command packet.

First byte of response body is a status code:
* 0x00: OK
* 0x01: Failed
* 0x02: Return from command 0x06 (might be LAF_ERROR_INVALID_PARAMETER? but it
  can only ever return this.)
* 0x05: Return from webdload_proc subcommand 0x00 (might be
  LAF_ERROR_INTERNAL_ERROR?)
* 0xFF: Invalid command

Following response bytes depend on the command:
* testmode_proc: null-terminated string (eg "lock", "unlock", "fail") followed
  by unknown bytes (0x19 0xEA 0xE8 0x7F 0x00 0x00 observed)
* webdload_proc: several strings of device info


## Encoded commands
For convenience, valid commands encoded with CRC:
* 0xEF 0x00 0x00 0x00 0xAD 0xFA 0x7E
* 0xEF 0xA0 0x00 0x00 0x7A 0xF5 0x7E
* 0xEF 0xA1 0x00 0x00 0xA6 0xAF 0x7E
* 0xEF 0xA2 0x00 0x00 0xC2 0x40 0x7E
* 0xEF 0xB0 0x00 0x00 0xEF 0x70 0x7E
* 0xEF 0xB1 0x00 0x00 0x33 0x2A 0x7E
* 0xEF 0xB2 0x00 0x00 0x57 0xC5 0x7E
* 0xEF 0xB5 0x00 0x00 0x52 0x49 0x7E
* 0xFA 0x94 0x00 0x00 0x43 0xBD 0x7E
* 0xFA 0x94 0x00 0x01 0xCA 0xAC 0x7E
* 0xFA 0x94 0x00 0x02 0x51 0x9E 0x7E
* 0xFA 0x94 0x00 0x03 0xD8 0x8F 0x7E
* 0xFA 0x94 0x00 0x04 0x67 0xFB 0x7E


## USB layer
The LG Windows driver (via `LGMobileDriver_WHQL_Ver_4.0.3.exe`) exposes two
serial ports, `LGANDNETMDM0` and `LGANDNETDIAG1`. The `LGANDNETDIAG1` port is
used for LAF.

The LG G3 (D855) has Vendor ID 0x1004 and Product ID 0x633e.

There is only one configuration descriptor and LAF uses bulk transfers over
endpoints 5 (for input from the device) and endpoint 3 (for output to the
device).

For other descriptors, see [info/lsusb.txt](info/lsusb.txt).
