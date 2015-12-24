# LG LAF Protocol
This document is a reverse-engineered protocol description for "LG LAG", the
download mode offered by various LG models. It is based on analysis on the
`Send_Command.exe` utility and `LGD855_20140526_LGFLASHv160.dll` file and a USB
trace using Wireshark and usbmon on Linux. Some commands were found in the
`/sbin/lafd` binary.

## Overview
LAF is a simple request/response protocol operating over USB. The USB details
are described at the end of the document, the messages are described below.

Each message consists of a header, followed by an optional body. The header
contains 32-bit DWORDs, integers are encoded in little-endian form:

| Offset (hex) | Offset (dec) | Type | Description
| ----:| --:| ---
| 0x00 | 0  | char[4] | Command
| 0x04 | 4  | var     | Argument 1
| 0x08 | 8  | var     | Argument 2
| 0x0c | 12 | var     | Argument 3
| 0x10 | 16 | var     | Argument 4 (not encountered)
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

### OPEN - Open
Arguments: none
Request body: at most 276 (0x114) bytes (?)

### CLSE - Close
Arguments: none

### HELO - Hello
Arguments:
 - arg1: DWORD Protocol Version (`\1\0\0\1`) (resp must match req.)
 - arg2 (response): Minimum Protocol Version (`\0\0\x80\0` was observed)

### CTRL - Control
Arguments:
 - arg1: "RSET" or "ONRS"

Note: `CTRL(RSET)` with no body is sent by the `Send_Command.exe` utility for
the `LEAVE` command.

### WRTE - Write
Arguments:
 - arg1: ?
 - arg2: ?

### READ - Read
Arguments:
 - arg1: ?
 - arg2: ?
 - arg3: ?
Response body: present.

(Arguments probably encode read offset, length)

### ERSE - Erase
Arguments:
 - arg1: ?
 - arg2: ?
 - arg3: ?

### EXEC - Execute Command
Arguments: none
Request body: NUL-terminated command.
Response body: standard output of the command.

The command is probably split on space and then passes to `execve`. In order to
see standard error, use variables and globbing, use a command such as:

    sh -c "$@" -- eval 2>&1 echo $PATH

### INFO - Get Info
Arguments:
 - arg1: action (`GPRO` - Get Properties, `SPRO` - Set Properties)
Request body: fixed size 2824 (0xb08)
Response body: present for `GPRO`

### UNLK - Unlock
Arguments: none

### RSVD - Reserved
Arguments: none

### IOCT
Unknown.

### MISC
Unknown.

### KILO
Unknown.

### DIFF
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
