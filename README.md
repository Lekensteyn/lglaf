# LGLAF.py
LGLAF.py is a utility for communication with LG devices in Download Mode. This
allows you to execute arbitrary shell commands on a LG phone as root.

Contents of this repository:

 - [lglaf.py](lglaf.py) - main script for communication (see below).
 - [partitions.py](partitions.py) - manage (list / read / write) partitions.
 - [extract-partitions.py](extract-partitions.py) - Dump all partitions
   (convenience script that uses partitions.py under the hood). By default the
   largest partitions (system, cache, cust, userdata) are not dumped though.
   This can be changed with the `--max-size` option.
 - [dump-file.py](dump-file.py) - dumps a regular file from device.
 - [protocol.md](protocol.md) - Protocol documentation.
 - [lglaf.lua](lglaf.lua) - Wireshark dissector for LG LAF protocol.
 - [scripts/](scripts/) - Miscellaneous scripts.

## Requirements
LGLAF.py depends on:

 - Python 2.7 or 3: https://www.python.org/
 - (Windows) LG driver,
   [LGMobileDriver\_WHQL\_Ver\_4.2.0.exe](http://oceanhost.eu/wylc5rg7a8ou/LGMobileDriver_WHQL_Ver_4.2.0.exe.htm)
   (16691672 bytes,
   sha256sum: d78ae6dfe7d34b9cabb8c4de5c6e734b6fed20b513d0da0183871bd77abba56c),
   **WARNING**: This file was found via google search, it's not downloaded directly from LG servers
 - (Linux) PyUSB: https://walac.github.io/pyusb/
 - Cryptography library: https://cryptography.io/en/latest/

On Linux, you must also install
[rules.d/42-usb-lglaf.rules](rules.d/42-usb-lglaf.rules) to `/etc/udev/rules.d/`
in order to give the regular user access to the USB device.

Tested with:

 - LG G3 (D855) on 64-bit Arch Linux (Python 3.5.1, pyusb 1.0.0b2, libusb 1.0.20)
 - LG G3 (D855) on 32-bit Windows XP (Python 3.4.4, LG drivers).
 - LG G2 (VS985).
 - LG G4 (VS986) on Linux (Python 3.5) and Windows.
 - LG K10 2017 (M250N) on Linux (Both Python 2.7.13 and Python 3.5.3).

## Usage
This tool provides an interactive shell where you can execute commands in
Download Mode. To enter this mode:

 1. Power off the phone.
 2. Connect the phone to a computer using a USB cable.
 3. Press and hold **Volume up**.
 4. Briefly press the power button.
 5. Wait for the **Download mode** screen to appear.
 6. Release keys. You should now see a **Firmware Update** screen.

Now you can issue commands using the interactive shell:

    (venv)[peter@al lglaf]$ python lglaf.py
    LGLAF.py by Peter Wu (https://lekensteyn.nl/lglaf)
    Type a shell command to execute or "exit" to leave.
    # pwd
    /
    # uname -a
    -: uname: not found
    # cat /proc/version
    Linux version 3.4.0-perf-gf95c7ee (lgmobile@LGEARND12B2) (gcc version 4.8 (GCC) ) #1 SMP PREEMPT Tue Aug 18 19:25:04 KST 2015
    # exit

When commands are piped to stdin (or given via `-c`), the prompt is hidden:

    (venv)[peter@al lglaf]$ echo mount | python lglaf.py
    rootfs / rootfs rw 0 0
    tmpfs /dev tmpfs rw,seclabel,nosuid,relatime,size=927232k,nr_inodes=87041,mode=755 0 0
    devpts /dev/pts devpts rw,seclabel,relatime,mode=600 0 0
    proc /proc proc rw,relatime 0 0
    sysfs /sys sysfs rw,seclabel,relatime 0 0
    selinuxfs /sys/fs/selinux selinuxfs rw,relatime 0 0
    debugfs /sys/kernel/debug debugfs rw,relatime 0 0
    /dev/block/platform/msm_sdcc.1/by-name/system /system ext4 ro,seclabel,noatime,data=ordered 0 0
    /dev/block/platform/msm_sdcc.1/by-name/userdata /data ext4 rw,seclabel,nosuid,nodev,noatime,noauto_da_alloc,resuid=1000,errors=continue,data=ordered 0 0
    /dev/block/platform/msm_sdcc.1/by-name/persist /persist ext4 ro,seclabel,nosuid,nodev,relatime,data=ordered 0 0
    /dev/block/platform/msm_sdcc.1/by-name/cache /cache ext4 rw,seclabel,nosuid,nodev,noatime,data=ordered 0 0
    (venv)[peter@al lglaf]$ python lglaf.py -c date
    Thu Jan  1 01:30:06 GMT 1970
    (venv)[peter@al lglaf]$

## Advanced usage
If you know the [protocol](protocol.md), you can send commands directly. Each
request has a command, zero to four arguments and possibly a body. The
`lglaf.py` tool accepts this command:

    ![command] [arguments] [body]

All of these words accept escape sequences such as `\0` (octal escape), `\x00`
(hex), `\n`, `\r` and `\t`. The command must be exactly four bytes, the
arguments and body are optional.

Arguments are comma-separated and must either be four-byte sequences (such as
`\0\1\2\3`) or numbers (such as 0x03020100). If no arguments are given, but a
body is needed, keep two spaces between the command and argument.

Reboot device (command CTRL, arg1 RSET, no body):

    $ ./lglaf.py  --debug -c '!CTRL RSET'
    LGLAF.py: DEBUG: Hello done, proceeding with commands
    LGLAF.py: DEBUG: Header: b'CTRL' b'RSET' b'\0\0\0\0' b'\0\0\0\0' b'\0\0\0\0' b'\0\0\0\0' b'\xc7\xeb\0\0' b'\xbc\xab\xad\xb3'

Execute a shell command (command EXEC, no args, with body):

    $ ./lglaf.py --debug --skip-hello -c '!EXEC  id\0'
    LGLAF.py: DEBUG: Header: b'EXEC' b'\0\0\0\0' b'\0\0\0\0' b'\0\0\0\0' b'\0\0\0\0' b'/\0\0\0' b'\x8dK\0\0' b'\xba\xa7\xba\xbc'
    uid=0(root) gid=0(root) context=u:r:toolbox:s0

## License
See the [LICENSE](LICENSE) file for the license (MIT).
