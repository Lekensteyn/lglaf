# LGLAF.py
LGLAF.py is a utility for communication with LG devices in Download Mode. This
allows you to execute arbitrary shell commands on a LG phone as root.

## Requirements
LGLAF.py depends on:

 - Python 2.7 or 3: https://www.python.org/
 - (Windows) LG driver,
   [LGMobileDriver\_WHQL\_Ver\_4.0.3.exe](http://18d5a.wpc.azureedge.net/8018D5A/tool/dn/downloader.dev?fileKey=UW00120120425)
   (12986920 bytes,
   sha256sum: 86e893b7f5da7f7d2656d9ce2563f082271983bb63903d0ed5cb279c560db459)
 - (Linux) PyUSB: https://walac.github.io/pyusb/

Tested with:

 - LG G3 (D855) on 64-bit Arch Linux (Python 3.5.1, pyusb 1.0.0b2, libusb 1.0.20)
 - LG G3 (D855) on 32-bit Windows XP (Python 3.4.4, LG drivers).

## Usage
This tool provides an interactive shell where you can execute commands in
Download Mode. To enter this mode:

 1. Power off the phone.
 2. Press and hold **Volume up**.
 3. Connect the phone to a computer using a USB cable.
 4. Wait for the **Download mode** screen to appear.
 5. Release keys. You should now see a **Firmware Update** screen.

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

When commands are piped to stdin, the prompt is hidden:

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
    (venv)[peter@al lglaf]$

## License
See the [LICENSE](LICENSE) file for the license (MIT).
