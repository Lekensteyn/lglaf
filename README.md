# LGLAF.py
LGLAF.py is a utility for communication with LG devices in Download Mode. This
allows you to execute arbitrary shell commands on a LG phone as root.

## Requirements
LGLAF.py depends on:

 - Python 2.7 or 3: https://www.python.org/
 - (Recommended) PyUSB: https://walac.github.io/pyusb/

Tested with:

 - LG G3 (D855) on Arch Linux.

## Usage
This tool provides an interactive shell where you can execute commands in
Download Mode. To enter this mode:

 1. Power off the phone.
 2. Press and hold **Volume up**.
 3. Connect the phone to a computer using a USB cable.
 4. Wait for the **Download mode** screen to appear.
 5. Release keys. You should now see a **Firmware Update** screen.

Now you can issue commands using the interactive shell:

    (venv)[peter@al lglaf]$ ./lglaf.py
    LGLAF.py by Peter Wu (https://lekensteyn.nl/lglaf)
    Type a shell command to execute or "exit" to leave.
    # pwd
    /
    # uname -a
    -: uname: not found
    # cat /proc/version
    Linux version 3.4.0-perf-gf95c7ee (lgmobile@LGEARND12B2) (gcc version 4.8 (GCC) ) #1 SMP PREEMPT Tue Aug 18 19:25:04 KST 2015
    # exit

When commands are piped to stdin, the promps is hidden:

    (venv)[peter@al lglaf]$ echo mount | ./lglaf.py
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

Or if you are on Windows and have LG drivers installed:

    > reg query HKLM\hardware\devicemap\SERIALCOMM
    HKEY_LOCAL_MACHINE\hardware\devicemap\SERIALCOMM
        \Device\Serial0         REG_SZ  COM1
        \Device\LGANDNETMDM0    REG_SZ  COM3
        \Device\LGANDNETDIAG1   REG_SZ  COM4
    > python lglaf.py --serial COM4
    LGLAF.py by Peter Wu (https://lekensteyn.nl/lglaf)
    Type a shell command to execute or "exit" to leave.
    # exit
    > echo ls -l | python lglaf.py --serial COM4
    ...

## License
See the [LICENSE](LICENSE) file for the license (MIT).
