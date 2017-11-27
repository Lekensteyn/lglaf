#!/usr/bin/env python
# coding: utf-8
# vim:et:sta:sts=2:sw=2:ts=2:tw=0:
"""
Source: https://github.com/jrd/pyreadpartitions

Read MBR (msdos) and GPT partitions for a disk on UNIX.
Does not rely on any os tools or library.

Exemple:
  import pyreadpartitions as pyrp
  fp = open('/dev/sda', 'rb')
  info = pyrp.get_disk_partitions_info(fp)
  print(info.mbr)
  print(info.gpt)
  pyrp.show_disk_partitions_info(info)
  fp.close()
  with open('/dev/sda', 'rb') as fp:
    pyrp.show_disk_partitions_info(fp)

"""
from __future__ import print_function, unicode_literals, division, absolute_import

__copyright__ = 'Copyright 2013-2014, Salix OS'
__author__ = 'Cyrille Pontvieux <jrd@salixos.org>'
__credits__ = ['Cyrille Pontvieux']
__email__ = 'jrd@salixos.org'
__license__ = 'MIT'
__version__ = '1.0.0'

from collections import namedtuple
import struct
import sys
import uuid
#from fcntl import ioctl

# http://en.wikipedia.org/wiki/Master_boot_record#Sector_layout
MBR_FORMAT = [
  (b'446x', '_'),  # boot code
  (b'16s', 'partition1'),
  (b'16s', 'partition2'),
  (b'16s', 'partition3'),
  (b'16s', 'partition4'),
  (b'2s', 'signature'),
]
# http://en.wikipedia.org/wiki/Master_boot_record#Partition_table_entries
MBR_PARTITION_FORMAT = [
  (b'B', 'status'),  # > 0x80 => active
  (b'3p', 'chs_first'),  # 8*h + 2*c + 6*s + 8*c
  (b'B', 'type'),
  (b'3p', 'chs_last'),  # 8*h + 2*c + 6*s + 8*c
  (b'L', 'lba'),
  (b'L', 'sectors'),
]
# http://en.wikipedia.org/wiki/Partition_type#List_of_partition_IDs
MBR_PARTITION_TYPE = {
  0x00: 'Empty',
  0x01: 'FAT12',
  0x04: 'FAT16 16-32MB',
  0x05: 'Extended, CHS',
  0x06: 'FAT16 32MB-2GB',
  0x07: 'NTFS',
  0x0B: 'FAT32',
  0x0C: 'FAT32X',
  0x0E: 'FAT16X',
  0x0F: 'Extended, LBA',
  0x11: 'Hidden FAT12',
  0x14: 'Hidden FAT16,16-32MB',
  0x15: 'Hidden Extended, CHS',
  0x16: 'Hidden FAT16,32MB-2GB',
  0x17: 'Hidden NTFS',
  0x1B: 'Hidden FAT32',
  0x1C: 'Hidden FAT32X',
  0x1E: 'Hidden FAT16X',
  0x1F: 'Hidden Extended, LBA',
  0x27: 'Windows recovery environment',
  0x39: 'Plan 9',
  0x3C: 'PartitionMagic recovery partition',
  0x42: 'Windows dynamic extended partition marker',
  0x44: 'GoBack partition',
  0x63: 'Unix System V',
  0x64: 'PC-ARMOUR protected partition',
  0x81: 'Minix',
  0x82: 'Linux Swap',
  0x83: 'Linux',
  0x84: 'Hibernation',
  0x85: 'Linux Extended',
  0x86: 'Fault-tolerant FAT16B volume set',
  0x87: 'Fault-tolerant NTFS volume set',
  0x88: 'Linux plaintext',
  0x8E: 'Linux LVM',
  0x93: 'Hidden Linux',
  0x9F: 'BSD/OS',
  0xA0: 'Hibernation',
  0xA1: 'Hibernation',
  0xA5: 'FreeBSD',
  0xA6: 'OpenBSD',
  0xA8: 'Mac OS X',
  0xA9: 'NetBSD',
  0xAB: 'Mac OS X Boot',
  0xAF: 'Mac OS X HFS',
  0xBE: 'Solaris 8 boot partition',
  0xBF: 'Solaris x86',
  0xE8: 'Linux Unified Key Setup',
  0xEB: 'BFS',
  0xEE: 'EFI GPT protective MBR',
  0xEF: 'EFI system partition',
  0xFA: 'Bochs x86 emulator',
  0xFB: 'VMware File System',
  0xFC: 'VMware Swap',
  0xFD: 'Linux RAID',
}
MBR_EXTENDED_TYPE = [0x05, 0x0F, 0x15, 0x1F, 0x85]
# http://en.wikipedia.org/wiki/Extended_boot_record#Structures
EBR_FORMAT = [
  (b'446x', '_'),
  (b'16s', 'partition'),  # lba = offset from ebr, sectors = size of partition
  (b'16s', 'next_ebr'),  # lba = offset from extended partition, sectors = next EBR + next Partition size
  (b'16x', '_'),
  (b'16x', '_'),
  (b'2s', 'signature'),
]
# http://en.wikipedia.org/wiki/GUID_Partition_Table#Partition_table_header_.28LBA_1.29
GPT_HEADER_FORMAT = [
  (b'8s', 'signature'),
  (b'H', 'revision_minor'),
  (b'H', 'revision_major'),
  (b'L', 'header_size'),
  (b'L', 'crc32'),
  (b'4x', '_'),
  (b'Q', 'current_lba'),
  (b'Q', 'backup_lba'),
  (b'Q', 'first_usable_lba'),
  (b'Q', 'last_usable_lba'),
  (b'16s', 'disk_guid'),
  (b'Q', 'part_entry_start_lba'),
  (b'L', 'num_part_entries'),
  (b'L', 'part_entry_size'),
  (b'L', 'crc32_part_array'),
]
# http://en.wikipedia.org/wiki/GUID_Partition_Table#Partition_entries_.28LBA_2.E2.80.9333.29
GPT_PARTITION_FORMAT = [
  (b'16s', 'guid'),
  (b'16s', 'uid'),
  (b'Q', 'first_lba'),
  (b'Q', 'last_lba'),
  (b'Q', 'flags'),
  (b'72s', 'name'),
]
# http://en.wikipedia.org/wiki/GUID_Partition_Table#Partition_type_GUIDs
GPT_GUID = {
  '024DEE41-33E7-11D3-9D69-0008C781F39F': 'MBR partition scheme',
  'C12A7328-F81F-11D2-BA4B-00A0C93EC93B': 'EFI System partition',
  '21686148-6449-6E6F-744E-656564454649': 'BIOS Boot partition',
  'D3BFE2DE-3DAF-11DF-BA40-E3A556D89593': 'Intel Fast Flash (iFFS) partition (for Intel Rapid Start technology)',
  'F4019732-066E-4E12-8273-346C5641494F': 'Sony boot partition',
  'BFBFAFE7-A34F-448A-9A5B-6213EB736C22': 'Lenovo boot partition',
  'E3C9E316-0B5C-4DB8-817D-F92DF00215AE': 'Microsoft Reserved Partition (MSR)',
  'EBD0A0A2-B9E5-4433-87C0-68B6B72699C7': 'Basic data partition',
  '5808C8AA-7E8F-42E0-85D2-E1E90434CFB3': 'Logical Disk Manager (LDM) metadata partition',
  'AF9B60A0-1431-4F62-BC68-3311714A69AD': 'Logical Disk Manager data partition',
  'DE94BBA4-06D1-4D40-A16A-BFD50179D6AC': 'Windows Recovery Environment',
  '37AFFC90-EF7D-4E96-91C3-2D7AE055B174': 'IBM General Parallel File System (GPFS) partition',
  '75894C1E-3AEB-11D3-B7C1-7B03A0000000': 'Data partition',
  'E2A1E728-32E3-11D6-A682-7B03A0000000': 'Service Partition',
  '0FC63DAF-8483-4772-8E79-3D69D8477DE4': 'Linux filesystem data',
  'A19D880F-05FC-4D3B-A006-743F0F84911E': 'RAID partition',
  '0657FD6D-A4AB-43C4-84E5-0933C84B4F4F': 'Swap partition',
  'E6D6D379-F507-44C2-A23C-238F2A3DF928': 'Logical Volume Manager (LVM) partition',
  '933AC7E1-2EB4-4F13-B844-0E14E2AEF915': '/home partition',
  '3B8F8425-20E0-4F3B-907F-1A25A76F98E8': '/srv partition',
  '7FFEC5C9-2D00-49B7-8941-3EA10A5586B7': 'Plain dm-crypt partition',
  'CA7D7CCB-63ED-4C53-861C-1742536059CC': 'LUKS partition',
  '8DA63339-0007-60C0-C436-083AC8230908': 'Reserved',
  '83BD6B9D-7F41-11DC-BE0B-001560B84F0F': 'Boot partition',
  '516E7CB4-6ECF-11D6-8FF8-00022D09712B': 'Data partition',
  '516E7CB5-6ECF-11D6-8FF8-00022D09712B': 'Swap partition',
  '516E7CB6-6ECF-11D6-8FF8-00022D09712B': 'Unix File System (UFS) partition',
  '516E7CB8-6ECF-11D6-8FF8-00022D09712B': 'Vinum volume manager partition',
  '516E7CBA-6ECF-11D6-8FF8-00022D09712B': 'ZFS partition',
  '48465300-0000-11AA-AA11-00306543ECAC': 'Hierarchical File System Plus (HFS+) partition',
  '55465300-0000-11AA-AA11-00306543ECAC': 'Apple UFS',
  '6A898CC3-1DD2-11B2-99A6-080020736631': 'ZFS',
  '52414944-0000-11AA-AA11-00306543ECAC': 'Apple RAID partition',
  '52414944-5F4F-11AA-AA11-00306543ECAC': 'Apple RAID partition, offline',
  '426F6F74-0000-11AA-AA11-00306543ECAC': 'Apple Boot partition',
  '4C616265-6C00-11AA-AA11-00306543ECAC': 'Apple Label',
  '5265636F-7665-11AA-AA11-00306543ECAC': 'Apple TV Recovery partition',
  '53746F72-6167-11AA-AA11-00306543ECAC': 'Apple Core Storage (i.e. Lion FileVault) partition',
  '6A82CB45-1DD2-11B2-99A6-080020736631': 'Boot partition',
  '6A85CF4D-1DD2-11B2-99A6-080020736631': 'Root partition',
  '6A87C46F-1DD2-11B2-99A6-080020736631': 'Swap partition',
  '6A8B642B-1DD2-11B2-99A6-080020736631': 'Backup partition',
  '6A898CC3-1DD2-11B2-99A6-080020736631': '/usr partition',
  '6A8EF2E9-1DD2-11B2-99A6-080020736631': '/var partition',
  '6A90BA39-1DD2-11B2-99A6-080020736631': '/home partition',
  '6A9283A5-1DD2-11B2-99A6-080020736631': 'Alternate sector',
  '6A945A3B-1DD2-11B2-99A6-080020736631': 'Reserved partition',
  '6A9630D1-1DD2-11B2-99A6-080020736631': 'Reserved partition',
  '6A980767-1DD2-11B2-99A6-080020736631': 'Reserved partition',
  '6A96237F-1DD2-11B2-99A6-080020736631': 'Reserved partition',
  '6A8D2AC7-1DD2-11B2-99A6-080020736631': 'Reserved partition',
  '49F48D32-B10E-11DC-B99B-0019D1879648': 'Swap partition',
  '49F48D5A-B10E-11DC-B99B-0019D1879648': 'FFS partition',
  '49F48D82-B10E-11DC-B99B-0019D1879648': 'LFS partition',
  '49F48DAA-B10E-11DC-B99B-0019D1879648': 'RAID partition',
  '2DB519C4-B10F-11DC-B99B-0019D1879648': 'Concatenated partition',
  '2DB519EC-B10F-11DC-B99B-0019D1879648': 'Encrypted partition',
  'FE3A2A5D-4F32-41A7-B725-ACCC3285A309': 'ChromeOS kernel',
  '3CB8E202-3B7E-47DD-8A3C-7FF2A13CFCEC': 'ChromeOS rootfs',
  '2E0A753D-9E48-43B0-8337-B15192CB1B5E': 'ChromeOS future use',
  '42465331-3BA3-10F1-802A-4861696B7521': 'Haiku BFS',
  '85D5E45E-237C-11E1-B4B3-E89A8F7FC3A7': 'Boot partition',
  '85D5E45A-237C-11E1-B4B3-E89A8F7FC3A7': 'Data partition',
  '85D5E45B-237C-11E1-B4B3-E89A8F7FC3A7': 'Swap partition',
  '0394EF8B-237E-11E1-B4B3-E89A8F7FC3A7': 'Unix File System (UFS) partition',
  '85D5E45C-237C-11E1-B4B3-E89A8F7FC3A7': 'Vinum volume manager partition',
  '85D5E45D-237C-11E1-B4B3-E89A8F7FC3A7': 'ZFS partition',
  'BFBFAFE7-A34F-448A-9A5B-6213EB736C22': 'Ceph Journal',
  '45B0969E-9B03-4F30-B4C6-5EC00CEFF106': 'Ceph dm-crypt Encrypted Journal',
  '4FBD7E29-9D25-41B8-AFD0-062C0CEFF05D': 'Ceph OSD',
  '4FBD7E29-9D25-41B8-AFD0-5EC00CEFF05D': 'Ceph dm-crypt OSD',
  '89C57F98-2FE5-4DC0-89C1-F3AD0CEFF2BE': 'Ceph disk in creation',
  '89C57F98-2FE5-4DC0-89C1-5EC00CEFF2BE': 'Ceph dm-crypt disk in creation',
}


def make_fmt(name, fmt, extras=[]):
  packfmt = b'<' + b''.join(t for t, n in fmt)
  tupletype = namedtuple(name, [n for t, n in fmt if n != '_'] + extras)
  return (packfmt, tupletype)


class MBRError(Exception):
  pass


class MBRMissing(MBRError):
  pass


class GPTError(Exception):
  pass


class GPTMissing(GPTError):
  pass


def read_mbr_header(fp):
  fmt, MBRHeader = make_fmt('MBRHeader', MBR_FORMAT)
  data = fp.read(struct.calcsize(fmt))
  header = MBRHeader._make(struct.unpack(fmt, data))
  if header.signature != b'\x55\xAA':
    raise MBRMissing('Bad MBR signature')
  return header


def read_mbr_partitions(fp, header):
  def read_mbr_partition(partstr, num):
    fmt, MBRPartition = make_fmt('MBRPartition', MBR_PARTITION_FORMAT, extras=['index', 'active', 'type_str'])
    part = MBRPartition._make(struct.unpack(fmt, partstr) + (num, False, ''))
    if part.type:
      ptype = 'Unknown'
      if part.type in MBR_PARTITION_TYPE:
        ptype = MBR_PARTITION_TYPE[part.type]
      part = part._replace(active=part.status >= 0x80, type_str=ptype)
      return part

  def read_ebr_partition(fp, extended_lba, lba, num):
    fp.seek((extended_lba + lba) * 512)  # lba size is fixed to 512 for MBR
    fmt, EBR = make_fmt('EBR', EBR_FORMAT)
    data = fp.read(struct.calcsize(fmt))
    ebr = EBR._make(struct.unpack(fmt, data))
    if ebr.signature != b'\x55\xAA':
      raise MBRError('Bad EBR signature')
    parts = [read_mbr_partition(ebr.partition, num)]
    if ebr.next_ebr != 16 * b'\x00':
      part_next_ebr = read_mbr_partition(ebr.next_ebr, 0)
      next_lba = part_next_ebr.lba
      parts.extend(read_ebr_partition(fp, extended_lba, next_lba, num + 1))
    return parts
  parts = []
  for i in range(1, 4):
    part = read_mbr_partition(getattr(header, 'partition{0}'.format(i)), i)
    if part:
      parts.append(part)
  extendpart = None
  for part in parts:
    if part.type in MBR_EXTENDED_TYPE:
      extendpart = part
      break
  if extendpart:
    parts.extend(read_ebr_partition(fp, extendpart.lba, 0, 5))
  return parts


def read_gpt_header(fp, lba_size=512):
  try:
    # skip MBR (if any)
    fp.seek(1 * lba_size)
  except IOError as e:
    raise GPTError(e)
  fmt, GPTHeader = make_fmt('GPTHeader', GPT_HEADER_FORMAT)
  data = fp.read(struct.calcsize(fmt))
  header = GPTHeader._make(struct.unpack(fmt, data))
  if header.signature != b'EFI PART':
    raise GPTMissing('Bad GPT signature')
  revision = header.revision_major + (header.revision_minor / 10)
  if revision < 1.0:
    raise GPTError('Bad GPT revision: {0}.{1}'.format(header.revision_major, header.revision_minor))
  if header.header_size < 92:
    raise GPTError('Bad GPT header size: {0}'.format(header.header_size))
  header = header._replace(
    disk_guid=str(uuid.UUID(bytes_le=header.disk_guid)).upper(),
  )
  return header


def read_gpt_partitions(fp, header, lba_size=512):
  fp.seek(header.part_entry_start_lba * lba_size)
  fmt, GPTPartition = make_fmt('GPTPartition', GPT_PARTITION_FORMAT, extras=['index', 'type'])
  parts = []
  for i in range(header.num_part_entries):
    data = fp.read(header.part_entry_size)
    if len(data) < struct.calcsize(fmt):
      raise GPTError('Short GPT partition entry #{0}'.format(i + 1))
    part = GPTPartition._make(struct.unpack(fmt, data) + (i + 1, ''))
    if part.guid == 16 * b'\x00':
      continue
    guid = str(uuid.UUID(bytes_le=part.guid)).upper()
    ptype = 'Unknown'
    if guid in GPT_GUID:
      ptype = GPT_GUID[guid]
    part = part._replace(
      guid=guid,
      uid=str(uuid.UUID(bytes_le=part.uid)).upper(),
      # cut on C-style string termination; otherwise you'll see a long row of NILs for most names
      name=part.name.decode('utf-16').split(u'\0', 1)[0],
      type=ptype,
    )
    parts.append(part)
  return parts


class DiskException(Exception):
  pass


def check_disk_file(disk):
  try:
    disk.tell()
  except:
    raise DiskException('Please provide a file pointer (sys.stding or result of open function) as first argument, pointing to an existing disk such as /dev/sda.')


def get_mbr_info(disk):
  check_disk_file(disk)
  disk.seek(0)
  try:
    mbrheader = read_mbr_header(disk)
    partitions = read_mbr_partitions(disk, mbrheader)
    return namedtuple('MBRInfo', 'lba_size, partitions')(512, partitions)
  except MBRMissing:
    return None
  except MBRError:
    return None


def get_gpt_info(disk):
  check_disk_file(disk)
  disk.seek(0)
  info = {
    'lba_size': None,
    'revision_minor': None,
    'revision_major': None,
    'crc32': None,
    'current_lba': None,
    'backup_lba': None,
    'first_usable_lba': None,
    'last_usable_lba': None,
    'disk_guid': None,
    'part_entry_start_lba': None,
    'num_part_entries': None,
    'part_entry_size': None,
    'crc32_part_array': None,
    'partitions': [],
  }
  # EDIT by tuxuser: we are only working with datachunks, not real block devices
  # Using hardcoded LBA size for usage by LGLAF
  #try:
  #  blocksize = struct.unpack('i', ioctl(disk.fileno(), 4608 | 104, struct.pack('i', -1)))[0]
  #except:
  #  blocksize = 512
  blocksize = 512
  try:
    info['lba_size'] = blocksize
    gptheader = read_gpt_header(disk, lba_size=blocksize)
    for key in [k for k in info.keys() if k not in ('lba_size', 'partitions')]:
      info[key] = getattr(gptheader, key)
    info['partitions'] = read_gpt_partitions(disk, gptheader, lba_size=blocksize)
    return namedtuple('GPTInfo', info.keys())(**info)
  except GPTMissing:
    return None
  except GPTError:
    return None


def get_disk_partitions_info(disk):
  check_disk_file(disk)
  return namedtuple('DiskInfo', 'mbr, gpt')(get_mbr_info(disk), get_gpt_info(disk))

def show_disk_partitions_info(diskOrInfo):
  fileUsed = None
  if hasattr(diskOrInfo, 'read'):
    info = get_disk_partitions_info(diskOrInfo)
  else:
    info = diskOrInfo

  if info.mbr:
    mbr = info.mbr
    print('MBR Header')
    print('LBA size (sector size): {0}', mbr.lba_size)
    print('Number of MBR partitions: {0}'.format(len(mbr.partitions)))
    print('#  Active From(#s)   Size(#s)   Code Type')
    for part in mbr.partitions:
      print('{n: <2} {boot: ^6} {from_s: <10} {size_s: <10} {code: ^4X} {type}'.format(n=part.index, boot='*' if part.active else '_', from_s=part.lba, size_s=part.sectors, code=part.type, type=part.type_str))
  else:
    print('No MBR')
  print('---')
  if info.gpt:
    gpt = info.gpt
    print('GPT Header')
    print('Disk GUID: {0}'.format(gpt.disk_guid))
    print('LBA size (sector size): {0}'.format(gpt.lba_size))
    print('GPT First LBA: {0}'.format(gpt.current_lba))
    print('GPT Last  LBA: {0}'.format(gpt.backup_lba))
    print('Number of GPT partitions: {0}'.format(len(gpt.partitions)))
    print('#   Flags From(#s)   To(#s)     GUID/UID                             Type/Name')
    for part in gpt.partitions:
      print(('{n: <3} {flags: ^5} {from_s: <10} {to_s: <10} {guid} {type}\n' + ' ' * 32 + '{uid} {name}').format(n=part.index, flags=part.flags, from_s=part.first_lba, to_s=part.last_lba, guid=part.guid, type=part.type, uid=part.uid, name=part.name))
  else:
    print('No GPT')
  print('---')
  if fileUsed:
    fileUsed.close()


if __name__ == '__main__':
  fp = sys.stdin
  if len(sys.argv) > 1:
    fp = open(sys.argv[1])
  try:
    show_disk_partitions_info(fp)
  except DiskException as e:
    print(e, file=sys.stderr)
  if fp != sys.stdin:
    fp.close()
