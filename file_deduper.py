#!/usr/bin/env python3

import datetime
import sys
import os
import stat
from typing import AnyStr, List, Optional, Union
from hashlib import sha256

# https://stackoverflow.com/questions/53418046/how-do-i-type-hint-a-variable-that-can-be-passed-as-the-first-argument-to-open
def sha256sum(filename: Union[str, bytes, os.PathLike]) -> bytes:
    hash = sha256()
    with open(filename, "rb") as f:
        for chunk in iter(lambda: f.read(128 * hash.block_size), b""):
            hash.update(chunk)
    return hash.digest()

def to_hex(checksum: Optional[bytes]) -> str:
    if checksum is None:
        return "----------------------------------------------------------------"
    else:
        return checksum.hex()

class Entry:
    def __init__(self, parent: "Optional[Entry]",
                 path: Union[str, bytes, os.PathLike],
                 is_dir: bool, date_modified: int,
                 size: int, checksum: Optional[bytes]):
        self.parent = parent
        self.children: list[Entry] = []
        self.path = path
        self.is_dir = is_dir
        self.date_modified = date_modified
        self.size = size
        self.checksum = checksum

    def name(self) -> AnyStr:
        return os.path.basename(self.path)

    def __repr__(self) -> str:
        # 12 is enough for ~9.1 TiB
        size = "{:>12}".format(self.size)
        # removing .strftime() brings default formatting (which also prints second fractions)
        date = datetime.datetime.fromtimestamp(self.date_modified).strftime('%Y-%m-%d %H:%M:%S')
        return f"{date} {size} {to_hex(self.checksum)} {self.path}"

def make_entry(parent: Optional[Entry],
               path: Union[str, bytes, os.PathLike],
               stats: os.stat_result) -> Entry:
    is_dir = stat.S_ISDIR(stats.st_mode)
    if is_dir:
        checksum = None
        size = 0
    else:
        checksum = sha256sum(path)
        size = stats.st_size
    return Entry(parent, path, is_dir, stats.st_mtime, size, checksum)

class Database:
    def __init__(self):
        self.entries_by_name:     dict[str, list[Entry]] = {}
        self.entries_by_checksum: dict[bytes, list[Entry]] = {}
        self.total_dirs = 0
        self.total_files = 0

    def _update_dict(self, d: dict, key, entry: Entry):
        l = d.get(key)
        if l:
            l.append(entry)
        else:
            d.update([(key, [entry])])

    def add(self, entry: Entry):
        self._update_dict(self.entries_by_name, entry.name(), entry)
        if entry.is_dir:
            self.total_dirs += 1
        else:
            # checksum is computed only for files
            # directories should compare checksums of their children
            self._update_dict(self.entries_by_checksum, entry.checksum, entry)
            self.total_files += 1

    def print(self, all: bool = False):
        print("duplicate by name:")
        for name, entries in self.entries_by_name.items():
            if all or len(entries) > 1:
                print() # empty line to separate groups of duplicates
                for entry in entries:
                    print(entry)

        print("\n\nduplicate by checksum:")
        for checksum, entries in self.entries_by_checksum.items():
            if all or len(entries) > 1:
                print() # empty line to separate groups of duplicates
                for entry in entries:
                    print(entry)

        print(f"\n\ntotal dirs: {self.total_dirs}")
        print(f"total files: {self.total_files}")


def walktree(parent: Entry, database: Database):
    for name in os.listdir(parent.path):
        path = os.path.join(parent.path, name)
        stats = os.lstat(path)
        if stat.S_ISDIR(stats.st_mode) or stat.S_ISREG(stats.st_mode):
            entry = make_entry(parent, path, stats)
            parent.children.append(entry)
            database.add(entry)
            if entry.is_dir:
                walktree(entry, database)
                for child in entry.children:
                    entry.size += child.size
        else:
            print(f"Skipping unsupported filesystem type: {path}")

def scan(root_dirs: List[Union[str, bytes, os.PathLike]]):
    database = Database()
    for root_dir in root_dirs:
        root_entry = make_entry(None, root_dir, os.lstat(root_dir))
        walktree(root_entry, database)
    database.print()

if __name__ == "__main__":
    if len(sys.argv) == 1:
        print("enter 1 or more paths, both absolute and relative work")
        exit(1)
    scan(sys.argv[1:])

# dict by size+checksum, not checksum
# print total size of duplicates
# print total amount of duplicate sets
# remove files that have "XYZ" and "XYZ (1)" names
# printing duplicates - print by discovery order, path (might be the same) or by date
# prompt for removal if in the same directory?
# scanning - by name or by cheksum - make it an option
