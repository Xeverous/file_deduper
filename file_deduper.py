#!/usr/bin/env python3

import datetime
import os
import stat
from typing import AnyStr, Dict, List, Optional, Union
from hashlib import sha256
import argparse
import progressbar

# https://stackoverflow.com/questions/53418046/how-do-i-type-hint-a-variable-that-can-be-passed-as-the-first-argument-to-open
def sha256sum(filename: Union[str, bytes, os.PathLike]) -> bytes:
    hash = sha256()
    with open(filename, "rb") as f:
        for chunk in iter(lambda: f.read(128 * hash.block_size), b""):
            hash.update(chunk)
    return hash.digest()

def to_hex(checksum: Optional[bytes]) -> str:
    if checksum is None:
        return "------------------------ (not computed) ------------------------"
    else:
        return checksum.hex()

# modified https://stackoverflow.com/a/1094933/4818802
# - removed suffix parameter
# - added space before unit
# - added a condition to prevent "1.0 B"
# - removed leading spaces in formatting
# - added type hints
def pretty_byte_size(num: int) -> str:
    for unit in ("B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB", "ZiB"):
        if abs(num) < 1024.0:
            if unit == "B":
                return f"{num} {unit}"
            else:
                return f"{num:.1f} {unit}"
        num /= 1024.0
    return f"{num:.1f} YiB"

class Entry:
    def __init__(self, parent: "Optional[Entry]",
                 path: Union[str, bytes, os.PathLike],
                 is_dir: bool, date_modified: int,
                 size: int, checksum: Optional[bytes]=None):
        self.parent = parent
        self.children: list[Entry] = []
        self.path = path
        self.is_dir = is_dir
        self.date_modified = date_modified
        self.size = size
        self.checksum = checksum

    def name(self) -> AnyStr:
        return os.path.basename(self.path)

    def to_string(self, pretty_size=False) -> str:
        # removing .strftime() brings default formatting (which also prints second fractions)
        date = datetime.datetime.fromtimestamp(self.date_modified).strftime('%Y-%m-%d %H:%M:%S')
        if pretty_size:
            size = "{:>12}".format(pretty_byte_size(self.size))
        else:
            # 12 is enough for ~9.1 TiB
            size = "{:>12}".format(self.size)
        return f"{date} {size} {self.path}"

    def __repr__(self) -> str:
        return self.to_string()

    def print(self, pretty_size=False):
        print(self.to_string(pretty_size))


def make_entry(parent: Optional[Entry],
               path: Union[str, bytes, os.PathLike],
               stats: os.stat_result) -> Entry:
    is_dir = stat.S_ISDIR(stats.st_mode)
    if is_dir:
        size = 0
    else:
        size = stats.st_size
    return Entry(parent, path, is_dir, stats.st_mtime, size)

class ScanResult:
    def __init__(self):
        self.root_objects: list[Entry] = []
        self.all_objects:  list[Entry] = []
        self.total_dirs  = 0
        self.total_files = 0
        self.total_size  = 0

    def print_stats(self):
        print("OVERALL STATS:")
        print(f"total dirs: {self.total_dirs}")
        print(f"total files: {self.total_files}")
        print(f"total size: {pretty_byte_size(self.total_size)}")

# parent must be a directory
def scan_recurse(parent: Entry, result: ScanResult):
    for name in os.listdir(parent.path):
        path = os.path.join(parent.path, name)
        stats = os.lstat(path)
        if stat.S_ISDIR(stats.st_mode) or stat.S_ISREG(stats.st_mode):
            entry = make_entry(parent, path, stats)
            parent.children.append(entry)
            result.all_objects.append(entry)
            if entry.is_dir:
                scan_recurse(entry, result)
                for child in entry.children:
                    entry.size += child.size
                result.total_dirs += 1
            else:
                result.total_files += 1
        else:
            print(f"Skipping unsupported object with mode {hex(stats.st_mode)} on '{path}'")

def scan(paths: List[Union[str, bytes, os.PathLike]]) -> ScanResult:
    result = ScanResult()

    for path in paths:
        stats = os.lstat(path)
        if stat.S_ISREG(stats.st_mode) or stat.S_ISDIR(stats.st_mode):
            entry = make_entry(None, path, stats)
            result.root_objects.append(entry)
            result.all_objects.append(entry)
            if entry.is_dir:
                scan_recurse(entry, result)
                for child in entry.children:
                    entry.size += child.size
                result.total_dirs += 1
            else:
                result.total_files += 1
            result.total_size += entry.size
        else:
            print(f"Skipping unsupported object with mode {hex(stats.st_mode)} on '{path}'")

    return result

def update_dict(d: dict, key, entry: Entry):
    l = d.get(key)
    if l:
        l.append(entry)
    else:
        d.update([(key, [entry])])

def sort_by_date(l: List[Entry]):
    l.sort(key=lambda e: e.date_modified)


class NameGrouping:
    def __init__(self, grouping: Dict[str, List[Entry]], order_by_date=False):
        self.grouping = grouping
        # no space_taken_by_duplicates as here each may have a different size
        # so computing which files contribute to redundant space is impossible
        self.duplicate_sets = 0
        self.duplicate_entries = 0

        for _, entries in self.grouping.items():
            if len(entries) > 1:
                self.duplicate_sets += 1
                self.duplicate_entries += len(entries) - 1 # -1 because one copy should remain.
                if order_by_date:
                    sort_by_date(entries)

    def print_duplicates(self, pretty_size=False):
        print("NAME DUPLICATES:")
        for name, entries in self.grouping.items():
            if len(entries) > 1:
                print(f"\n{name}") # empty line to separate groups of duplicates
                for entry in entries:
                    entry.print(pretty_size)

    def print_stats(self):
        print("NAME DUPLICATE STATS:")
        print(f"duplicate sets: {self.duplicate_sets}")
        print(f"duplicate entries: {self.duplicate_entries}")


class HashGrouping:
    def __init__(self, grouping: Dict[bytes, List[Entry]], order_by_date=False):
        self.grouping = grouping
        self.space_taken_by_duplicates = 0
        self.duplicate_sets = 0
        self.duplicate_files = 0

        for _, entries in self.grouping.items():
            if len(entries) > 1:
                duplicates = len(entries) - 1 # -1 because one copy should remain.
                # It can be very safely assumed that the size of each file with same hash is identical.
                # As of writing this, there is no known SHA-256 collision.
                self.space_taken_by_duplicates += entries[0].size * duplicates
                self.duplicate_sets += 1
                self.duplicate_files += duplicates
                if order_by_date:
                    sort_by_date(entries)

    def print_duplicates(self, pretty_size=False):
        print("HASH DUPLICATES:")
        for hash, entries in self.grouping.items():
            if len(entries) > 1:
                print(f"\n{to_hex(hash)}") # empty line to separate groups of duplicates
                for entry in entries:
                    entry.print(pretty_size)

    def print_stats(self):
        print("HASH DUPLICATE STATS:")
        print(f"duplicate sets: {self.duplicate_sets}")
        print(f"duplicate files: {self.duplicate_files}")
        print(f"space taken by duplicates: {pretty_byte_size(self.space_taken_by_duplicates)}")


def group_by_name(entries: List[Entry], order_by_date=False) -> NameGrouping:
    result = {}
    for entry in entries:
        update_dict(result, entry.name(), entry)
    return NameGrouping(result, order_by_date)

def group_by_hash(entries: List[Entry], total_bytes: int, order_by_date=False) -> HashGrouping:
    result = {}
    processed_bytes = 0
    bar = progressbar.ProgressBar(
        maxval=total_bytes,
        widgets=[progressbar.Bar('#', '[', ']'), ' ', progressbar.Percentage()])
    bar.start()

    for entry in entries:
        if not entry.is_dir:
            entry.checksum = sha256sum(entry.path)
            update_dict(result, entry.checksum, entry)
            processed_bytes += entry.size
            bar.update(processed_bytes)

    bar.finish()
    return HashGrouping(result, order_by_date)

def run(by_name: bool, by_hash: bool, paths: List[str], order_by_date=False, pretty_size=False):
    # step: scan
    print(f"scanning {len(paths)} root paths for files...")
    scan_result = scan(paths)
    print(f"found {len(scan_result.all_objects)} objects totalling {pretty_byte_size(scan_result.total_size)}")

    # step: compute
    if by_name:
        # this is very fast
        name_grouping = group_by_name(scan_result.all_objects, order_by_date)
    if by_hash:
        # this grows linearly with size of files
        # future improvement: compute hashes concurrently
        print("computing hashes...")
        hash_grouping = group_by_hash(scan_result.all_objects, scan_result.total_size, order_by_date)

    # step: print duplicates
    if by_name:
        print()
        name_grouping.print_duplicates(pretty_size)
    if by_hash:
        print()
        hash_grouping.print_duplicates(pretty_size)

    # step: print stats
    print()
    scan_result.print_stats()
    if by_name:
        print()
        name_grouping.print_stats()
    if by_hash:
        print()
        hash_grouping.print_stats()

if __name__ == "__main__":
    parser = argparse.ArgumentParser("file deduplicator - scan given places and list duplicates")
    parser.add_argument("-n", "--name", action="store_true", help="list duplicate files by name")
    parser.add_argument("-s", "--hash", action="store_true", help="list duplicate files by their SHA-256")
    parser.add_argument("-d", "--date-sort", action="store_true", help="sort duplicates by date (default: filesystem order)")
    parser.add_argument("-p", "--pretty-size", action="store_true", help="pretty print file sizes")
    parser.add_argument("paths", nargs="+", help="file or directory paths to scan, can be relative and absolute")
    args = parser.parse_args()
    run(by_name=args.name, by_hash=args.hash, paths=args.paths,
        order_by_date=args.date_sort, pretty_size=args.pretty_size)

# autoremove same-hash files that have "XYZ" and "XYZ (1)" names in the same directory?

# interactive mode plan:
# <num> - file to keep
# s - skip this set
# d - skip this directory?
# q - quit interactive mode, print remaining duplicates
# ? - help
