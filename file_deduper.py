#!/usr/bin/env python3

import datetime
import os
import re
import stat
from typing import Any, AnyStr, Dict, List, Optional, Tuple, Union
from hashlib import sha256
import argparse
import progressbar
from abc import ABC, abstractmethod

def read_file(path: str) -> str:
    with open(path, 'r', encoding="utf-8") as file:
        return file.read()

def matches_any_regex(s: str, regexes: List[re.Pattern]) -> bool:
    for regex in regexes:
        if regex.search(s):
            return True
    return False

def str_to_int(s: str) -> Union[int, None]:
    try:
        return int(s)
    except ValueError:
        return None

def is_in_range(value: int, min_value: Optional[int] = None, max_value: Optional[int] = None) -> bool:
    if min_value is not None:
        if value < min_value:
            return False
    if max_value is not None:
        if value > max_value:
            return False
    return True

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

def print_separator() -> None:
    progressbar.ProgressBar(widgets=[progressbar.Bar('_', '_', '_', '_')]).start().finish()

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
        self.root_objects: List[Entry] = []
        self.all_objects:  Dict[str, Entry] = {} # key is path, for easy removal
        self.total_dirs  = 0
        self.total_files = 0
        self.total_size  = 0

    def remove_entry(self, path: str):
        size = self.all_objects[path].size
        self.root_objects = [ x for x in self.root_objects if path != x.path ]
        del self.all_objects[path]
        self.total_files -= 1
        self.total_size -= size

    def print_stats(self):
        print("OVERALL STATS:")
        print(f"total dirs: {self.total_dirs}")
        print(f"total files: {self.total_files}")
        print(f"total size: {pretty_byte_size(self.total_size)}")

# parent must be a directory
def scan_recurse(parent: Entry, exclude_regexes: List[re.Pattern],
                 min_size: Optional[int],
                 max_size: Optional[int],
                 result: ScanResult):
    for name in os.listdir(parent.path):
        path = os.path.join(parent.path, name)
        if matches_any_regex(path, exclude_regexes):
            continue
        stats = os.lstat(path)
        if stat.S_ISREG(stats.st_mode) and not is_in_range(stats.st_size, min_size, max_size):
            continue
        if stat.S_ISDIR(stats.st_mode) or stat.S_ISREG(stats.st_mode):
            entry = make_entry(parent, path, stats)
            parent.children.append(entry)
            result.all_objects.update([(path, entry)])
            if entry.is_dir:
                scan_recurse(entry, exclude_regexes, min_size, max_size, result)
                for child in entry.children:
                    entry.size += child.size
                result.total_dirs += 1
            else:
                result.total_files += 1
        else:
            print(f"Skipping unsupported object with mode {hex(stats.st_mode)} on '{path}'")

def scan(paths: List[Union[str, bytes, os.PathLike]],
         exclude_regexes: List[re.Pattern] = [],
         min_size: Optional[int] = None,
         max_size: Optional[int] = None) -> ScanResult:
    result = ScanResult()

    for path in paths:
        if matches_any_regex(path, exclude_regexes):
            continue
        stats = os.lstat(path)
        if stat.S_ISREG(stats.st_mode) and not is_in_range(stats.st_size, min_size, max_size):
            continue
        if stat.S_ISREG(stats.st_mode) or stat.S_ISDIR(stats.st_mode):
            entry = make_entry(None, path, stats)
            result.root_objects.append(entry)
            result.all_objects.update([(path, entry)])
            if entry.is_dir:
                scan_recurse(entry, exclude_regexes, min_size, max_size, result)
                for child in entry.children:
                    entry.size += child.size
                result.total_dirs += 1
            else:
                result.total_files += 1
            result.total_size += entry.size
        else:
            print(f"Skipping unsupported object with mode {hex(stats.st_mode)} on '{path}'")

    return result

def update_dict(d: dict, key, entry: Entry) -> None:
    l = d.get(key)
    if l:
        l.append(entry)
    else:
        d.update([(key, [entry])])

def sort_by_date(l: List[Entry]):
    l.sort(key=lambda e: e.date_modified)

class Grouping(ABC):
    @abstractmethod
    def grouping(self) -> Dict[Any, List[Entry]]:
        pass

    def keys_to_duplicate_sets(self) -> list:
        result = []
        for key, val in self.grouping().items():
            if len(val) > 1:
                result.append(key)
        return result

    @abstractmethod
    # key from the list obtained from keys_to_duplicate_sets
    def print_set(self, key, pretty_size=False, numerate=False) -> None:
        pass

    @abstractmethod
    def print_duplicates(self, pretty_size=False) -> None:
        pass

    @abstractmethod
    def print_stats(self) -> None:
        pass

    @staticmethod
    def print_set(header: str, entries: List[Entry], pretty_size=False, numerate=False) -> None:
        print(f"\n{header}") # empty line to separate groups of duplicates
        if numerate:
            for idx, entry in enumerate(entries):
                print(f"[{idx + 1}]: ", end="")
                entry.print(pretty_size=True)
        else:
            for entry in entries:
                entry.print(pretty_size)

    # Returns whether operation succeeded and the total size of removed files.
    # It is possible to have False with non-zero values on partial success.
    # if idx is None, then remove all files
    def remove_all_files_except(self, scan_result: ScanResult, key, idx: Optional[int]) -> Tuple[bool, int]:
        entries = self.grouping()[key]

        if idx is not None and idx not in range(len(entries)):
            print("Error: invalid index")
            return False, 0

        remaining_entries = []
        result = True
        bytes_removed = 0

        for i, entry in enumerate(entries):
            if i == idx:
                continue
            try:
                os.remove(entry.path)
                bytes_removed += entry.size
                scan_result.remove_entry(entry.path)
                print(f"Removed {entry.path} ({pretty_byte_size(entry.size)})")
            except OSError as e:
                remaining_entries.append(entry)
                print(f"Error when removing \"{entry.path}\": {e.strerror}")
                result = False
        self.grouping()[key] = remaining_entries
        return result, bytes_removed

    def move_2_to_1(self, scan_result: ScanResult, key, idx: Optional[int]) -> Tuple[bool, int]:
        entries = self.grouping()[key]

        if idx is not None and idx not in range(len(entries)):
            print("Error: invalid index")
            return False, 0

        remaining_entries = []
        result = True
        bytes_removed = 0

        entry = entries[0]
        try:
            entry0_path = entry.path
            os.remove(entry.path)
            bytes_removed += entry.size
            scan_result.remove_entry(entry.path)
            print(f"Removed {entry.path} ({pretty_byte_size(entry.size)})")
            x = input()
        except OSError as e:
            remaining_entries.append(entry)
            print(f"Error when removing \"{entry.path}\": {e.strerror}")
            return False, 0

        entry = entries[1]
        try:
            os.rename(entry.path, entry0_path)
            scan_result.remove_entry(entry.path)
            print(f"moved {entry.path} to {entry0_path} ({pretty_byte_size(entry.size)})")
            x = input()
        except OSError as e:
            remaining_entries.append(entry)
            print(f"Error when moving \"{entry.path}\" to \"{entry0_path}\": {e.strerror}")
            return False, bytes_removed

        self.grouping()[key] = remaining_entries
        return result, bytes_removed

class NameGrouping(Grouping):
    def __init__(self, grouping: Dict[str, List[Entry]], order_by_date=False):
        self._grouping = grouping
        if order_by_date:
            for entries in self._grouping.values():
                sort_by_date(entries)

    def grouping(self) -> Dict[Any, List[Entry]]:
        return self._grouping

    def compute_stats(self) -> Tuple[int, int]:
        duplicate_sets = 0
        duplicate_entries = 0

        for entries in self._grouping.values():
            if len(entries) > 1:
                duplicates = len(entries) - 1 # -1 because one copy should remain.
                duplicate_sets += 1
                duplicate_entries += duplicates
                # no space_taken_by_duplicates as here each may have a different size
                # so computing which files contribute to redundant space is impossible

        return duplicate_sets, duplicate_entries

    def print_set(self, key: str, pretty_size=False, numerate=False) -> None:
        Grouping.print_set(key, self._grouping[key], pretty_size, numerate)

    def print_duplicates(self, pretty_size=False) -> None:
        print("NAME DUPLICATES:")
        for key in self.keys_to_duplicate_sets():
            self.print_set(key, pretty_size=pretty_size)

    def print_stats(self) -> None:
        print("NAME DUPLICATE STATS:")
        duplicate_sets, duplicate_entries = self.compute_stats()
        print(f"duplicate sets: {duplicate_sets}")
        print(f"duplicate entries: {duplicate_entries}")


class HashGrouping(Grouping):
    def __init__(self, grouping: Dict[bytes, List[Entry]], order_by_date=False):
        self._grouping = grouping

        if order_by_date:
            for entries in self._grouping.values():
                sort_by_date(entries)

    def grouping(self) -> Dict[Any, List[Entry]]:
        return self._grouping

    def compute_stats(self) -> Tuple[int, int, int]:
        duplicate_sets = 0
        duplicate_files = 0 # not duplicate_entries because hashes are computed only for files
        space_taken_by_duplicates = 0

        for _, entries in self._grouping.items():
            if len(entries) > 1:
                duplicates = len(entries) - 1 # -1 because one copy should remain.
                duplicate_sets += 1
                duplicate_files += duplicates
                # It can be very safely assumed that the size of each file with same hash is identical.
                # As of writing this, there is no known SHA-256 collision.
                space_taken_by_duplicates += entries[0].size * duplicates
        return duplicate_sets, duplicate_files, space_taken_by_duplicates

    def print_set(self, key: bytes, pretty_size=False, numerate=False):
        Grouping.print_set(to_hex(key), self._grouping[key], pretty_size, numerate)

    def print_duplicates(self, pretty_size=False):
        print("HASH DUPLICATES:")
        for key in self.keys_to_duplicate_sets():
            self.print_set(key, pretty_size=pretty_size)

    def print_stats(self):
        print("HASH DUPLICATE STATS:")
        duplicate_sets, duplicate_files, space_taken_by_duplicates = self.compute_stats()
        print(f"duplicate sets: {duplicate_sets}")
        print(f"duplicate files: {duplicate_files}")
        print(f"space taken by duplicates: {pretty_byte_size(space_taken_by_duplicates)}")


def group_by_name(entries: Dict[str, Entry], order_by_date=False) -> NameGrouping:
    result = {}
    for entry in entries.values():
        update_dict(result, entry.name(), entry)
    return NameGrouping(result, order_by_date)

def group_by_hash(entries: Dict[str, Entry], total_bytes: int, order_by_date=False) -> HashGrouping:
    result = {}
    processed_bytes = 0
    bar = progressbar.ProgressBar(
        maxval=total_bytes,
        widgets=[progressbar.Bar('#', '[', ']'), ' ', progressbar.Percentage()])
    bar.start()

    for entry in entries.values():
        if not entry.is_dir:
            entry.checksum = sha256sum(entry.path)
            update_dict(result, entry.checksum, entry)
            processed_bytes += entry.size
            bar.update(processed_bytes)

    bar.finish()
    return HashGrouping(result, order_by_date)

class Deduper:
    def __init__(self, paths: List[str], exclude_regexes: List[re.Pattern] = [],
                 min_size: int = None, max_size: int = None, order_by_date=False):
        self.paths = paths
        self.exclude_regexes = exclude_regexes
        self.min_size = min_size
        self.max_size = max_size
        self.order_by_date = order_by_date
        self.removed_files_size = 0
        self.scan()

    def scan(self):
        # Note: there can only be grouping at a time.
        # This is because file removal on one grouping will invalidate another.
        # This is also why removal needs to update scan_result
        self.grouping = None
        print(f"scanning {len(self.paths)} root paths for files...")
        self.scan_result = scan(self.paths, self.exclude_regexes, self.min_size, self.max_size)
        print(f"found {len(self.scan_result.all_objects)} objects totalling {pretty_byte_size(self.scan_result.total_size)}")

    def search_name_duplicates(self):
        if not isinstance(self.grouping, NameGrouping):
            self.grouping = group_by_name(self.scan_result.all_objects, self.order_by_date)

    def search_hash_duplicates(self):
        if not isinstance(self.grouping, HashGrouping):
            # this grows linearly with size of files
            # future improvement: compute hashes concurrently
            print("computing hashes...")
            self.grouping = group_by_hash(self.scan_result.all_objects, self.scan_result.total_size, self.order_by_date)

    def print_duplicates(self, pretty_size=False):
        if self.grouping:
            print()
            self.grouping.print_duplicates(pretty_size)

    def print_stats(self):
        print()
        self.scan_result.print_stats()
        # this stat is only for interactive mode and thus should only be printed if modified
        if self.removed_files_size != 0:
            print(f"removed files size: {pretty_byte_size(self.removed_files_size)}")
        if self.grouping:
            print()
            self.grouping.print_stats()

    def run(self, by_name=False, by_hash=False, pretty_size=False):
        if by_name:
            self.search_name_duplicates()
            self.print_duplicates(pretty_size)
            self.print_stats()
        if by_hash:
            self.search_hash_duplicates()
            self.print_duplicates(pretty_size)
            self.print_stats()

    def print_parameters(self) -> None:
        print(f"\nmin/max size: {self.min_size}/{self.max_size}")
        print(f"\norder by date: {self.order_by_date}")
        print("\npaths:")
        for path in self.paths:
            print(path)
        print("\nexclusions:")
        for regex in self.exclude_regexes:
            print(regex.pattern)

    def run_interactive(self):
        while True:
            print("\nINTERACTIVE MODE")
            print("i - print command-line parameters given on launch")
            print("s - print stats")
            print("n - interactively remove name duplicates")
            print("h - interactively remove hash duplicates")
            print("r - reset (use when changes were made outside this program)")
            print("q - quit")
            answer = input()
            print_separator()
            print()

            if answer == "i":
                self.print_parameters()
            elif answer == "s":
                self.print_stats()
            elif answer == "n":
                self.search_name_duplicates()
                self.run_interactive_duplicates()
            elif answer == "h":
                self.search_hash_duplicates()
                self.run_interactive_duplicates()
            elif answer == "r":
                self.scan()
            elif answer == "q":
                break

    def run_interactive_duplicates(self):
        self.grouping.print_stats()
        duplicate_set_keys = self.grouping.keys_to_duplicate_sets()
        total_sets = len(duplicate_set_keys)
        for idx0, key in enumerate(duplicate_set_keys):
            while True:
                self.grouping.print_set(key, pretty_size=True, numerate=True)
                # print 1-based index for the user
                print(f"\nINTERACTIVE REMOVAL (set {idx0 + 1}/{total_sets})")
                print("  0   - keep none of these files, remove all")
                print("<num> - keep this file, remove others")
                print("  s   - keep all of these files (skip this set)")
                print("  b   - back to previous menu")
                answer = input()
                print_separator()
                idx1 = str_to_int(answer)
                if idx1 is not None:
                    if idx1 == 0:
                        # if user choose 0 then it means none of the files should be kept
                        keep_idx = None
                        result, bytes_removed = self.grouping.remove_all_files_except(self.scan_result, key, keep_idx)
                        self.removed_files_size += bytes_removed
                    elif idx1 < 0:
                        keep_idx = -idx1 - 1
                        result, bytes_removed = self.grouping.move_2_to_1(self.scan_result, key, keep_idx)
                        self.removed_files_size += bytes_removed
                    else:
                        # if not 0, then convert 1-based index to 0-based index
                        keep_idx = idx1 - 1
                        result, bytes_removed = self.grouping.remove_all_files_except(self.scan_result, key, keep_idx)
                        self.removed_files_size += bytes_removed
                    if result:
                        break
                if answer == "s":
                    break
                elif answer == "b":
                    return


if __name__ == "__main__":
    parser = argparse.ArgumentParser("file_deduper.py", description="file deduplicator - scan given places and list duplicates")
    parser.add_argument("paths", nargs="+", help="file or directory paths to scan, can be relative and absolute")

    scaning_options = parser.add_argument_group("scanning options")
    scaning_options.add_argument("-r", "--regex-exclude", nargs="*", default=[], help="ignore paths matching specified regex(es)")
    scaning_options.add_argument("-f", "--regex-exclude-file", help="like -r, but read regexes from file, one per line, empty lines are ignored")
    scaning_options.add_argument("-m", "--min-size", type=int, default=None, help="minimum required file size in bytes")
    scaning_options.add_argument("-x", "--max-size", type=int, default=None, help="maximum allowed file size in bytes")

    processing_options = parser.add_argument_group("processing options")
    processing_options.add_argument("-n", "--name", action="store_true", help="list duplicate files by name")
    processing_options.add_argument("-s", "--hash", action="store_true", help="list duplicate files by their SHA-256")
    processing_options.add_argument("-i", "--interactive", action="store_true", help="interactive mode (overrides other processing options and applies -p)")

    formatting_options = parser.add_argument_group("formatting options")
    formatting_options.add_argument("-d", "--date-sort", action="store_true", help="order duplicates by date (default: filesystem order)")
    formatting_options.add_argument("-p", "--pretty-size", action="store_true", help="pretty print file sizes on duplicate listings (default: bytes)")

    args = parser.parse_args()

    regexes = []
    if args.regex_exclude_file:
        regexes = read_file(args.regex_exclude_file).splitlines()
    for regex in args.regex_exclude:
        regexes.append(regex)

    compiled_regexes = []
    for regex in regexes:
        if regex != "":
            compiled_regexes.append(re.compile(regex))

    deduper = Deduper(args.paths, compiled_regexes, args.min_size, args.max_size, args.date_sort)
    if (args.interactive):
        deduper.run_interactive()
    else:
        deduper.run(args.name, args.hash, args.pretty_size)

# autoremove same-hash files that have "XYZ" and "XYZ (1)" names in the same directory?
