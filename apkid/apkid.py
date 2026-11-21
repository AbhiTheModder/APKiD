"""
 Copyright (C) 2024  RedNaga. https://rednaga.io
 All rights reserved. Contact: rednaga@protonmail.com


 This file is part of APKiD


 Commercial License Usage
 ------------------------
 Licensees holding valid commercial APKiD licenses may use this file
 in accordance with the commercial license agreement provided with the
 Software or, alternatively, in accordance with the terms contained in
 a written agreement between you and RedNaga.


 GNU General Public License Usage
 --------------------------------
 Alternatively, this file may be used under the terms of the GNU General
 Public License version 3.0 as published by the Free Software Foundation
 and appearing in the file LICENSE.GPL included in the packaging of this
 file. Please visit http://www.gnu.org/copyleft/gpl.html and review the
 information to ensure the GNU General Public License version 3.0
 requirements will be met.
"""

import io
import lzma
import os
import struct
import sys
import traceback
import zipfile
from typing import Union, IO, List, Dict, Set, Callable

import yara_x as yara

from .output import OutputFormatter, PrintFilter
from .rules import RulesManager

SCANNABLE_FILE_MAGICS: Dict[str, Set[bytes]] = {
    'zip': {b'PK\x03\x04', b'PK\x05\x06', b'PK\x07\x08'},
    'dex': {b'dex\n', b'dey\n'},
    'elf': {b'\x7fELF'},
    'res': {b'\x02\x00\x0c\x00'},
    'dll': {b'MZ\x90\x00'},
    # TODO: implement axml yara module
    # 'axml': set(),
}
XZ_COMPRESSION_TYPE = 95
DEFAULT_ENTRY_MAX_SCAN_SIZE = 100 * 1024 * 1024
# The LZMA2 decoder allocates memory proportional to the dictionary size, which
# the stream header declares. Entry bodies are otherwise capped by the scan
# budget, so this floor only has to cover real-world encoder presets: xz -9 uses
# a 64 MiB dictionary, plus a little room for the decoder's own state.
MIN_DECODER_MEMORY = 128 * 1024 * 1024
# Compressed XZ bytes are read in blocks, so a lying `compress_size` cannot force
# the whole entry into memory before the decoder gets a say.
XZ_COMPRESSED_READ_SIZE = 64 * 1024
# Number of leading bytes `_should_scan()` needs to run the magic check.
SCAN_MAGIC_SIZE = 4
ENTRY_READ_CHUNK_SIZE = 1024 * 1024
ZIP_LFH_SIG_SIZE = 4
ZIP_LFH_FIELDS_SIZE = 26
ZIP_LFH_HEADER_SIZE = ZIP_LFH_SIG_SIZE + ZIP_LFH_FIELDS_SIZE


class Options(object):

    def __init__(self, timeout: int = 10, verbose: bool = False, json: bool = False, output_dir: Union[str, None] = None,
                 typing: Union[str, None] = 'magic', entry_max_scan_size: int = DEFAULT_ENTRY_MAX_SCAN_SIZE,
                 scan_depth=2, recursive: bool = False,
                 include_trackers: bool = False, include_types: bool = False, print_filter: PrintFilter = None):
        """Scan options.
        Holds user-supplied options governing how APKiD behaves.

        Parameters
        ----------
        timeout : integer, optional (default=10)
            The number of seconds before Yara match should time out.
        json : boolean, optional (default=False)
            If the output should be JSON format.
        output_dir : string or None, optional (default=None)
            Directory to write individual scan results to. If this is true, it implies `json_output=True`.
            Note: This is useful for feature extraction of a bunch of APKs.
        verbose : boolean, optional (default=False)
            When set to `True`, log warnings and other debug information.
        typing : string or None, optional (default="magic")
            Determines how the scanner decides if a file should be scanned.
            If "magic", then require the file match a built-in list of supported file magics
            If "filename", then scan files which have names known to be supported (e.g. ".dex")
            If None, pass every file to Yara for matching.
            Note: This option defines a trade-off between performance and accuracy. For example, if you're scanning a large APK file, it is expensive
            to uncompress every ZIP entry for Yara matching. It's much faster to only decompress files which have a known extension such as ".dex".
            But in many cases files may not have the correct extension, e.g. a DEX file may be named "notmalware.gif". On the other extreme, one could
            simply decompress every file and scan it, but this is wasteful because most files in an APK are typically not interesting, e.g. images.
            The default behavior of "magic" only needs to read a few bytes to decide if a file should be completely uncompressed.
        entry_max_scan_size : integer, optional (default=100 MiB)
            Size budget, in bytes, for a single ZIP entry. Entries larger than the
            budget are skipped instead of being decompressed and scanned.
            If 0, no budget is applied.
        scan_depth : integer, optional (default=2)
            Determines how many times scanner should recurse into nested archives.
            If 0, don't recurse into nested archives.
            Note: It's possible to construct a malicious ZIP which can be infinitely nested. It's therefore necessary to limit the scan depth.
            Don't get cheeky and think you can set this value to 1000 and scan random malware without blowing up your memory.
        include_trackers : boolean, optional (default=False)
            If true, scans for embedded trackers using rules from exodus.
        recursive : boolean, optional (default=True)
            If true, when scanning a directory, will recurse into subdirectories.
        print_filter : tuple of strings, optional (default=None)
        """
        self.timeout = timeout
        self.verbose = verbose
        self.typing = typing
        self.entry_max_scan_size = entry_max_scan_size
        self.scan_depth = scan_depth
        self.include_trackers = include_trackers
        self.recursive = recursive
        self.rules_manager = RulesManager(include_trackers=include_trackers)
        self.output = OutputFormatter(
            json_output=json,
            output_dir=output_dir,
            rules_manager=self.rules_manager,
            include_types=include_types,
            include_trackers=include_trackers
        )
        self.print_matches = print_filter


class Scanner(object):

    def __init__(self, rules: yara.Rules, options: Options):
        self.rules = rules
        self.options = options
        self.scanner = yara.Scanner(self.rules)
        try:
            self.scanner.set_timeout(self.options.timeout)
        except Exception:
            pass

    def _scan_data(self, data: bytes):
        # yara-x raises TimeoutError on timeout (unlike yara which returns
        # partial matches). Treat timeout as no matches to keep scanning.
        try:
            return self.scanner.scan(data).matching_rules
        except yara.TimeoutError:
            if self.options.verbose:
                print("[W] YARA-X scan timed out", file=sys.stderr)
            return []
        except yara.ScanError as e:
            if self.options.verbose:
                print(f"[W] YARA-X scan error: {e}", file=sys.stderr)
            return []

    def scan(self, path: str) -> None:
        if os.path.isfile(path):
            results = self.scan_file(path)
            if len(results) > 0:
                self.options.output.write(results)
        elif os.path.isdir(path):
            self.scan_directory(path)

    def scan_directory(self, dir_path: str) -> None:
        for file_path in self._yield_file_paths(dir_path):
            self.scan(file_path)

    def scan_file(self, file_path: str) -> Dict[str, list]:
        results = []
        with open(file_path, 'rb') as f:
            try:
                results: Dict[str, list] = self.scan_file_obj(f, file_path)
            except Exception as e:
                stack = traceback.format_exc()
                print(f"Exception scanning {file_path}: {stack}")
        return results

    def scan_file_obj(self, file: IO, file_path: str = '$FILE$'):
        if file_path == '$FILE$':
            file_name = file_path
        else:
            file_name = os.path.basename(file_path)

        results: Dict[str, list] = {}
        if not self._should_scan(file, file_name):
            return results

        data = file.read()
        matches = self._scan_data(data)
        if len(matches) > 0:
            self._print_matches(file_name, matches, data)
            results[file_path] = list(matches)
        if self._is_zipfile(file, file_name):
            with zipfile.ZipFile(file) as zf:
                # Thread the parent file path so nested entries are printed
                # as 'path!entry!...' instead of 'None!...'.
                zip_results = self._scan_zip(zf, prefix=f'{file_path}!')
            for entry_name, entry_matches in zip_results.items():
                results[f'{file_path}!{entry_name}'] = entry_matches
        return results

    def _scan_zip(self, zf: zipfile.ZipFile, depth=0, prefix='') -> Dict[str, list]:
        results: Dict[str, list] = {}
        for info in zf.infolist():
            if info.is_dir():
                continue
            try:
                self._scan_zip_entry(zf, info, results, depth, prefix)
            except Exception as e:
                stack = traceback.format_exc()
                print(f"Exception scanning {info.filename} in {zf.filename}, depth={depth}: {stack}",
                    file=sys.stderr)
        return results

    def _scan_zip_entry(self, zf, info, results, depth, prefix='') -> None:
        budget = self.options.entry_max_scan_size
        budget = budget if budget > 0 else None

        try:
            with zf.open(info) as entry:
                # The declared size is attacker-controlled, so this is only a
                # cheap early reject, but it is also sufficient: `ZipExtFile`
                # stops reading at `info.file_size`, so a header that
                # understates the size cannot make the read below return more
                # than the budget.
                if budget is not None and info.file_size > budget:
                    if self.options.verbose:
                        print(f"[W] Skipping entry {info.filename}: "
                              f"declared size {info.file_size} exceeds {budget}")
                    return
                # Python 3.6 zip entries are not seek'able :(
                head = entry.read(SCAN_MAGIC_SIZE)
                entry_buffer: IO = io.BytesIO(head)
                entry_buffer.seek(0)
                if not self._should_scan(entry_buffer, info.filename):
                    return
                entry_buffer.seek(len(head))
                if budget is None:
                    entry_buffer.write(entry.read())
                else:
                    # `read()` stops at `info.file_size`, but that bounds what
                    # is kept, not the decoder's own allocation: given no
                    # length, `zipfile` reads as much compressed input as
                    # `compress_size` declares and inflates it in one call
                    # before trimming to the declared size. Chunked reads keep
                    # a single call bounded even when the header understates
                    # the size.
                    while True:
                        chunk = entry.read(ENTRY_READ_CHUNK_SIZE)
                        if not chunk:
                            break
                        entry_buffer.write(chunk)
        except zipfile.BadZipFile as e:
            if "Overlapped entries" in str(e) or "possible zip bomb" in str(e):
                if self.options.verbose:
                    print(f"[W] Skipping overlapped entry {info.filename} (possible zip bomb)")
                return
            else:
                raise
        except NotImplementedError:
            # XZ-compression
            if info.compress_type == XZ_COMPRESSION_TYPE:
                # `--typing filename` only needs the entry name, so it can be
                # decided without decompressing anything.
                if self.options.typing == 'filename' and not self._should_scan(io.BytesIO(b''), info.filename):
                    return
                # Only `--typing magic` needs the filter to peek at the
                # decompressed bytes; `filename` was decided above, and
                # `typing` None scans everything.
                def peek_magic(head: bytes) -> bool:
                    return self._should_scan(io.BytesIO(head), info.filename)

                should_scan = peek_magic if self.options.typing == 'magic' else None
                with open(zf.filename, 'rb') as raw_zip:
                    raw_zip.seek(info.header_offset + ZIP_LFH_FIELDS_SIZE)
                    filename_len = struct.unpack('<H', raw_zip.read(2))[0]
                    extra_len = struct.unpack('<H', raw_zip.read(2))[0]
                    data_offset = info.header_offset + ZIP_LFH_HEADER_SIZE + filename_len + extra_len
                    decompressed_data = self._decompress_xz_entry(
                        raw_zip, info, data_offset, should_scan=should_scan)
                    if decompressed_data is None:
                        return
                    entry_buffer = io.BytesIO(decompressed_data)
            else:
                print(f"[E] Unsupported compression method {info.compress_type} for {info.filename}")
                return


        entry_buffer.seek(0)
        data = entry_buffer.read()
        matches = self._scan_data(data)

        if len(matches) > 0:
            # Print exactly once, here, even when the entry itself is a
            # nested archive (the old `elif` suppressed these matches).
            results[info.filename] = list(matches)
            self._print_matches(f'{prefix}{info.filename}', matches, data)

        if depth < self.options.scan_depth and self._is_zipfile(entry_buffer, info.filename):
            with zipfile.ZipFile(entry_buffer) as zip_entry:
                nested_results = self._scan_zip(zip_entry, depth=depth + 1, prefix=f'{prefix}{info.filename}!')
                for nested_name, nested_matches in nested_results.items():
                    results[f'{info.filename}!{nested_name}'] = nested_matches

    def _decompress_xz_entry(self, raw_zip: IO, info: zipfile.ZipInfo, data_offset: int,
                             should_scan: Callable[[bytes], bool] = None) -> Union[bytes, None]:
        """Decompress an XZ-compressed ZIP entry within a bounded budget.

        `zipfile` cannot read method-95 entries, so their raw bytes are fed to
        `lzma` here. `lzma.decompress()` would happily materialize gigabytes
        from a few kilobytes of input, so decompression stops as soon as the
        output would exceed the `entry_max_scan_size` budget, and the decoder
        itself runs with a memory limit. A budget of 0 disables the size check,
        while the decoder memory limit still applies.

        `should_scan`, when given, is applied to the first `SCAN_MAGIC_SIZE`
        bytes of the entry, so `--typing` can drop it before the rest is
        materialized.

        Returns the decompressed bytes, or None when the entry is too large,
        filtered out, or the stream is malformed.
        """
        max_size = self.options.entry_max_scan_size
        # 0 disables the budget, as documented; negative values are treated the same.
        budget = max_size if max_size > 0 else None

        # The declared size is attacker-controlled, so this is a cheap early
        # reject that saves reading the entry at all; the budget below is what
        # actually holds when the header lies.
        if budget is not None and info.file_size > budget:
            if self.options.verbose:
                print(f"[W] Skipping XZ entry {info.filename}: "
                      f"declared size {info.file_size} exceeds {budget}")
            return None

        raw_zip.seek(data_offset)
        # Read the compressed bytes in blocks instead of buffering the whole
        # entry up front: `compress_size` is attacker-controlled too.
        input_remaining = info.compress_size
        decoder_memory_limit = max(budget or 0, MIN_DECODER_MEMORY)
        decompressor = lzma.LZMADecompressor(memlimit=decoder_memory_limit)
        output = bytearray()
        pending = b''
        filtered = should_scan is None
        # Where the current stream's output starts, and how many streams are
        # already complete: a failed tail is dropped back to `stream_start`,
        # the way `lzma.decompress()` only keeps completed streams.
        stream_start = 0
        completed_streams = 0
        while True:
            if pending:
                block, pending = pending, b''
            elif decompressor.needs_input:
                block = b''
                if input_remaining > 0:
                    block = raw_zip.read(min(input_remaining, XZ_COMPRESSED_READ_SIZE))
                    input_remaining -= len(block)
                if not block:
                    # The input ended inside a stream. `lzma.decompress()`
                    # rejects this even when earlier streams completed, so the
                    # entry is malformed rather than a valid prefix.
                    print(f"[E] Failed to decompress {info.filename}: truncated XZ stream",
                          file=sys.stderr)
                    return None
            else:
                block = b''

            if budget is None:
                max_length = -1
            else:
                max_length = budget + 1 - len(output)
            if not filtered:
                # Stop as soon as `_should_scan()` has the bytes it needs.
                peek = SCAN_MAGIC_SIZE - len(output)
                max_length = peek if max_length < 0 else min(max_length, peek)

            try:
                chunk = decompressor.decompress(block, max_length=max_length)
            except lzma.LZMAError as e:
                # A tail that is not a stream (trailing junk) is ignored and
                # the completed streams are kept, as `lzma.decompress()` does.
                # A memory-limit refusal is not a bad tail: the data asked for
                # more decoder memory than allowed, so the entry is rejected
                # rather than scanned in part.
                if completed_streams and 'memory usage limit' not in str(e).lower():
                    del output[stream_start:]
                    break
                print(f"[E] Failed to decompress {info.filename}: {e}", file=sys.stderr)
                return None

            output += chunk

            if budget is not None and len(output) > budget:
                if self.options.verbose:
                    print(f"[W] Skipping XZ entry {info.filename}: "
                          f"decompressed size exceeds {budget}")
                return None

            # The filter sees the entry's first bytes, so it waits until they
            # exist instead of judging a short first stream.
            if not filtered and len(output) >= SCAN_MAGIC_SIZE:
                if not should_scan(bytes(output[:SCAN_MAGIC_SIZE])):
                    return None
                filtered = True

            if decompressor.eof:
                completed_streams += 1
                # XZ allows concatenated streams, and `lzma.decompress()` consumes them all.
                pending = decompressor.unused_data
                stream_start = len(output)
                # Stream Padding is a multiple of four null bytes between or
                # after streams. It is valid XZ, so it is skipped rather than
                # mistaken for a new stream that the input cuts short.
                padding = 0
                while True:
                    stripped = pending.lstrip(b'\x00')
                    padding += len(pending) - len(stripped)
                    pending = stripped
                    if pending or input_remaining <= 0:
                        break
                    pending = raw_zip.read(min(input_remaining, XZ_COMPRESSED_READ_SIZE))
                    input_remaining -= len(pending)
                    if not pending:
                        break
                if padding % 4:
                    print(f"[E] Failed to decompress {info.filename}: "
                          f"invalid XZ stream padding", file=sys.stderr)
                    return None
                if not pending:
                    break
                decompressor = lzma.LZMADecompressor(memlimit=decoder_memory_limit)

        if not filtered and not should_scan(bytes(output[:SCAN_MAGIC_SIZE])):
            return None

        return bytes(output)

    @staticmethod
    def _type_file(file: IO) -> Union[None, str]:
        magic = file.read(SCAN_MAGIC_SIZE)
        file.seek(0)
        for file_type, magics in SCANNABLE_FILE_MAGICS.items():
            if magic in magics:
                return file_type
        return None

    def _is_zipfile(self, file: IO, name: str) -> bool:
        if self.options.typing == 'filename':
            name = name.lower()
            return name.endswith('.apk') or name.endswith('.zip') or name.endswith('.jar')
        else:
            # Look at file magic since zipfile.is_zipfile isn't perfect
            # Some elfs may be considered zips and this causes apkid to barf errors
            file.seek(0)
            return Scanner._type_file(file) == 'zip' and zipfile.is_zipfile(file)

    def _should_scan(self, file: IO, name: str) -> bool:
        if self.options.typing == 'magic':
            file_type = Scanner._type_file(file)
            return file_type is not None
        elif self.options.typing == 'filename':
            name = name.lower()
            return name.startswith('classes') \
                   or name.startswith('AndroidManifest.xml') \
                   or name.startswith('lib/') \
                   or name.endswith('.so') \
                   or name.endswith('.dex') \
                   or name.endswith('.apk') \
                   or name.endswith('.arsc') \
                   or name.endswith('.dll')
        return True

    def _yield_file_paths(self, dir_path: str):
        if self.options.recursive:
            for root, _, filenames in os.walk(dir_path):
                for path in filenames:
                    yield os.path.join(root, path)
        else:
            for path in os.listdir(dir_path):
                full_path = os.path.join(dir_path, path)
                if os.path.isdir(full_path):
                    continue
                yield full_path

    def _print_matches(self, name: str, matches, data: Union[bytes, None] = None) -> None:
        """
        Print matched rules and the patterns that hit, honoring
        --print-matches / --print-filter (include/exclude rule filter).

        Adapted for yara-x: a Rule exposes `identifier` and `patterns`
        (each Pattern has `identifier` and `matches` with offset/length /
        xor_key, but not the matched bytes), so the matched data is sliced
        from the scanned buffer and de-XORed when the pattern used `xor`.
        """
        f = self.options.print_matches
        if f is None:
            return
        include, exclude = f
        # Raw prints must not corrupt JSON on stdout when -j/-o is active.
        out = sys.stderr if self.options.output.json else sys.stdout
        for match in matches:
            rule = match.identifier
            if rule in exclude or (include and rule not in include):
                continue
            lines = [f"[{rule}] in '{name}':"]
            for pattern in match.patterns:
                for pm in pattern.matches:
                    offset, length = pm.offset, pm.length
                    if data is not None:
                        matched = data[offset:offset + length]
                        if pm.xor_key is not None:
                            matched = bytes(b ^ pm.xor_key for b in matched)
                    else:
                        matched = f'<{length} bytes>'
                    lines.append(f"\t0x{offset:08x} {pattern.identifier} {matched!r}")
            print('\n'.join(lines) + '\n', file=out)
