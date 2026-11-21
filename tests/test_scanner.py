"""
 Copyright (C) 2023  RedNaga. https://rednaga.io
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
import zipfile

import pytest

from apkid.apkid import MIN_DECODER_MEMORY, Scanner
from .factories import make_temp_zip, make_temp_xz_zip, make_temp_file, make_zip


def test_scan_with_dummy_zip(scanner: Scanner):
    zip_entries = {'dummy': b'hello'}
    with make_temp_zip(zip_entries) as tz:
        results = scanner.scan_file(tz.name)

    assert tz.name in results
    assert len(results) == 1
    assert len(results[tz.name]) > 0


def test_scan_with_unscannable_file(scanner: Scanner):
    with make_temp_file(b'hello') as tz:
        results = scanner.scan_file(tz.name)

    assert len(results) == 0


def test_scan_with_zip_with_dex(scanner: Scanner):
    zip_entries = {'classes.dex': b'dex\nnot a real dex!'}
    with make_temp_zip(zip_entries) as tz:
        results = scanner.scan_file(tz.name)

    for key in (tz.name, f'{tz.name}!classes.dex'):
        assert key in results
        assert len(results[key]) > 0


def test_scan_with_nested_zips(scanner: Scanner):
    third_layer = {
        '3.dex': b'dex\n'
    }
    second_layer = {
        '3.zip': make_zip(third_layer).read(),
        '2.dex': b'dex\n',
    }
    first_layer = {
        '2.zip': make_zip(second_layer).read(),
        '1.dex': b'dex\n',
    }
    zero_layer = {
        '1.zip': make_zip(first_layer).read(),
        '0.dex': b'dex\n',
    }

    scanner.options.scan_depth = 2
    with make_temp_zip(zero_layer) as tz:
        results = scanner.scan_file(tz.name)

    for key in (
            tz.name, f'{tz.name}!0.dex', f'{tz.name}!1.zip', f'{tz.name}!1.zip!1.dex', f'{tz.name}!1.zip!2.zip',
            f'{tz.name}!1.zip!2.zip!2.dex', f'{tz.name}!1.zip!2.zip!3.zip'
    ):
        assert key in results
        assert len(results[key]) > 0


def test_scan_with_xz_entry(scanner: Scanner):
    entries = {'classes.dex': b'dex\n' + b'A' * 128}
    with make_temp_xz_zip(entries) as tz:
        results = scanner.scan_file(tz.name)

    assert f'{tz.name}!classes.dex' in results
    assert len(results[f'{tz.name}!classes.dex']) > 0


def test_scan_scans_xz_entry_at_max_scan_size(scanner: Scanner):
    scanner.options.entry_max_scan_size = 1024
    entries = {'classes.dex': b'dex\n' + b'A' * (1024 - 4)}
    with make_temp_xz_zip(entries) as tz:
        results = scanner.scan_file(tz.name)

    assert f'{tz.name}!classes.dex' in results


def test_scan_skips_xz_entry_over_max_scan_size(scanner: Scanner):
    scanner.options.entry_max_scan_size = 1024
    entries = {'classes.dex': b'dex\n' + b'A' * (1025 - 4)}
    with make_temp_xz_zip(entries) as tz:
        results = scanner.scan_file(tz.name)

    assert f'{tz.name}!classes.dex' not in results


def test_scan_reads_entries_in_chunks_when_budgeted(scanner: Scanner, monkeypatch):
    # A DEFLATE header can understate `file_size`; a single unbounded `read()`
    # would let `zipfile` inflate the whole entry in one call before trimming
    # to the declared size, so the budgeted path reads in fixed-size chunks.
    monkeypatch.setattr('apkid.apkid.ENTRY_READ_CHUNK_SIZE', 8)
    reads = []
    real_read = zipfile.ZipExtFile.read

    def recording_read(self, n=-1):
        reads.append(n)
        return real_read(self, n)

    monkeypatch.setattr(zipfile.ZipExtFile, 'read', recording_read)

    with make_temp_zip({'classes.dex': b'dex\n' + b'A' * 64}) as tz:
        scanner.scan_file(tz.name)

    assert reads
    assert max(reads) <= 8


def test_scan_skips_xz_entry_with_lying_declared_size(scanner: Scanner):
    scanner.options.entry_max_scan_size = 1024
    entries = {'classes.dex': b'dex\n' + b'A' * (64 * 1024)}
    with make_temp_xz_zip(entries, declared_sizes={'classes.dex': 16}) as tz:
        results = scanner.scan_file(tz.name)

    assert f'{tz.name}!classes.dex' not in results


def test_decompress_xz_entry_handles_concatenated_streams(scanner: Scanner):
    payload = lzma.compress(b'AAAA') + lzma.compress(b'BBBB')
    info = zipfile.ZipInfo('classes.dex')
    info.file_size = 8
    info.compress_size = len(payload)

    assert scanner._decompress_xz_entry(io.BytesIO(payload), info, 0) == b'AAAABBBB'


def test_decompress_xz_entry_applies_memory_limit_to_later_streams(scanner: Scanner, monkeypatch):
    # Every decoder, including the one rebuilt for each concatenated stream, has
    # to carry the memory limit. Encoding a stream that declares a large
    # dictionary is not an option here: the encoder allocates roughly ten times
    # the dictionary size just to compress a few bytes, so the test records the
    # limit each decoder is constructed with instead.
    scanner.options.entry_max_scan_size = 1024
    limits = []
    real_decompressor = lzma.LZMADecompressor

    def recording_decompressor(*args, **kwargs):
        limits.append(kwargs.get('memlimit'))
        return real_decompressor(*args, **kwargs)

    monkeypatch.setattr('apkid.apkid.lzma.LZMADecompressor', recording_decompressor)

    payload = lzma.compress(b'AAAA') + lzma.compress(b'BBBBBBBB')
    info = zipfile.ZipInfo('classes.dex')
    info.file_size = 12
    info.compress_size = len(payload)

    assert scanner._decompress_xz_entry(io.BytesIO(payload), info, 0) == b'AAAABBBBBBBB'
    assert limits == [MIN_DECODER_MEMORY, MIN_DECODER_MEMORY]


def test_decompress_xz_entry_zero_disables_budget(scanner: Scanner):
    scanner.options.entry_max_scan_size = 0
    payload = lzma.compress(b'A' * 4096)
    info = zipfile.ZipInfo('classes.dex')
    info.file_size = 4096
    info.compress_size = len(payload)

    assert scanner._decompress_xz_entry(io.BytesIO(payload), info, 0) == b'A' * 4096


def test_decompress_xz_entry_bounds_concatenated_streams(scanner: Scanner):
    scanner.options.entry_max_scan_size = 1024
    payload = lzma.compress(b'A' * 600) + lzma.compress(b'B' * 600)
    info = zipfile.ZipInfo('classes.dex')
    info.file_size = 600
    info.compress_size = len(payload)

    assert scanner._decompress_xz_entry(io.BytesIO(payload), info, 0) is None


def test_decompress_xz_entry_keeps_valid_stream_before_trailing_junk(scanner: Scanner):
    # `lzma.decompress()` ignores a tail that is not a stream and returns what
    # the valid streams produced, so this path has to do the same instead of
    # discarding the whole entry.
    payload = lzma.compress(b'AAAABBBB') + b'not-an-xz-stream'
    info = zipfile.ZipInfo('classes.dex')
    info.file_size = 8
    info.compress_size = len(payload)

    assert lzma.decompress(payload) == b'AAAABBBB'
    assert scanner._decompress_xz_entry(io.BytesIO(payload), info, 0) == b'AAAABBBB'


def test_decompress_xz_entry_honours_decoder_memory_limit(scanner: Scanner, monkeypatch):
    # Encoding a stream that declares a huge dictionary would need a huge
    # encoder, so the floor is patched down instead and a normal stream is
    # expected to be rejected rather than decoded.
    monkeypatch.setattr('apkid.apkid.MIN_DECODER_MEMORY', 1024)
    scanner.options.entry_max_scan_size = 0
    payload = lzma.compress(b'A' * 4096)
    info = zipfile.ZipInfo('classes.dex')
    info.file_size = 4096
    info.compress_size = len(payload)

    assert scanner._decompress_xz_entry(io.BytesIO(payload), info, 0) is None


def test_decompress_xz_entry_reads_compressed_data_in_blocks(scanner: Scanner, monkeypatch):
    # `compress_size` is attacker-controlled, so the compressed payload is not
    # buffered up front; the decoder is fed in blocks instead.
    monkeypatch.setattr('apkid.apkid.XZ_COMPRESSED_READ_SIZE', 16)
    payload = lzma.compress(b'A' * 4096)
    info = zipfile.ZipInfo('classes.dex')
    info.file_size = 4096
    info.compress_size = len(payload)

    reads = []

    class CountingReader(io.BytesIO):
        def read(self, size=-1):
            reads.append(size)
            return super().read(size)

    assert scanner._decompress_xz_entry(CountingReader(payload), info, 0) == b'A' * 4096
    assert len(reads) > 1
    assert max(reads) <= 16


def test_decompress_xz_entry_reads_past_a_stream_boundary(scanner: Scanner, monkeypatch):
    # A stream that ends exactly on a read boundary has no `unused_data`; the
    # entry is not over as long as compressed bytes are left.
    first = lzma.compress(b'AAAA')
    payload = first + lzma.compress(b'BBBB')
    monkeypatch.setattr('apkid.apkid.XZ_COMPRESSED_READ_SIZE', len(first))
    info = zipfile.ZipInfo('classes.dex')
    info.file_size = 8
    info.compress_size = len(payload)

    assert scanner._decompress_xz_entry(io.BytesIO(payload), info, 0) == b'AAAABBBB'


def test_decompress_xz_entry_filters_on_entry_bytes(scanner: Scanner):
    # The filter sees the entry, not the first stream, so a short first stream
    # must not decide the magic check on its own.
    payload = lzma.compress(b'de') + lzma.compress(b'x\nAAAA')
    info = zipfile.ZipInfo('classes.dex')
    info.file_size = 8
    info.compress_size = len(payload)
    seen = []

    def should_scan(head):
        seen.append(head)
        return head == b'dex\n'

    assert scanner._decompress_xz_entry(io.BytesIO(payload), info, 0, should_scan=should_scan) == b'dex\nAAAA'
    assert seen == [b'dex\n']


def test_decompress_xz_entry_discards_a_stream_that_never_completes(scanner: Scanner, monkeypatch):
    # Data that failed to decompress is not a partial entry: only completed
    # streams are kept, as with `lzma.decompress()`.
    monkeypatch.setattr('apkid.apkid.XZ_COMPRESSED_READ_SIZE', 16)
    payload = bytearray(lzma.compress(b'B' * 4096))
    payload[-1] ^= 0xFF
    info = zipfile.ZipInfo('classes.dex')
    info.file_size = 4096
    info.compress_size = len(payload)

    assert scanner._decompress_xz_entry(io.BytesIO(bytes(payload)), info, 0) is None


def test_decompress_xz_entry_rejects_a_truncated_later_stream(scanner: Scanner):
    # Runs out of input inside the second stream. `lzma.decompress()` raises
    # here even though the first stream completed, so the entry is malformed
    # rather than a valid prefix worth scanning.
    first = lzma.compress(b'A' * 4096)
    payload = first + lzma.compress(b'B' * 4096)[:-8]
    info = zipfile.ZipInfo('classes.dex')
    info.file_size = 8192
    info.compress_size = len(payload)

    assert scanner._decompress_xz_entry(io.BytesIO(payload), info, 0) is None


def test_decompress_xz_entry_accepts_stream_padding(scanner: Scanner):
    # Trailing null bytes in multiples of four are valid XZ Stream Padding,
    # not a new stream. (`lzma.decompress()` rejects padding, so it cannot be
    # used as the reference here.)
    payload = lzma.compress(b'AAAA') + b'\x00' * 8
    info = zipfile.ZipInfo('classes.dex')
    info.file_size = 4
    info.compress_size = len(payload)

    with pytest.raises(lzma.LZMAError):
        lzma.decompress(payload)
    assert scanner._decompress_xz_entry(io.BytesIO(payload), info, 0) == b'AAAA'


def test_decompress_xz_entry_accepts_padding_between_streams(scanner: Scanner):
    payload = lzma.compress(b'AAAA') + b'\x00' * 4 + lzma.compress(b'BBBB')
    info = zipfile.ZipInfo('classes.dex')
    info.file_size = 8
    info.compress_size = len(payload)

    assert scanner._decompress_xz_entry(io.BytesIO(payload), info, 0) == b'AAAABBBB'


def test_decompress_xz_entry_rejects_invalid_stream_padding(scanner: Scanner):
    # Stream Padding has to be a multiple of four null bytes.
    payload = lzma.compress(b'AAAA') + b'\x00' * 2
    info = zipfile.ZipInfo('classes.dex')
    info.file_size = 4
    info.compress_size = len(payload)

    assert scanner._decompress_xz_entry(io.BytesIO(payload), info, 0) is None


def test_decompress_xz_entry_rejects_later_stream_over_memory_limit(scanner: Scanner, monkeypatch):
    # A later stream that declares a larger dictionary than the decoder may
    # allocate is not a bad tail: the entry is rejected instead of returning
    # the completed first stream.
    monkeypatch.setattr('apkid.apkid.MIN_DECODER_MEMORY', 128 * 1024)
    scanner.options.entry_max_scan_size = 0
    first = lzma.compress(b'A' * 4096, filters=[{'id': lzma.FILTER_LZMA2, 'dict_size': 4096}])
    payload = first + lzma.compress(b'B' * 4096)  # default preset: 8 MiB dictionary
    info = zipfile.ZipInfo('classes.dex')
    info.file_size = 8192
    info.compress_size = len(payload)

    assert scanner._decompress_xz_entry(io.BytesIO(payload), info, 0) is None


def test_scan_applies_typing_to_xz_entries(scanner: Scanner):
    # The XZ branch used to scan every entry regardless of `--typing`.
    entries = {'classes.dex': b'\x89PNG\r\n\x1a\n' + b'A' * 128}
    with make_temp_xz_zip(entries) as tz:
        results = scanner.scan_file(tz.name)

    assert f'{tz.name}!classes.dex' not in results


def test_scan_applies_filename_typing_to_xz_entries(scanner: Scanner):
    scanner.options.typing = 'filename'
    entries = {'assets/picture.png': b'dex\n' + b'A' * 128}
    with make_temp_xz_zip(entries) as tz, open(tz.name, 'rb') as f:
        results = scanner.scan_file_obj(f, 'test.apk')

    assert 'test.apk!assets/picture.png' not in results


def test_scan_scans_regular_entry_at_max_scan_size(scanner: Scanner):
    scanner.options.entry_max_scan_size = 1024
    entries = {'classes.dex': b'dex\n' + b'A' * (1024 - 4)}
    with make_temp_zip(entries) as tz:
        results = scanner.scan_file(tz.name)

    assert f'{tz.name}!classes.dex' in results


def test_scan_scans_short_entry_at_a_small_budget(scanner: Scanner):
    # Entries shorter than the magic size still fit a budget that small.
    scanner.options.entry_max_scan_size = 3
    scanner.options.typing = 'filename'
    entries = {'classes.dex': b'dex'}
    with make_temp_zip(entries) as tz, open(tz.name, 'rb') as f:
        results = scanner.scan_file_obj(f, 'test.apk')

    assert 'test.apk!classes.dex' in results


def test_scan_skips_regular_entry_over_max_scan_size(scanner: Scanner):
    scanner.options.entry_max_scan_size = 1024
    entries = {'classes.dex': b'dex\n' + b'A' * (1025 - 4)}
    with make_temp_zip(entries) as tz:
        results = scanner.scan_file(tz.name)

    assert f'{tz.name}!classes.dex' not in results
