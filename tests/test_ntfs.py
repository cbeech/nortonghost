"""Unit tests for the NTFS reader's parsing primitives.

These use hand-built structures rather than a real volume, so they pin the
bit-level decisions (run-list encoding, update sequence fixups, the LZNT1
displacement/length split) that are easy to get subtly wrong.
"""

from __future__ import annotations

import struct

from nortonghost.ntfs import (
    apply_fixup,
    decode_runs,
    decompress_lznt1,
)


def _non_resident(run_bytes: bytes) -> bytes:
    """Build the smallest attribute that decode_runs will accept."""
    attribute = bytearray(0x40)
    struct.pack_into("<H", attribute, 0x20, 0x40)  # run list starts at 0x40
    return bytes(attribute) + run_bytes


def test_decode_runs_reads_lengths_and_signed_deltas():
    # 0x21: one length byte, two offset bytes
    runs = decode_runs(_non_resident(b"\x21\x18\x34\x56\x00"))
    assert runs == ((0x5634, 0x18),)


def test_decode_runs_accumulates_relative_offsets():
    # second run's offset is a delta from the first, and here it is negative
    runs = decode_runs(_non_resident(b"\x21\x10\x00\x10\x21\x10\x00\xf0\x00"))
    assert runs == ((0x1000, 0x10), (0x1000 - 0x1000, 0x10))


def test_decode_runs_marks_sparse_runs():
    # a run with no offset field at all is sparse
    runs = decode_runs(_non_resident(b"\x21\x08\x00\x20\x01\x40\x00"))
    assert runs == ((0x2000, 8), (None, 0x40))


def _record_with_fixup(sequence: int, tail_a: bytes, tail_b: bytes) -> bytearray:
    record = bytearray(1024)
    record[0:4] = b"FILE"
    struct.pack_into("<HH", record, 0x04, 0x30, 3)  # usa offset, count
    struct.pack_into("<H", record, 0x30, sequence)
    record[0x32:0x34] = tail_a  # real bytes for the end of sector 0
    record[0x34:0x36] = tail_b  # ... and sector 1
    struct.pack_into("<H", record, 510, sequence)
    struct.pack_into("<H", record, 1022, sequence)
    return record


def test_apply_fixup_restores_the_sector_tails():
    record = _record_with_fixup(0xBEEF, b"\x11\x22", b"\x33\x44")
    assert apply_fixup(record) is True
    assert bytes(record[510:512]) == b"\x11\x22"
    assert bytes(record[1022:1024]) == b"\x33\x44"


def test_apply_fixup_rejects_a_torn_record():
    record = _record_with_fixup(0xBEEF, b"\x11\x22", b"\x33\x44")
    struct.pack_into("<H", record, 1022, 0x0000)  # second sector never written
    assert apply_fixup(record) is False


def _lznt1_unit(chunk: bytes, compressed: bool) -> bytes:
    header = (len(chunk) - 1) | (0x8000 if compressed else 0)
    return struct.pack("<H", header) + chunk


def test_decompress_lznt1_passes_through_a_stored_chunk():
    data = _lznt1_unit(b"hello world", compressed=False)
    assert decompress_lznt1(data, 11) == b"hello world"


def test_decompress_lznt1_resolves_a_back_reference():
    # eight literals, then a token copying 5 bytes from 8 back
    pair = (8 - 1) << 12 | (5 - 3)
    chunk = b"\x00" + b"ABCDEFGH" + b"\x01" + struct.pack("<H", pair)
    assert decompress_lznt1(_lznt1_unit(chunk, compressed=True), 13) == b"ABCDEFGHABCDE"


def test_decompress_lznt1_stops_on_an_impossible_back_reference():
    # a back-reference as the very first token has nothing to point at
    pair = (1 - 1) << 12 | (5 - 3)
    chunk = b"\x01" + struct.pack("<H", pair)
    assert decompress_lznt1(_lznt1_unit(chunk, compressed=True), 16) == bytes(16)


def test_decompress_lznt1_zero_fills_a_short_unit():
    data = _lznt1_unit(b"abc", compressed=False)
    assert decompress_lznt1(data, 8) == b"abc" + bytes(5)


def test_walk_does_not_follow_a_directory_cycle():
    """A corrupt index can name an ancestor as its own child."""
    from nortonghost.ntfs import DirEntry, NtfsVolume

    class Cyclic(NtfsVolume):
        def __init__(self):
            pass

        def listdir(self, number):
            # every directory claims the root as its child
            return [DirEntry("loop", 5, True, 0)]

    walked = list(Cyclic().walk(5))
    assert walked == [("/loop", DirEntry("loop", 5, True, 0))]
