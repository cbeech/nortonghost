"""Tests for the .v2i container reader, against a synthetic image.

The real sample set is 48 GB and cannot be committed, so these tests build
a miniature container that uses the same structures: a raw metadata slot
carrying $CDH and $CDED, then $CAN blocks whose payloads are a deflate
stream followed by a literal tail.
"""

from __future__ import annotations

import struct
import zlib

import pytest

from nortonghost.v2i import (
    CAN_HEADER_SIZE,
    PAYLOAD_SIZE,
    SLOT_SIZE,
    MissingSpanError,
    V2iImage,
    block_checksum,
)
from nortonghost.volume import Volume

SECTORS_PER_CHUNK = 512
SECTOR = 512
CHUNK_BYTES = SECTORS_PER_CHUNK * SECTOR

UBMAP_OFFSET = 0x2000
# chunk 0 whole, chunk 1 absent, chunk 2 two stored runs
STORED_RUNS = [(64, 192), (320, 128)]
CHUNK2_STORED = sum(length for _, length in STORED_RUNS)
UDATA_SECTORS = SECTORS_PER_CHUNK + 0 + CHUNK2_STORED


def _chunk_record(index: int, span: int, stored: int, kind: int, inline: tuple[int, ...]) -> bytes:
    body = struct.pack("<HIHHH4H", 0x3474, index, span, stored, kind, *inline)
    return body.ljust(32, b"\x00")


def _build_ubmap() -> bytes:
    header = struct.pack("<IIII", 0, SECTORS_PER_CHUNK * 3, 0, 3) + bytes(16)
    records = b"".join(
        [
            _chunk_record(0, SECTORS_PER_CHUNK, SECTORS_PER_CHUNK, 0x100, (0, 511, 0, 0)),
            _chunk_record(1, SECTORS_PER_CHUNK, 0, 0x000, (0, 0, 0, 511)),
            _chunk_record(
                2, SECTORS_PER_CHUNK, CHUNK2_STORED, 0x200, (64, 447, 0, 511)
            ),
        ]
    )
    # run-list slot: start, then (length, next start, length, ...)
    values = [STORED_RUNS[0][1], STORED_RUNS[1][0], STORED_RUNS[1][1]]
    slot = (
        struct.pack("<HIIH H", 0x2290, len(STORED_RUNS), 0, 0x2290, STORED_RUNS[0][0])
        + struct.pack(f"<{len(values)}H", *values)
    )
    slot = slot.ljust(512, b"\x00")
    return header + records + slot


def _udata() -> bytes:
    return bytes((i * 7 + 3) % 251 for i in range(UDATA_SECTORS * SECTOR))


def _cded_entry(entry_id: int, name: str, offset: int, length: int) -> bytes:
    encoded = (name + "\x00").encode("utf-16-le")
    entry = bytearray(0x38 + len(encoded))
    entry[0:5] = b"$CDED"
    struct.pack_into("<II", entry, 0x08, entry_id, 4)
    struct.pack_into("<QQ", entry, 0x18, offset, length)
    struct.pack_into("<II", entry, 0x28, 0x38, len(name) + 1)
    entry[0x38:] = encoded
    return bytes(entry)


def build_image(path, *, truncate_blocks: int | None = None) -> bytes:
    """Write a synthetic .v2i and return the logical stream it encodes."""
    ubmap = _build_ubmap()
    udata = _udata()
    udata_offset = UBMAP_OFFSET + len(ubmap)

    stream = bytearray(UBMAP_OFFSET)
    stream += ubmap
    stream += udata

    slot = bytearray(SLOT_SIZE)
    struct.pack_into("<I", slot, 0, 0x12268978)
    slot[CAN_HEADER_SIZE:] = stream[:PAYLOAD_SIZE]

    # $CDH and $CDED are addressed in file coordinates and live in the
    # metadata slot, so they overwrite the (unused) head of the stream.
    slot[0x800:0x804] = b"$CDH"
    struct.pack_into("<Q", slot, 0x810, len(stream))
    struct.pack_into("<II", slot, 0x818, 0, 1)  # block count patched below
    directory = b"".join(
        [
            _cded_entry(7, "ubmap", UBMAP_OFFSET, len(ubmap)),
            _cded_entry(8, "udata", udata_offset, len(udata)),
        ]
    )
    slot[0x1000 : 0x1000 + len(directory)] = directory
    # keep the stream mirror in step with the slot we just patched
    stream[: PAYLOAD_SIZE] = slot[CAN_HEADER_SIZE:]

    blocks = bytearray()
    position = PAYLOAD_SIZE
    sequence = 1
    while position < len(stream):
        body = stream[position : position + 60_000]
        compressed = zlib.compress(bytes(body), 6)[2:-4]
        tail_room = PAYLOAD_SIZE - 1 - len(compressed)
        tail = stream[position + len(body) : position + len(body) + tail_room]
        payload = b"\x74" + compressed + bytes(tail)
        payload = payload.ljust(PAYLOAD_SIZE, b"\x00")

        header = bytearray(CAN_HEADER_SIZE)
        header[0:4] = b"$CAN"
        struct.pack_into("<I", header, 0x30, sequence)
        struct.pack_into("<I", header, 0x34, 1)
        struct.pack_into("<Q", header, 0x38, position)
        struct.pack_into("<Q", header, 0x40, len(body) + len(tail))
        struct.pack_into("<Q", header, 0x48, len(compressed) + 1)
        struct.pack_into("<Q", header, 0x58, block_checksum(bytes(header), payload))
        blocks += header + payload

        position += len(body) + len(tail)
        sequence += 1

    struct.pack_into("<I", slot, 0x818, sequence - 1)
    stream[:PAYLOAD_SIZE] = slot[CAN_HEADER_SIZE:]
    if truncate_blocks is not None:
        blocks = blocks[: truncate_blocks * SLOT_SIZE]
    path.write_bytes(bytes(slot) + bytes(blocks))
    return bytes(stream)


@pytest.fixture
def image(tmp_path):
    path = tmp_path / "TEST001.v2i"
    stream = build_image(path)
    with V2iImage(path) as img:
        yield img, stream


def test_streams_are_listed(image):
    img, _ = image
    assert [e.name for e in img.streams] == ["ubmap", "udata"]
    assert img.stream("udata").length == UDATA_SECTORS * SECTOR


def test_set_info_counts_blocks(image):
    img, _ = image
    assert img.set_info.file_count == 1
    assert img.set_info.total_blocks == len(img.index_blocks())


def test_stream_read_matches_source(image):
    img, stream = image
    assert img.stream_size == len(stream)
    assert img.read(0, 4096) == stream[:4096]
    # spanning the raw slot into the first compressed block
    assert img.read(PAYLOAD_SIZE - 100, 200) == stream[PAYLOAD_SIZE - 100 : PAYLOAD_SIZE + 100]
    assert img.read(len(stream) - 1000, 1000) == stream[-1000:]


def test_block_tails_are_data_not_padding(image):
    img, stream = image
    blocks = img.index_blocks()
    assert len(blocks) > 1
    # every block's payload is shorter than what it contributes
    assert all(b.stream_length > b.deflate_size for b in blocks)
    seam = blocks[0].stream_end
    assert img.read(seam - 64, 128) == stream[seam - 64 : seam + 64]


def test_read_past_the_end_names_the_missing_span(tmp_path):
    path = tmp_path / "TEST002.v2i"
    build_image(path, truncate_blocks=1)
    with V2iImage(path) as img:
        with pytest.raises(MissingSpanError):
            img.read(img.stream_size + 10, 16)


def test_every_block_checksum_verifies(image):
    img, _ = image
    assert all(good for _, good in img.verify())


def test_a_flipped_byte_fails_verification(tmp_path):
    path = tmp_path / "TEST003.v2i"
    build_image(path)
    raw = bytearray(path.read_bytes())
    # corrupt one byte inside the first block's payload
    raw[SLOT_SIZE + CAN_HEADER_SIZE + 500] ^= 0xFF
    path.write_bytes(bytes(raw))
    with V2iImage(path) as img:
        results = dict((b.sequence, good) for b, good in img.verify())
        assert results[1] is False
        assert all(good for seq, good in results.items() if seq != 1)


def test_volume_geometry(image):
    img, _ = image
    volume = Volume(img)
    assert volume.total_sectors == SECTORS_PER_CHUNK * 3
    assert volume.size == CHUNK_BYTES * 3
    assert volume.stored_sectors == UDATA_SECTORS


def test_volume_maps_whole_absent_and_partial_chunks(image):
    img, _ = image
    volume = Volume(img)
    udata = _udata()

    # chunk 0 is stored whole
    assert volume.read(0, CHUNK_BYTES) == udata[:CHUNK_BYTES]
    # chunk 1 was never stored
    assert volume.read(CHUNK_BYTES, CHUNK_BYTES) == bytes(CHUNK_BYTES)
    # chunk 2 keeps only two runs; everything else reads back as zeros
    chunk2 = volume.read(CHUNK_BYTES * 2, CHUNK_BYTES)
    assert chunk2[: 64 * SECTOR] == bytes(64 * SECTOR)
    first_run = udata[CHUNK_BYTES : CHUNK_BYTES + 192 * SECTOR]
    assert chunk2[64 * SECTOR : 256 * SECTOR] == first_run
    assert chunk2[256 * SECTOR : 320 * SECTOR] == bytes(64 * SECTOR)
    second_run = udata[CHUNK_BYTES + 192 * SECTOR : CHUNK_BYTES + 320 * SECTOR]
    assert chunk2[320 * SECTOR : 448 * SECTOR] == second_run
    assert chunk2[448 * SECTOR :] == bytes(64 * SECTOR)


def test_volume_read_spans_chunk_boundaries(image):
    img, _ = image
    volume = Volume(img)
    whole = volume.read(0, volume.size)
    assert len(whole) == volume.size
    for start in (0, CHUNK_BYTES - 10, CHUNK_BYTES * 2 + 64 * SECTOR - 10):
        assert volume.read(start, 4096) == whole[start : start + 4096]


def test_write_image_matches_a_straight_read(image, tmp_path):
    img, _ = image
    volume = Volume(img)
    out = tmp_path / "volume.img"
    with open(out, "wb") as fh:
        stored = volume.write_image(fh)
    assert stored == volume.stored_sectors * SECTOR
    assert out.stat().st_size == volume.size
    assert out.read_bytes() == volume.read(0, volume.size)


def test_write_image_handles_a_partial_range(image, tmp_path):
    img, _ = image
    volume = Volume(img)
    out = tmp_path / "slice.img"
    # a range that starts inside the absent chunk and ends inside chunk 2
    start, length = CHUNK_BYTES + 4096, CHUNK_BYTES
    with open(out, "wb") as fh:
        volume.write_image(fh, start, length)
    assert out.stat().st_size == length
    assert out.read_bytes() == volume.read(start, length)


def test_write_image_rejects_or_empties_degenerate_ranges(image, tmp_path):
    img, _ = image
    volume = Volume(img)
    out = tmp_path / "empty.img"
    with open(out, "wb") as fh:
        assert volume.write_image(fh, volume.size + 1024, 4096) == 0
    assert out.stat().st_size == 0
    with open(out, "wb") as fh:
        with pytest.raises(ValueError):
            volume.write_image(fh, -1, 4096)


def test_readable_size_reports_a_partial_set(image):
    img, _ = image
    volume = Volume(img)
    assert volume.readable_size(volume.data_stream.length) == volume.size
    # only the first chunk's worth of udata present
    assert volume.readable_size(CHUNK_BYTES) == CHUNK_BYTES


def _ubmap_with(chunk_count: int, run_count: int) -> bytes:
    body = bytearray(32 + 32 + 512)
    struct.pack_into("<IIII", body, 0, 0, 512, 0, chunk_count)
    struct.pack_into("<HIHHH", body, 32, 0x3474, 0, 512, 256, 0x200)
    struct.pack_into("<HI", body, 64, 0x2290, run_count)
    return bytes(body)


@pytest.mark.parametrize(
    "chunk_count,run_count",
    [(1, 0), (1, 2**31), (10**6, 1)],
)
def test_a_corrupt_ubmap_raises_a_clear_error(chunk_count, run_count):
    """Fields from the image must be checked, not fed straight to struct."""
    from nortonghost.v2i import V2iError
    from nortonghost.volume import parse_ubmap

    with pytest.raises(V2iError):
        parse_ubmap(_ubmap_with(chunk_count, run_count))
