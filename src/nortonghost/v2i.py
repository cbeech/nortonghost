"""Reader for the .v2i binary container.

A Ghost backup set is one base ``.v2i`` file plus zero or more span files
(``_s01.v2i``, ``_s02.v2i`` ...). Together they encode a single logical
byte stream. The stream is divided into named sub-streams (``ubmap``,
``udata`` ...) by a ``$CDED`` directory held in the base file's metadata.

Physical layout, confirmed against the reference sample set (see
docs/format-notes.md):

* Every file is a sequence of 128 KB slots, and every slot has a 96-byte
  header followed by a 130,976-byte payload.
* The base file's first slot is metadata and its payload is stored raw,
  so file offsets ``96 .. 131,071`` are stream offsets ``0 .. 130,975``.
* Every later slot (and every slot of a span file) is a ``$CAN`` block
  whose payload is compressed.
* A payload is ``[1 flag byte][raw deflate stream][literal tail]``. The
  block contributes ``inflate(stream) + tail`` to the logical stream; the
  tail is real data, not padding.
* The header records where the block lands: ``stream_offset`` is absolute
  and ``stream_length`` is the block's contribution, so blocks can be
  binary-searched for random access without decompressing anything.
"""

from __future__ import annotations

import re
import struct
import zlib
from bisect import bisect_right
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Iterator

SLOT_SIZE = 131072
CAN_HEADER_SIZE = 96
PAYLOAD_SIZE = SLOT_SIZE - CAN_HEADER_SIZE  # 130,976

CAN_MAGIC = b"$CAN"
CDH_MAGIC = b"$CDH"
CDED_MAGIC = b"$CDED"
FILE_MAGIC = 0x12268978

CDH_OFFSET = 0x800

# Offsets within a $CAN header.
_OFF_SEQUENCE = 0x30
_OFF_KIND = 0x34
_OFF_STREAM_OFFSET = 0x38  # uint64
# Stream length and deflate size are uint32. Reading them as uint64 works for
# every block except the last one in a set, where the uint32 at 0x44 is
# non-zero and would otherwise be folded into the length.
_OFF_STREAM_LENGTH = 0x40
_OFF_DEFLATE_SIZE = 0x48
_OFF_CHECKSUM = 0x58

# The base file's metadata slot is mapped into the stream verbatim.
RAW_PREFIX_SIZE = PAYLOAD_SIZE

_SPAN_RE = re.compile(r"^(?P<stem>.+)_s(?P<index>\d+)$", re.IGNORECASE)


class V2iError(Exception):
    """Raised when a .v2i container cannot be parsed or read."""


class MissingSpanError(V2iError):
    """Raised when a read needs a span file that is not present."""


@dataclass(frozen=True)
class Block:
    """One $CAN block, located but not yet decompressed."""

    sequence: int
    kind: int  # 1 for a data block, 3 for the set's final block
    file_index: int
    file_offset: int
    stream_offset: int
    stream_length: int
    deflate_size: int
    checksum: int

    @property
    def stream_end(self) -> int:
        return self.stream_offset + self.stream_length


@dataclass(frozen=True)
class SetInfo:
    """Totals for the whole backup set, from the base file's $CDH block."""

    total_blocks: int
    file_count: int
    total_stream_size: int


@dataclass(frozen=True)
class StreamEntry:
    """One named sub-stream from the $CDED directory."""

    name: str
    entry_id: int
    kind: int
    offset: int
    length: int

    @property
    def end(self) -> int:
        return self.offset + self.length


def _u32(buf: bytes, off: int) -> int:
    return struct.unpack_from("<I", buf, off)[0]


def _u64(buf: bytes, off: int) -> int:
    return struct.unpack_from("<Q", buf, off)[0]


def span_files(base: Path) -> list[Path]:
    """Return the base file followed by its span files, in stream order.

    Spans are named ``<stem>_sNN.v2i`` alongside the base. The list stops
    at the first gap, so a partially copied set yields the prefix that is
    actually contiguous.
    """
    base = Path(base)
    if _SPAN_RE.match(base.stem):
        raise V2iError(
            f"{base.name} is a span file; open the base .v2i instead"
        )
    files = [base]
    index = 1
    while True:
        candidate = base.with_name(f"{base.stem}_s{index:02d}{base.suffix}")
        if not candidate.exists():
            break
        files.append(candidate)
        index += 1
    return files


def parse_cdh(metadata: bytes) -> SetInfo:
    """Read the set-wide totals out of the $CDH block."""
    if metadata[CDH_OFFSET : CDH_OFFSET + 4] != CDH_MAGIC:
        raise V2iError(f"no $CDH block at {CDH_OFFSET:#x}")
    return SetInfo(
        total_blocks=_u32(metadata, CDH_OFFSET + 0x18),
        file_count=_u32(metadata, CDH_OFFSET + 0x1C),
        total_stream_size=_u64(metadata, CDH_OFFSET + 0x10),
    )


def parse_cded_entries(metadata: bytes) -> list[StreamEntry]:
    """Parse the $CDED named-stream directory out of the metadata slot."""
    entries: list[StreamEntry] = []
    pos = metadata.find(CDED_MAGIC)
    while pos != -1:
        name_off = _u32(metadata, pos + 0x28)
        name_len = _u32(metadata, pos + 0x2C)
        raw_name = metadata[pos + name_off : pos + name_off + name_len * 2]
        entries.append(
            StreamEntry(
                name=raw_name.decode("utf-16-le", "replace").rstrip("\x00"),
                entry_id=_u32(metadata, pos + 0x08),
                kind=_u32(metadata, pos + 0x0C),
                offset=_u64(metadata, pos + 0x18),
                length=_u64(metadata, pos + 0x20),
            )
        )
        pos = metadata.find(CDED_MAGIC, pos + len(CDED_MAGIC))
    return entries


def block_checksum(header: bytes, payload: bytes) -> int:
    """Recompute a $CAN block's checksum field.

    The high 32 bits are a CRC-32 of the whole 130,976-byte payload, the low
    32 bits a CRC-32 of the header up to the checksum field itself. Verified
    against 700 blocks of the reference sample set.
    """
    high = zlib.crc32(payload) & 0xFFFFFFFF
    low = zlib.crc32(header[:_OFF_CHECKSUM]) & 0xFFFFFFFF
    return high << 32 | low


def _decompress_payload(payload: bytes) -> bytes:
    """Inflate one block payload, appending the literal tail."""
    obj = zlib.decompressobj(-15)
    try:
        out = obj.decompress(payload[1:]) + obj.flush()
    except zlib.error as exc:  # pragma: no cover - corrupt input
        raise V2iError(f"deflate stream failed: {exc}") from exc
    return out + bytes(obj.unused_data)


class V2iImage:
    """Random-access reader over a .v2i base file and its spans."""

    def __init__(self, base_path: str | Path, cache_blocks: int = 8) -> None:
        self.path = Path(base_path)
        self.files = span_files(self.path)
        self._handles: dict[int, BinaryIO] = {}
        self._cache: dict[int, bytes] = {}
        self._cache_order: list[int] = []
        self._cache_limit = cache_blocks

        with open(self.path, "rb") as fh:
            self.metadata = fh.read(SLOT_SIZE)
        if _u32(self.metadata, 0) != FILE_MAGIC:
            raise V2iError(
                f"{self.path.name} is not a .v2i base file "
                f"(magic {_u32(self.metadata, 0):#010x})"
            )

        self.set_info = parse_cdh(self.metadata)
        self.streams = parse_cded_entries(self.metadata)
        self.blocks: list[Block] = []
        self._starts: list[int] = []
        self._indexed = False

    # -- lifecycle ----------------------------------------------------

    def __enter__(self) -> V2iImage:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def close(self) -> None:
        for fh in self._handles.values():
            fh.close()
        self._handles.clear()
        self._cache.clear()
        self._cache_order.clear()

    def _handle(self, file_index: int) -> BinaryIO:
        fh = self._handles.get(file_index)
        if fh is None:
            fh = open(self.files[file_index], "rb")
            self._handles[file_index] = fh
        return fh

    # -- block index --------------------------------------------------

    def index_blocks(self) -> list[Block]:
        """Scan every slot header and build the stream index (cached).

        Only 96 bytes per 128 KB slot are read, so this touches well under
        0.1% of the set.
        """
        if self._indexed:
            return self.blocks

        blocks: list[Block] = []
        expected_offset = RAW_PREFIX_SIZE
        for file_index, path in enumerate(self.files):
            size = path.stat().st_size
            start = 0 if file_index else SLOT_SIZE
            fh = self._handle(file_index)
            for offset in range(start, size - CAN_HEADER_SIZE + 1, SLOT_SIZE):
                fh.seek(offset)
                header = fh.read(CAN_HEADER_SIZE)
                if header[:4] != CAN_MAGIC:
                    raise V2iError(
                        f"{path.name}: expected $CAN at {offset:#x}, "
                        f"found {header[:4]!r}"
                    )
                block = Block(
                    sequence=_u32(header, _OFF_SEQUENCE),
                    kind=_u32(header, _OFF_KIND),
                    file_index=file_index,
                    file_offset=offset,
                    stream_offset=_u64(header, _OFF_STREAM_OFFSET),
                    stream_length=_u32(header, _OFF_STREAM_LENGTH),
                    deflate_size=_u32(header, _OFF_DEFLATE_SIZE),
                    checksum=_u64(header, _OFF_CHECKSUM),
                )
                if block.stream_offset != expected_offset:
                    raise V2iError(
                        f"{path.name}: block {block.sequence} starts at "
                        f"{block.stream_offset:,}, expected "
                        f"{expected_offset:,} (out-of-order or missing span)"
                    )
                expected_offset = block.stream_end
                blocks.append(block)

        self.blocks = blocks
        self._starts = [b.stream_offset for b in blocks]
        self._indexed = True
        return blocks

    @property
    def stream_size(self) -> int:
        """Total logical bytes available from the files actually present."""
        blocks = self.index_blocks()
        return blocks[-1].stream_end if blocks else RAW_PREFIX_SIZE

    # -- integrity ----------------------------------------------------

    def verify_block(self, position: int) -> bool:
        """Check one block's stored checksum against its bytes on disk."""
        block = self.blocks[position]
        fh = self._handle(block.file_index)
        fh.seek(block.file_offset)
        header = fh.read(CAN_HEADER_SIZE)
        payload = fh.read(PAYLOAD_SIZE)
        return block_checksum(header, payload) == block.checksum

    def verify(self) -> Iterator[tuple[Block, bool]]:
        """Yield every block with whether its checksum matched."""
        for position in range(len(self.index_blocks())):
            yield self.blocks[position], self.verify_block(position)

    # -- reading ------------------------------------------------------

    def _block_data(self, position: int) -> bytes:
        cached = self._cache.get(position)
        if cached is not None:
            return cached
        block = self.blocks[position]
        fh = self._handle(block.file_index)
        fh.seek(block.file_offset + CAN_HEADER_SIZE)
        data = _decompress_payload(fh.read(PAYLOAD_SIZE))
        if len(data) < block.stream_length:
            raise V2iError(
                f"block {block.sequence} produced {len(data):,} bytes, "
                f"header claims {block.stream_length:,}"
            )
        if len(data) > block.stream_length:
            # A final slot can be padded out; anything else is corruption.
            excess = data[block.stream_length :]
            if any(excess):
                raise V2iError(
                    f"block {block.sequence} produced {len(excess):,} bytes "
                    f"beyond its declared length, and they are not padding"
                )
            data = data[: block.stream_length]
        self._cache[position] = data
        self._cache_order.append(position)
        if len(self._cache_order) > self._cache_limit:
            self._cache.pop(self._cache_order.pop(0), None)
        return data

    def read(self, offset: int, length: int) -> bytes:
        """Read ``length`` bytes at ``offset`` in the logical stream."""
        if offset < 0 or length < 0:
            raise ValueError("offset and length must be non-negative")
        if length == 0:
            return b""

        chunks: list[bytes] = []
        remaining = length

        if offset < RAW_PREFIX_SIZE:
            take = min(remaining, RAW_PREFIX_SIZE - offset)
            start = CAN_HEADER_SIZE + offset
            chunks.append(self.metadata[start : start + take])
            offset += take
            remaining -= take

        if remaining:
            self.index_blocks()
        while remaining:
            position = bisect_right(self._starts, offset) - 1
            if (
                position < 0
                or position >= len(self.blocks)
                or offset >= self.blocks[-1].stream_end
            ):
                raise MissingSpanError(
                    f"stream offset {offset:,} is past the end of the "
                    f"{len(self.files)} file(s) present; the next span file "
                    f"is needed"
                )
            block = self.blocks[position]
            data = self._block_data(position)
            local = offset - block.stream_offset
            take = min(remaining, len(data) - local)
            chunks.append(data[local : local + take])
            offset += take
            remaining -= take

        return b"".join(chunks)

    def iter_stream(
        self, offset: int, length: int, chunk_size: int = 1 << 22
    ) -> Iterator[bytes]:
        """Yield ``length`` bytes from ``offset`` in chunks."""
        remaining = length
        while remaining:
            take = min(chunk_size, remaining)
            data = self.read(offset, take)
            if not data:
                break
            yield data
            offset += len(data)
            remaining -= len(data)

    # -- named sub-streams --------------------------------------------

    def stream(self, name: str) -> StreamEntry:
        for entry in self.streams:
            if entry.name == name:
                return entry
        known = ", ".join(e.name for e in self.streams) or "none"
        raise V2iError(f"no sub-stream named {name!r} (found: {known})")

    def read_stream(self, name: str, offset: int = 0, length: int | None = None) -> bytes:
        entry = self.stream(name)
        if length is None:
            length = entry.length - offset
        if offset + length > entry.length:
            raise ValueError(
                f"read of {length:,} at {offset:,} runs past the end of "
                f"{name!r} ({entry.length:,} bytes)"
            )
        return self.read(entry.offset + offset, length)
