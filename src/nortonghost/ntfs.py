"""Minimal read-only NTFS reader, enough to recover files from an image.

This exists so that recovering a file does not require extracting the whole
volume first. It reads directly from anything with a ``read(offset, length)``
method, which includes :class:`nortonghost.volume.Volume`, so files can be
pulled straight out of a ``.v2i`` set with no scratch space.

It is deliberately partial. It reads what a recovery tool needs: the boot
sector, the MFT, directory indexes and file data, including sparse and
LZNT1-compressed runs. It does not write, does not interpret security
descriptors, reparse points or extended attributes, and ignores named data
streams other than the default one.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Iterator, Protocol

MFT_RECORD_SIZE = 1024
SECTOR_SIZE = 512

ATTR_ATTRIBUTE_LIST = 0x20
ATTR_FILE_NAME = 0x30
ATTR_DATA = 0x80
ATTR_INDEX_ROOT = 0x90
ATTR_INDEX_ALLOCATION = 0xA0

FLAG_IN_USE = 0x0001
FLAG_DIRECTORY = 0x0002

NAMESPACE_DOS = 2

# A directory index far larger than this is a corrupt or hostile image,
# not a real directory: 512 MB of index covers millions of entries.
MAX_INDEX_BYTES = 512 * 1024 * 1024

ROOT_RECORD = 5


class Reader(Protocol):
    def read(self, offset: int, length: int) -> bytes: ...


class NtfsError(Exception):
    """Raised when the volume cannot be read as NTFS."""


@dataclass(frozen=True)
class Attribute:
    type_id: int
    name: str
    resident: bool
    flags: int
    content: bytes  # resident data, or the raw attribute header when not
    runs: tuple[tuple[int | None, int], ...]
    data_size: int
    allocated_size: int

    @property
    def compressed(self) -> bool:
        return bool(self.flags & 0x0001)

    @property
    def compression_unit(self) -> int:
        return 1 << self.content[0x22] if not self.resident else 0


@dataclass(frozen=True)
class DirEntry:
    name: str
    record_number: int
    is_directory: bool
    size: int

    def __str__(self) -> str:
        return self.name


def apply_fixup(record: bytearray, sector_size: int = SECTOR_SIZE) -> bool:
    """Apply the NTFS update sequence array in place.

    Every sector of a record ends with two bytes replaced by a sequence
    number; the originals live in the header. If a sector's marker does not
    match, that sector was never written and the record is torn.
    """
    usa_offset, usa_count = struct.unpack_from("<HH", record, 0x04)
    if usa_count == 0 or usa_offset + usa_count * 2 > len(record):
        return False
    sequence = struct.unpack_from("<H", record, usa_offset)[0]
    for i in range(1, usa_count):
        end = i * sector_size - 2
        if end + 2 > len(record):
            return False
        if struct.unpack_from("<H", record, end)[0] != sequence:
            return False
        struct.pack_into(
            "<H", record, end, struct.unpack_from("<H", record, usa_offset + i * 2)[0]
        )
    return True


def decode_runs(attribute: bytes) -> tuple[tuple[int | None, int], ...]:
    """Decode a non-resident attribute's run list.

    Returns (lcn, clusters) pairs, with lcn None for a sparse run.
    """
    offset = struct.unpack_from("<H", attribute, 0x20)[0]
    runs: list[tuple[int | None, int]] = []
    lcn = 0
    while offset < len(attribute):
        header = attribute[offset]
        if header == 0:
            break
        length_size, offset_size = header & 0x0F, header >> 4
        offset += 1
        if length_size == 0 or offset + length_size + offset_size > len(attribute):
            break
        count = int.from_bytes(attribute[offset : offset + length_size], "little")
        offset += length_size
        if offset_size == 0:
            runs.append((None, count))
            continue
        lcn += int.from_bytes(
            attribute[offset : offset + offset_size], "little", signed=True
        )
        offset += offset_size
        runs.append((lcn, count))
    return tuple(runs)


def _decompress_lznt1_chunk(chunk: bytes) -> bytearray:
    """Decompress one LZNT1 chunk.

    Back-references are relative to this chunk's own output, and the split
    between the displacement and length halves of a pair widens as the chunk
    fills: 12 length bits until 16 bytes are out, then 11, and so on.
    """
    out = bytearray()
    index = 0
    while index < len(chunk):
        flags = chunk[index]
        index += 1
        for bit in range(8):
            if index >= len(chunk):
                break
            if not flags >> bit & 1:
                out.append(chunk[index])
                index += 1
                continue
            if index + 2 > len(chunk):
                return out
            pair = struct.unpack_from("<H", chunk, index)[0]
            index += 2
            position = len(out) - 1
            length_mask = 0xFFF
            shift = 12
            while position >= 0x10:
                position >>= 1
                length_mask >>= 1
                shift -= 1
            length = (pair & length_mask) + 3
            delta = (pair >> shift) + 1
            if delta > len(out):
                return out  # corrupt stream; keep what decoded cleanly
            for _ in range(length):
                out.append(out[-delta])
    return out


def decompress_lznt1(data: bytes, expected: int) -> bytes:
    """Decompress an LZNT1 compression unit as used by NTFS."""
    out = bytearray()
    pos = 0
    while pos + 2 <= len(data) and len(out) < expected:
        header = struct.unpack_from("<H", data, pos)[0]
        pos += 2
        if header == 0:
            break
        size = (header & 0x0FFF) + 1
        chunk = data[pos : pos + size]
        pos += size
        if header & 0x8000:
            out += _decompress_lznt1_chunk(chunk)
        else:  # stored uncompressed
            out += chunk
    if len(out) < expected:
        out += bytes(expected - len(out))  # trailing sparse tail
    return bytes(out[:expected])


class NtfsVolume:
    """Read-only view of an NTFS volume."""

    def __init__(self, reader: Reader) -> None:
        self.reader = reader
        boot = reader.read(0, SECTOR_SIZE)
        if boot[3:11] != b"NTFS    ":
            raise NtfsError("no NTFS boot sector at volume offset 0")
        self.bytes_per_sector = struct.unpack_from("<H", boot, 0x0B)[0]
        self.cluster_size = self.bytes_per_sector * boot[0x0D]
        self.total_sectors = struct.unpack_from("<Q", boot, 0x28)[0]
        self.mft_offset = struct.unpack_from("<Q", boot, 0x30)[0] * self.cluster_size
        self._record_cache: dict[int, bytes] = {}

        first = bytearray(self.reader.read(self.mft_offset, MFT_RECORD_SIZE))
        if first[:4] != b"FILE" or not apply_fixup(first, self.bytes_per_sector):
            raise NtfsError("the $MFT's own record is unreadable")
        data = self._find(bytes(first), ATTR_DATA)
        if data is None or data.resident:
            raise NtfsError("$MFT has no non-resident $DATA")
        self.mft_runs = data.runs
        self.mft_size = data.data_size

    # -- records ------------------------------------------------------

    @property
    def record_count(self) -> int:
        return self.mft_size // MFT_RECORD_SIZE

    def _mft_read(self, offset: int, length: int) -> bytes:
        """Read from the MFT's own address space, following its run list."""
        out = bytearray()
        position = 0
        for lcn, count in self.mft_runs:
            run_bytes = count * self.cluster_size
            if position + run_bytes <= offset:
                position += run_bytes
                continue
            start = max(0, offset - position)
            take = min(run_bytes - start, length - len(out))
            if lcn is None:
                out += bytes(take)
            else:
                out += self.reader.read(lcn * self.cluster_size + start, take)
            position += run_bytes
            if len(out) >= length:
                break
        return bytes(out)

    def record(self, number: int) -> bytes:
        """Return MFT record ``number`` with its fixups applied."""
        cached = self._record_cache.get(number)
        if cached is not None:
            return cached
        raw = bytearray(self._mft_read(number * MFT_RECORD_SIZE, MFT_RECORD_SIZE))
        if len(raw) < MFT_RECORD_SIZE or raw[:4] != b"FILE":
            raise NtfsError(f"MFT record {number} is not a FILE record")
        if not apply_fixup(raw, self.bytes_per_sector):
            raise NtfsError(f"MFT record {number} is torn (fixup mismatch)")
        result = bytes(raw)
        if len(self._record_cache) > 4096:
            self._record_cache.clear()
        self._record_cache[number] = result
        return result

    # -- attributes ---------------------------------------------------

    def attributes(self, record: bytes) -> Iterator[Attribute]:
        offset = struct.unpack_from("<H", record, 0x14)[0]
        while offset + 8 <= len(record):
            type_id, length = struct.unpack_from("<II", record, offset)
            if type_id == 0xFFFFFFFF or length == 0:
                return
            non_resident = record[offset + 8]
            name_length = record[offset + 9]
            name_offset = struct.unpack_from("<H", record, offset + 0x0A)[0]
            flags = struct.unpack_from("<H", record, offset + 0x0C)[0]
            name = (
                record[
                    offset + name_offset : offset + name_offset + name_length * 2
                ].decode("utf-16-le", "replace")
                if name_length
                else ""
            )
            raw = record[offset : offset + length]
            if non_resident:
                yield Attribute(
                    type_id, name, False, flags, raw, decode_runs(raw),
                    struct.unpack_from("<Q", raw, 0x30)[0],
                    struct.unpack_from("<Q", raw, 0x28)[0],
                )
            else:
                content_offset = struct.unpack_from("<H", raw, 0x14)[0]
                size = struct.unpack_from("<I", raw, 0x10)[0]
                content = raw[content_offset : content_offset + size]
                yield Attribute(type_id, name, True, flags, content, (), size, size)
            offset += length

    def _find(
        self, record: bytes, type_id: int, name: str = ""
    ) -> Attribute | None:
        for attribute in self.attributes(record):
            if attribute.type_id == type_id and attribute.name == name:
                return attribute
        return None

    def find_attribute(
        self, record: bytes, type_id: int, name: str = ""
    ) -> Attribute | None:
        """Find an attribute, following $ATTRIBUTE_LIST into other records."""
        direct = self._find(record, type_id, name)
        if direct is not None:
            return direct
        listing = self._find(record, ATTR_ATTRIBUTE_LIST)
        if listing is None:
            return None
        data = (
            listing.content
            if listing.resident
            else self.attribute_data(listing, limit=MAX_INDEX_BYTES)
        )
        offset = 0
        while offset + 0x18 <= len(data):
            entry_type = struct.unpack_from("<I", data, offset)[0]
            entry_length = struct.unpack_from("<H", data, offset + 4)[0]
            if entry_length == 0:
                break
            if entry_type == type_id:
                reference = struct.unpack_from("<Q", data, offset + 0x10)[0]
                other = reference & 0x0000FFFFFFFFFFFF
                found = self._find(self.record(other), type_id, name)
                if found is not None:
                    return found
            offset += entry_length
        return None

    # -- attribute data -----------------------------------------------

    def attribute_data(self, attribute: Attribute, limit: int | None = None) -> bytes:
        """Read a whole attribute into memory.

        ``limit`` guards against a corrupt or hostile image declaring an
        enormous attribute and exhausting memory. Callers that stream should
        use :meth:`iter_attribute_data` instead.
        """
        if limit is not None and attribute.data_size > limit:
            raise NtfsError(
                f"attribute {attribute.type_id:#x} declares "
                f"{attribute.data_size:,} bytes, over the {limit:,} byte limit"
            )
        return b"".join(self.iter_attribute_data(attribute))

    def iter_attribute_data(
        self, attribute: Attribute, chunk_size: int = 1 << 22
    ) -> Iterator[bytes]:
        """Yield an attribute's data, expanding sparse and compressed runs."""
        if attribute.resident:
            yield attribute.content
            return
        if attribute.compressed:
            yield from self._iter_compressed(attribute)
            return

        remaining = attribute.data_size
        for lcn, count in attribute.runs:
            if remaining <= 0:
                break
            run_bytes = min(count * self.cluster_size, remaining)
            if lcn is None:
                produced = 0
                while produced < run_bytes:
                    take = min(chunk_size, run_bytes - produced)
                    yield bytes(take)
                    produced += take
            else:
                base = lcn * self.cluster_size
                produced = 0
                while produced < run_bytes:
                    take = min(chunk_size, run_bytes - produced)
                    yield self.reader.read(base + produced, take)
                    produced += take
            remaining -= run_bytes

    def _iter_compressed(self, attribute: Attribute) -> Iterator[bytes]:
        """Walk a compressed attribute one compression unit at a time.

        A compressed run is followed by a sparse run; together they make a
        compression unit whose stored clusters decompress to the full unit.
        """
        unit = attribute.compression_unit or 16
        unit_bytes = unit * self.cluster_size
        remaining = attribute.data_size
        runs = list(attribute.runs)
        index = 0
        while index < len(runs) and remaining > 0:
            lcn, count = runs[index]
            if lcn is None:
                produced = min(count * self.cluster_size, remaining)
                yield bytes(produced)
                remaining -= produced
                index += 1
                continue
            if count >= unit or index + 1 >= len(runs) or runs[index + 1][0] is not None:
                take = min(count * self.cluster_size, remaining)
                yield self.reader.read(lcn * self.cluster_size, take)
                remaining -= take
                index += 1
                continue
            stored = self.reader.read(lcn * self.cluster_size, count * self.cluster_size)
            expected = min(unit_bytes, remaining)
            yield decompress_lznt1(stored, expected)
            remaining -= expected
            index += 2

    # -- directories --------------------------------------------------

    def _index_entries(self, data: bytes, offset: int) -> Iterator[DirEntry]:
        while offset + 0x10 <= len(data):
            reference, entry_length, _stream_length, flags = struct.unpack_from(
                "<QHHH", data, offset
            )
            if entry_length == 0:
                return
            if flags & 0x02:  # last entry in this node
                return
            number = reference & 0x0000FFFFFFFFFFFF
            name_length = data[offset + 0x50]
            namespace = data[offset + 0x51]
            name = data[
                offset + 0x52 : offset + 0x52 + name_length * 2
            ].decode("utf-16-le", "replace")
            file_flags = struct.unpack_from("<I", data, offset + 0x48)[0]
            size = struct.unpack_from("<Q", data, offset + 0x40)[0]
            if namespace != NAMESPACE_DOS:
                yield DirEntry(name, number, bool(file_flags & 0x10000000), size)
            offset += entry_length

    def listdir(self, record_number: int) -> list[DirEntry]:
        """List a directory's entries by MFT record number."""
        record = self.record(record_number)
        root = self.find_attribute(record, ATTR_INDEX_ROOT, "$I30")
        if root is None:
            raise NtfsError(f"record {record_number} is not a directory")

        entries = list(self._index_entries(root.content, 0x20))
        allocation = self.find_attribute(record, ATTR_INDEX_ALLOCATION, "$I30")
        if allocation is None:
            return entries

        block_size = struct.unpack_from("<I", root.content, 0x08)[0]
        if not 512 <= block_size <= 1 << 20:
            raise NtfsError(
                f"record {record_number}: implausible index block size {block_size}"
            )
        data = self.attribute_data(allocation, limit=MAX_INDEX_BYTES)
        for start in range(0, len(data) - 0x18, block_size):
            block = bytearray(data[start : start + block_size])
            if block[:4] != b"INDX":
                continue
            if not apply_fixup(block, self.bytes_per_sector):
                continue
            first = struct.unpack_from("<I", block, 0x18)[0]
            entries.extend(self._index_entries(bytes(block), 0x18 + first))
        return entries

    # -- paths --------------------------------------------------------

    def resolve(self, path: str) -> DirEntry:
        """Resolve a path such as ``/WINDOWS/system32`` to its entry."""
        current = DirEntry("", ROOT_RECORD, True, 0)
        parts = [p for p in path.replace("\\", "/").split("/") if p]
        for index, part in enumerate(parts):
            if not current.is_directory:
                raise NtfsError(f"{'/'.join(parts[:index])} is not a directory")
            for entry in self.listdir(current.record_number):
                if entry.name.lower() == part.lower():
                    current = entry
                    break
            else:
                raise NtfsError(f"no such file or directory: {path}")
        return current

    def data_attribute(self, record_number: int) -> Attribute:
        attribute = self.find_attribute(self.record(record_number), ATTR_DATA)
        if attribute is None:
            raise NtfsError(f"record {record_number} has no unnamed $DATA")
        return attribute

    def iter_file(self, record_number: int) -> Iterator[bytes]:
        yield from self.iter_attribute_data(self.data_attribute(record_number))

    def file_size(self, record_number: int) -> int:
        return self.data_attribute(record_number).data_size

    def walk(
        self,
        record_number: int = ROOT_RECORD,
        prefix: str = "",
        _seen: frozenset[int] | None = None,
    ) -> Iterator[tuple[str, DirEntry]]:
        """Yield (path, entry) for everything under a directory.

        Directories already on the current path are skipped. A corrupt or
        hostile index can name an ancestor as its own child, and without that
        guard the walk recurses until the stack gives out.
        """
        seen = (_seen or frozenset()) | {record_number}
        for entry in self.listdir(record_number):
            if entry.name == ".":
                continue
            path = f"{prefix}/{entry.name}"
            yield path, entry
            if entry.is_directory and entry.record_number not in seen:
                yield from self.walk(entry.record_number, path, seen)
