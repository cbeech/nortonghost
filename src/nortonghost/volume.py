"""Sparse volume view over a .v2i image.

Ghost does not store unallocated space. The ``udata`` sub-stream holds only
the sectors that were in use, and the ``ubmap`` sub-stream says where each
stored sector belongs on the original volume.

``ubmap`` layout (offsets relative to the sub-stream), confirmed against the
reference sample set:

```
+0   u32  unknown
+4   u32  total sectors on the volume
+8   u32  zero
+12  u32  chunk record count
+16  u32  unknown
+32  chunk records, 32 bytes each
```

Each chunk record covers a run of consecutive volume sectors (32,768, i.e.
16 MB, except the last which covers the remainder):

```
+0   u16  magic 0x3474
+2   u32  chunk index
+6   u16  sectors spanned by this chunk
+8   u16  sectors of it actually stored
+10  u16  kind: 0x000 absent, 0x100 whole, 0x200 run list, 0x300 bitmap
+12  u16  first stored sector, relative to the chunk
+14  u16  last stored sector, relative to the chunk
+16  u16  first absent sector
+18  u16  last absent sector
```

Chunks of kind 0x200 and 0x300 describe themselves further in a table of
512-byte slots that follows the chunk records. Slots are consumed in chunk
order: one slot for a run list, eight for a bitmap.

Run-list slot:

```
+0   u16     magic 0x2290
+2   u32     number of stored runs
+10  u16     magic 0x2290
+12  u16     start of the first stored run
+14  u16[]   run length, next run start, run length, ... (2n-1 values)
```

Bitmap slot: 4,096 bytes, one bit per sector of the chunk, set when stored.
"""

from __future__ import annotations

import struct
from bisect import bisect_right
from dataclasses import dataclass
from typing import Iterator

from .v2i import V2iImage, V2iError

SECTOR_SIZE = 512
EXTENT_SLOT_SIZE = 512
CHUNK_MAGIC = 0x3474
EXTENT_MAGIC = 0x2290

KIND_ABSENT = 0x000
KIND_WHOLE = 0x100
KIND_RUNS = 0x200
KIND_BITMAP = 0x300


@dataclass(frozen=True)
class Extent:
    """A run of sectors present in ``udata``, in volume order."""

    volume_sector: int
    data_sector: int
    sectors: int

    @property
    def volume_end(self) -> int:
        return self.volume_sector + self.sectors


def _bitmap_runs(bitmap: bytes, limit: int) -> Iterator[tuple[int, int]]:
    """Yield (start, length) runs of set bits, up to ``limit`` bits."""
    start: int | None = None
    for bit in range(limit):
        on = bitmap[bit >> 3] >> (bit & 7) & 1
        if on and start is None:
            start = bit
        elif not on and start is not None:
            yield start, bit - start
            start = None
    if start is not None:
        yield start, limit - start


def parse_ubmap(ubmap: bytes) -> tuple[int, list[Extent]]:
    """Parse ``ubmap`` into the volume sector count and its stored extents.

    Everything read here comes from the image, so every field is checked
    before it is used: a corrupt or hostile map should produce a clear error
    rather than a struct traceback or a huge allocation.
    """
    if len(ubmap) < 32:
        raise V2iError(f"ubmap is only {len(ubmap)} bytes; expected at least 32")
    total_sectors = struct.unpack_from("<I", ubmap, 4)[0]
    chunk_count = struct.unpack_from("<I", ubmap, 12)[0]
    table_end = 32 + chunk_count * 32
    if table_end > len(ubmap):
        raise V2iError(
            f"ubmap claims {chunk_count:,} chunk records, which needs "
            f"{table_end:,} bytes but the sub-stream is {len(ubmap):,}"
        )

    extents: list[Extent] = []
    volume_sector = 0
    data_sector = 0
    slot = 0

    for i in range(chunk_count):
        off = 32 + i * 32
        magic, index = struct.unpack_from("<HI", ubmap, off)
        if magic != CHUNK_MAGIC:
            raise V2iError(
                f"ubmap chunk {i}: expected magic {CHUNK_MAGIC:#06x}, "
                f"found {magic:#06x}"
            )
        if index != i:
            raise V2iError(f"ubmap chunk {i}: out-of-order index {index}")
        span, stored, kind = struct.unpack_from("<HHH", ubmap, off + 6)

        runs: list[tuple[int, int]] = []
        if kind == KIND_WHOLE:
            runs = [(0, span)]
        elif kind == KIND_RUNS:
            base = table_end + slot * EXTENT_SLOT_SIZE
            slot += 1
            if base + EXTENT_SLOT_SIZE > len(ubmap):
                raise V2iError(f"ubmap chunk {i}: run list slot is past the end")
            slot_magic, run_count = struct.unpack_from("<HI", ubmap, base)
            if slot_magic != EXTENT_MAGIC:
                raise V2iError(
                    f"ubmap chunk {i}: run list has magic {slot_magic:#06x}"
                )
            # one value per run plus the start of each run after the first
            value_count = run_count * 2 - 1
            if run_count == 0 or base + 14 + value_count * 2 > len(ubmap):
                raise V2iError(
                    f"ubmap chunk {i}: implausible run count {run_count:,}"
                )
            values = struct.unpack_from(f"<{value_count}H", ubmap, base + 14)
            position = struct.unpack_from("<H", ubmap, base + 12)[0]
            for step, value in enumerate(values):
                if step % 2 == 0:
                    runs.append((position, value))
                    position += value
                else:
                    position = value
        elif kind == KIND_BITMAP:
            base = table_end + slot * EXTENT_SLOT_SIZE
            slot += 8
            bitmap = ubmap[base : base + span // 8]
            if len(bitmap) * 8 < span:
                raise V2iError(
                    f"ubmap chunk {i}: bitmap is {len(bitmap)} bytes, too short "
                    f"for {span:,} sectors"
                )
            runs = list(_bitmap_runs(bitmap, span))
        elif kind != KIND_ABSENT:
            raise V2iError(f"ubmap chunk {i}: unknown kind {kind:#06x}")

        if sum(length for _, length in runs) != stored:
            raise V2iError(
                f"ubmap chunk {i}: runs cover "
                f"{sum(length for _, length in runs):,} sectors, "
                f"record claims {stored:,}"
            )

        for offset, length in runs:
            extents.append(Extent(volume_sector + offset, data_sector, length))
            data_sector += length
        volume_sector += span

    if volume_sector != total_sectors:
        raise V2iError(
            f"ubmap chunks span {volume_sector:,} sectors, header says "
            f"{total_sectors:,}"
        )
    return total_sectors, extents


class Volume:
    """Reconstructed volume image, with unallocated space read back as zeros."""

    def __init__(self, image: V2iImage) -> None:
        self.image = image
        self.total_sectors, self.extents = parse_ubmap(image.read_stream("ubmap"))
        self._starts = [e.volume_sector for e in self.extents]
        self.data_stream = image.stream("udata")
        if self.data_stream.length != self.stored_sectors * SECTOR_SIZE:
            raise V2iError(
                f"udata is {self.data_stream.length:,} bytes but ubmap accounts "
                f"for {self.stored_sectors * SECTOR_SIZE:,}"
            )

    @property
    def size(self) -> int:
        return self.total_sectors * SECTOR_SIZE

    @property
    def stored_sectors(self) -> int:
        return sum(e.sectors for e in self.extents)

    @property
    def stored_size(self) -> int:
        return self.stored_sectors * SECTOR_SIZE

    def readable_size(self, available_data_bytes: int) -> int:
        """Highest volume offset reachable from the files actually present.

        ``available_data_bytes`` is how much of ``udata`` the present files
        cover. A complete set returns the full volume size.
        """
        if available_data_bytes >= self.data_stream.length:
            return self.size
        sector = available_data_bytes // SECTOR_SIZE
        limit = 0
        for extent in self.extents:
            if extent.data_sector >= sector:
                break
            reached = min(extent.sectors, sector - extent.data_sector)
            limit = (extent.volume_sector + reached) * SECTOR_SIZE
        return limit

    def read(self, offset: int, length: int) -> bytes:
        """Read volume bytes, zero-filling sectors that were not stored."""
        if offset < 0 or length < 0:
            raise ValueError("offset and length must be non-negative")
        end = min(offset + length, self.size)
        if end <= offset:
            return b""

        out = bytearray(end - offset)
        position = max(bisect_right(self._starts, offset // SECTOR_SIZE) - 1, 0)

        for index in range(position, len(self.extents)):
            extent = self.extents[index]
            extent_start = extent.volume_sector * SECTOR_SIZE
            extent_end = extent.volume_end * SECTOR_SIZE
            if extent_start >= end:
                break
            if extent_end <= offset:
                continue
            take_start = max(offset, extent_start)
            take_end = min(end, extent_end)
            data_offset = (
                extent.data_sector * SECTOR_SIZE + (take_start - extent_start)
            )
            chunk = self.image.read_stream(
                "udata", data_offset, take_end - take_start
            )
            out[take_start - offset : take_end - offset] = chunk

        return bytes(out)

    def write_image(
        self,
        fh,
        offset: int = 0,
        length: int | None = None,
        progress=None,
        chunk_size: int = 1 << 23,
    ) -> int:
        """Write the volume image to ``fh``, seeking over unstored space.

        Only stored sectors are transferred; holes are skipped with a seek
        and left for the filesystem to zero-fill, which avoids pushing tens
        of gigabytes of zeros through Python. Returns the bytes written.
        """
        if offset < 0 or (length is not None and length < 0):
            raise ValueError("offset and length must be non-negative")
        if length is None:
            length = self.size - offset
        end = min(offset + length, self.size)
        if end <= offset:
            fh.truncate(0)
            return 0
        written = 0
        covered = offset
        position = max(bisect_right(self._starts, offset // SECTOR_SIZE) - 1, 0)

        for index in range(position, len(self.extents)):
            extent = self.extents[index]
            extent_start = extent.volume_sector * SECTOR_SIZE
            extent_end = extent.volume_end * SECTOR_SIZE
            if extent_start >= end:
                break
            if extent_end <= offset:
                continue

            take_start = max(offset, extent_start)
            take_end = min(end, extent_end)
            if progress is not None and take_start > covered:
                progress(take_start - covered)
            covered = take_start

            fh.seek(take_start - offset)
            data_offset = (
                extent.data_sector * SECTOR_SIZE + (take_start - extent_start)
            )
            remaining = take_end - take_start
            while remaining:
                take = min(chunk_size, remaining)
                fh.write(self.image.read_stream("udata", data_offset, take))
                data_offset += take
                remaining -= take
                written += take
                covered += take
                if progress is not None:
                    progress(take)

        fh.truncate(end - offset)
        if progress is not None and end > covered:
            progress(end - covered)
        return written

    def iter_image(
        self, offset: int = 0, length: int | None = None, chunk_size: int = 1 << 22
    ) -> Iterator[bytes]:
        """Yield the volume image in chunks, zero-filling unstored space."""
        if length is None:
            length = self.size - offset
        remaining = length
        while remaining > 0:
            take = min(chunk_size, remaining)
            yield self.read(offset, take)
            offset += take
            remaining -= take
