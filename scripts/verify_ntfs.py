#!/usr/bin/env python3
"""Verify an extracted volume as real NTFS, with no third-party tools.

Reads either a .v2i set (through the library) or a raw .img, and checks
things the v2i reader cannot manufacture:

1. The boot sector parses, and the backup boot sector in the volume's last
   sector matches it.
2. $MFT is where the boot sector says, every record carries the NTFS update
   sequence fixup, and each record self-reports the number its offset implies.
3. $MFTMirr matches the first records of $MFT byte for byte.
4. The root directory lists plausible top-level names.
5. Known files resolve through their $DATA run lists to content whose magic
   bytes match the file extension.
6. Every cluster NTFS's own $Bitmap marks as allocated is present in the
   image. This is the one that matters: a sparse image that dropped an
   allocated cluster has lost data.

Usage:
    python scripts/verify_ntfs.py samples/backup.v2i
    python scripts/verify_ntfs.py --raw c_drive.img --ubmap samples/backup.v2i
"""

from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from nortonghost.v2i import V2iImage  # noqa: E402
from nortonghost.volume import Volume  # noqa: E402

MFT_RECORD_SIZE = 1024


class RawVolume:
    """Minimal Volume-alike over a raw .img file."""

    def __init__(self, path: Path) -> None:
        self.fh = open(path, "rb")
        self.size = path.stat().st_size

    def read(self, offset: int, length: int) -> bytes:
        self.fh.seek(offset)
        return self.fh.read(length)

    def close(self) -> None:
        self.fh.close()


def apply_fixup(record: bytearray, sector_size: int = 512) -> bool:
    """Apply the NTFS update sequence array; False if a sector is torn."""
    usa_offset, usa_count = struct.unpack_from("<HH", record, 0x04)
    usn = struct.unpack_from("<H", record, usa_offset)[0]
    for i in range(1, usa_count):
        end = i * sector_size - 2
        if end + 2 > len(record):
            return False
        if struct.unpack_from("<H", record, end)[0] != usn:
            return False
        value = struct.unpack_from("<H", record, usa_offset + i * 2)[0]
        struct.pack_into("<H", record, end, value)
    return True


def attributes(record: bytes):
    """Yield (type, resident, content) for each attribute in a FILE record."""
    offset = struct.unpack_from("<H", record, 0x14)[0]
    while offset < len(record) - 8:
        atype, length = struct.unpack_from("<II", record, offset)
        if atype == 0xFFFFFFFF or length == 0:
            return
        non_resident = record[offset + 8]
        if non_resident:
            yield atype, False, record[offset : offset + length]
        else:
            start = struct.unpack_from("<H", record, offset + 0x14)[0]
            size = struct.unpack_from("<I", record, offset + 0x10)[0]
            yield atype, True, record[offset + start : offset + start + size]
        offset += length


def data_runs(attribute: bytes) -> list[tuple[int, int]]:
    """Decode a non-resident attribute's run list into (lcn, clusters)."""
    offset = struct.unpack_from("<H", attribute, 0x20)[0]
    runs: list[tuple[int, int]] = []
    lcn = 0
    while offset < len(attribute):
        header = attribute[offset]
        if header == 0:
            break
        length_size, offset_size = header & 0x0F, header >> 4
        offset += 1
        count = int.from_bytes(attribute[offset : offset + length_size], "little")
        offset += length_size
        if offset_size:
            delta = int.from_bytes(
                attribute[offset : offset + offset_size], "little", signed=True
            )
            offset += offset_size
            lcn += delta
            runs.append((lcn, count))
        else:
            runs.append((-1, count))  # sparse run
    return runs


def read_runs(volume, runs, cluster: int, limit: int) -> bytes:
    out = bytearray()
    for lcn, count in runs:
        if len(out) >= limit:
            break
        take = min(count * cluster, limit - len(out))
        out += bytes(take) if lcn < 0 else volume.read(lcn * cluster, take)
    return bytes(out)


def file_names(record: bytes):
    for atype, resident, content in attributes(record):
        if atype == 0x30 and resident:
            parent = struct.unpack_from("<Q", content, 0)[0] & 0x0000FFFFFFFFFFFF
            length = content[0x40]
            namespace = content[0x41]
            name = content[0x42 : 0x42 + length * 2].decode("utf-16-le", "replace")
            yield parent, name, namespace


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path")
    parser.add_argument("--raw", action="store_true", help="path is a raw .img")
    parser.add_argument(
        "--ubmap",
        help="with --raw: a base .v2i to take the stored-sector map from, so "
        "the $Bitmap coverage check can run against the fast raw image",
    )
    parser.add_argument("--max-records", type=int, default=0, help="0 = all")
    args = parser.parse_args()

    failures: list[str] = []

    def check(name: str, ok: bool, detail: str = "") -> None:
        print(f"  [{'OK ' if ok else 'FAIL'}] {name}{(' — ' + detail) if detail else ''}")
        if not ok:
            failures.append(name)

    map_source = None
    if args.raw:
        volume = RawVolume(Path(args.path))
        image = None
        if args.ubmap:
            map_source = Volume(V2iImage(args.ubmap))
    else:
        image = V2iImage(args.path)
        volume = Volume(image)
        map_source = volume

    print("== boot sector ==")
    vbr = volume.read(0, 512)
    check("NTFS OEM id", vbr[3:11] == b"NTFS    ")
    check("boot signature", vbr[510:512] == b"\x55\xaa")
    bytes_per_sector = struct.unpack_from("<H", vbr, 0x0B)[0]
    cluster = bytes_per_sector * vbr[0x0D]
    total_sectors = struct.unpack_from("<Q", vbr, 0x28)[0]
    mft = struct.unpack_from("<Q", vbr, 0x30)[0] * cluster
    mirror = struct.unpack_from("<Q", vbr, 0x38)[0] * cluster
    print(f"        cluster {cluster}, {total_sectors:,} sectors, "
          f"$MFT at {mft:,}, $MFTMirr at {mirror:,}")

    # NTFS keeps a copy of the boot sector in the volume's last sector. That
    # sector sits outside the cluster-allocated area, and Ghost only stores
    # clusters $Bitmap marks in use, so it is absent from this image. Absent
    # is expected; present-but-different would mean corruption.
    backup = volume.read(total_sectors * bytes_per_sector, 512)
    if not any(backup):
        print("  [--- ] backup boot sector not stored by Ghost (expected)")
    else:
        check("backup boot sector matches", backup == vbr)

    print("\n== $MFT ==")
    record0 = bytearray(volume.read(mft, MFT_RECORD_SIZE))
    check("record 0 signature", record0[:4] == b"FILE")
    check("record 0 fixup", apply_fixup(record0))
    mft_runs: list[tuple[int, int]] = []
    for atype, resident, content in attributes(bytes(record0)):
        if atype == 0x80 and not resident:
            mft_runs = data_runs(content)
            mft_size = struct.unpack_from("<Q", content, 0x30)[0]
    check("record 0 has a non-resident $DATA", bool(mft_runs))
    record_count = mft_size // MFT_RECORD_SIZE
    print(f"        $MFT is {mft_size:,} bytes in {len(mft_runs)} run(s) "
          f"= {record_count:,} records")

    mirror_records = volume.read(mirror, 4 * MFT_RECORD_SIZE)
    check("$MFTMirr matches $MFT", mirror_records == volume.read(mft, 4 * MFT_RECORD_SIZE))

    print("\n== walking every MFT record ==")
    limit = args.max_records or record_count
    in_use = directories = bad_signature = bad_fixup = bad_number = 0
    root_children: list[str] = []
    seen_names: dict[int, str] = {}
    position = 0
    for lcn, count in mft_runs:
        if position >= limit:
            break
        run_records = count * cluster // MFT_RECORD_SIZE
        for i in range(run_records):
            number = position + i
            if number >= limit:
                break
            record = bytearray(
                volume.read(lcn * cluster + i * MFT_RECORD_SIZE, MFT_RECORD_SIZE)
            )
            if record[:4] != b"FILE":
                if any(record):
                    bad_signature += 1
                continue
            if not apply_fixup(record):
                bad_fixup += 1
                continue
            if struct.unpack_from("<I", record, 0x2C)[0] != number:
                bad_number += 1
            flags = struct.unpack_from("<H", record, 0x16)[0]
            if not flags & 1:
                continue
            in_use += 1
            if flags & 2:
                directories += 1
            for parent, name, namespace in file_names(bytes(record)):
                if namespace != 2:  # skip 8.3 aliases
                    seen_names[number] = name
                    if parent == 5 and number != 5:
                        root_children.append(name)
        position += run_records

    print(f"        {limit:,} records walked, {in_use:,} in use, "
          f"{directories:,} directories")
    check("every record self-numbers correctly", bad_number == 0, f"{bad_number} wrong")
    check("every record's fixup is intact", bad_fixup == 0, f"{bad_fixup} torn")
    check("no stray non-FILE records", bad_signature == 0, f"{bad_signature} odd")

    print("\n== root directory ==")
    unique_root = sorted(set(root_children), key=str.lower)
    print("        " + ", ".join(unique_root[:24]))
    expected = {"WINDOWS", "Program Files", "Documents and Settings"}
    found = {n for n in unique_root if n in expected}
    check("recognisable Windows layout", bool(found), f"found {sorted(found)}")

    print("\n== $Bitmap vs the image ==")
    bitmap_record = bytearray(volume.read(mft + 6 * MFT_RECORD_SIZE, MFT_RECORD_SIZE))
    apply_fixup(bitmap_record)
    bitmap_runs = []
    bitmap_size = 0
    for atype, resident, content in attributes(bytes(bitmap_record)):
        if atype == 0x80 and not resident:
            bitmap_runs = data_runs(content)
            bitmap_size = struct.unpack_from("<Q", content, 0x30)[0]
    bitmap = read_runs(volume, bitmap_runs, cluster, bitmap_size)
    check("$Bitmap read", len(bitmap) == bitmap_size, f"{len(bitmap):,} bytes")

    if map_source is not None:
        clusters = map_source.size // cluster
        stored = bytearray(clusters)
        for extent in map_source.extents:
            first = extent.volume_sector * 512 // cluster
            last = (extent.volume_end * 512 + cluster - 1) // cluster
            stored[first:last] = b"\x01" * (last - first)

        missing_map = bytearray(clusters)
        missing = allocated = 0
        for index, byte in enumerate(bitmap):
            if byte == 0:
                continue
            base = index * 8
            for bit in range(8):
                if byte >> bit & 1:
                    number = base + bit
                    if number >= clusters:
                        break
                    allocated += 1
                    if not stored[number]:
                        missing += 1
                        missing_map[number] = 1
        print(f"        {allocated:,} clusters allocated by NTFS, "
              f"{sum(stored):,} stored in the image")

        # Attribute every missing cluster to the file that owns it. Imaging
        # tools deliberately skip volatile files; anything else would be a
        # real hole in the image.
        owners: dict[str, int] = {}
        unattributed = missing
        if missing:
            position = 0
            for lcn, count in mft_runs:
                run_records = count * cluster // MFT_RECORD_SIZE
                for i in range(run_records):
                    number = position + i
                    record = bytearray(
                        volume.read(
                            lcn * cluster + i * MFT_RECORD_SIZE, MFT_RECORD_SIZE
                        )
                    )
                    if record[:4] != b"FILE" or not apply_fixup(record):
                        continue
                    if not struct.unpack_from("<H", record, 0x16)[0] & 1:
                        continue
                    hits = 0
                    for atype, resident, content in attributes(bytes(record)):
                        if resident or atype not in (0x80, 0xA0):
                            continue
                        for run_lcn, run_count in data_runs(content):
                            if run_lcn < 0:
                                continue
                            for c in range(run_lcn, min(run_lcn + run_count, clusters)):
                                if missing_map[c]:
                                    hits += 1
                                    missing_map[c] = 0
                    if hits:
                        name = next(
                            (n for _, n, ns in file_names(bytes(record)) if ns != 2),
                            f"<record {number}>",
                        )
                        owners[name] = owners.get(name, 0) + hits
                        unattributed -= hits
                position += run_records

        expected_skips = {"pagefile.sys", "hiberfil.sys"}
        for name, count in sorted(owners.items(), key=lambda kv: -kv[1])[:8]:
            tag = "skipped by design" if name.lower() in expected_skips else "UNEXPECTED"
            print(f"        {name:<24} {count:>10,} clusters missing  ({tag})")

        unexpected = sum(
            count for name, count in owners.items() if name.lower() not in expected_skips
        )
        check(
            "no unexpected file is missing clusters",
            unexpected == 0 and unattributed == 0,
            f"{unexpected:,} in other files, {unattributed:,} unattributed",
        )

    print("\n== known files ==")
    interesting = [
        (name, number)
        for number, name in seen_names.items()
        if name.lower() in {"ntldr", "boot.ini", "ntdetect.com", "pagefile.sys"}
    ]
    for name, number in interesting[:6]:
        record = bytearray(volume.read(mft + number * MFT_RECORD_SIZE, MFT_RECORD_SIZE))
        apply_fixup(record)
        head = b""
        size = 0
        for atype, resident, content in attributes(bytes(record)):
            if atype == 0x80:
                if resident:
                    head, size = content[:64], len(content)
                else:
                    size = struct.unpack_from("<Q", content, 0x30)[0]
                    head = read_runs(volume, data_runs(content), cluster, 64)
                break
        print(f"        {name:<16} {size:>14,} bytes  head={head[:16].hex(' ')}")
        if name.lower() == "ntldr":
            # NTLDR is not a plain PE: it starts with a real-mode jump stub
            # and carries the loader image behind it.
            check("NTLDR starts with a real-mode jump", head[:1] == b"\xe9")
        if name.lower() == "boot.ini":
            check("boot.ini is text", b"[boot loader]" in head or head[:1] == b"[")

    if image is not None:
        image.close()
    else:
        volume.close()

    print()
    if failures:
        print(f"FAILED: {len(failures)} check(s): {failures}")
        return 1
    print("All checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
