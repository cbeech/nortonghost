"""Checks against a real backup set.

These skip unless a base ``.v2i`` is present in ``samples/`` (gitignored:
real images are large and hold personal data). They assert NTFS facts that
the reader cannot manufacture, such as the boot sector's own geometry and
MFT records self-reporting the number their offset predicts.

The figures below come from the reference backup the format was worked out
against, so they will not match a different image. Anyone testing against
their own backup should expect the geometry assertions to need updating.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from nortonghost.v2i import V2iImage
from nortonghost.volume import Volume

SAMPLE = Path(__file__).resolve().parents[1] / "samples" / "C_Drive001.v2i"

pytestmark = pytest.mark.skipif(
    not SAMPLE.exists(), reason="real sample set not present"
)


@pytest.fixture(scope="module")
def volume():
    with V2iImage(SAMPLE) as image:
        yield Volume(image)


def test_container_totals(volume):
    image = volume.image
    assert image.set_info.file_count == 14
    assert image.set_info.total_blocks == 402_669
    assert [e.name for e in image.streams] == ["gptmd", "ldmmd", "ubmap", "udata"]


def test_ubmap_accounts_for_every_sector(volume):
    # 100,002,954,240 bytes of volume, 64,247,640,064 of it stored
    assert volume.size == 195_318_270 * 512
    assert volume.stored_size == volume.data_stream.length


def test_boot_sector_is_consistent_with_the_sidecar(volume):
    vbr = volume.read(0, 512)
    assert vbr[3:11] == b"NTFS    "
    assert vbr[510:512] == b"\x55\xaa"
    # the sv2i sidecar reports OffsetOnMedia 14,651,280 for this volume
    assert struct.unpack_from("<I", vbr, 0x1C)[0] == 14_651_280
    # the VBR does not count itself, so it is one short of the PART block
    assert struct.unpack_from("<Q", vbr, 0x28)[0] == 195_318_269


def test_mft_records_land_where_the_boot_sector_says(volume):
    vbr = volume.read(0, 512)
    cluster = struct.unpack_from("<H", vbr, 0x0B)[0] * vbr[0x0D]
    mft = struct.unpack_from("<Q", vbr, 0x30)[0] * cluster

    for number in (0, 1, 5, 100, 10_000):
        record = volume.read(mft + number * 1024, 48)
        assert record[:4] == b"FILE"
        assert struct.unpack_from("<I", record, 0x2C)[0] == number


def test_mft_mirror_matches_the_mft(volume):
    vbr = volume.read(0, 512)
    cluster = struct.unpack_from("<H", vbr, 0x0B)[0] * vbr[0x0D]
    mft = struct.unpack_from("<Q", vbr, 0x30)[0] * cluster
    mirror = struct.unpack_from("<Q", vbr, 0x38)[0] * cluster

    # NTFS keeps the first four records mirrored; the two copies live in
    # different chunks, blocks and extents of the image.
    assert volume.read(mirror, 4 * 1024) == volume.read(mft, 4 * 1024)


def test_real_block_checksums_verify(volume):
    image = volume.image
    image.index_blocks()
    # a slice is enough here; `nortonghost verify` walks the whole set
    assert all(image.verify_block(position) for position in range(200))


def test_unstored_space_reads_back_as_zeros(volume):
    gap = next(
        (a, b)
        for a, b in zip(volume.extents, volume.extents[1:])
        if a.volume_end < b.volume_sector
    )
    start = gap[0].volume_end * 512
    length = min((gap[1].volume_sector - gap[0].volume_end) * 512, 65536)
    assert volume.read(start, length) == bytes(length)


def test_files_come_back_out_of_the_image(volume):
    """Recover files straight from the .v2i, with no extraction step."""
    from nortonghost.ntfs import NtfsVolume

    fs = NtfsVolume(volume)

    root = {entry.name for entry in fs.listdir(5)}
    assert {"WINDOWS", "Program Files", "Documents and Settings"} <= root

    boot_ini = fs.resolve("/boot.ini")
    assert not boot_ini.is_directory
    text = b"".join(fs.iter_file(boot_ini.record_number)).decode("ascii")
    assert text.startswith("[boot loader]")
    assert "Windows XP" in text

    # a compressed, heavily fragmented system binary must come back a valid PE
    kernel = fs.resolve("/WINDOWS/system32/ntoskrnl.exe")
    data = b"".join(fs.iter_file(kernel.record_number))
    assert len(data) == fs.file_size(kernel.record_number)
    assert data[:2] == b"MZ"
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    assert data[pe_offset : pe_offset + 4] == b"PE\x00\x00"


def test_a_compressed_attribute_decompresses(volume):
    from nortonghost.ntfs import ATTR_DATA, NtfsVolume

    fs = NtfsVolume(volume)
    found = 0
    for number in range(5, 1000):
        try:
            record = fs.record(number)
        except Exception:
            continue
        flags = struct.unpack_from("<H", record, 0x16)[0]
        if not flags & 1 or flags & 2:
            continue
        attribute = fs.find_attribute(record, ATTR_DATA)
        if attribute is None or attribute.resident or not attribute.compressed:
            continue
        data = b"".join(fs.iter_file(number))
        assert len(data) == attribute.data_size
        found += 1
        if found == 3:
            break
    assert found == 3, "expected compressed files in the first 1000 MFT records"
