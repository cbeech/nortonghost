# .v2i / .sv2i format notes

Byte-level documentation of the Symantec/Norton Ghost `.v2i` container,
reverse engineered from a real backup set. Written so that someone can build
another reader without repeating the work.

Every claim here was checked against an independent signal, usually a real
NTFS structure landing exactly where the parse predicted. Where a guess turned
out to be wrong, the wrong turn is recorded too. If you are building your own
reader, read "Corrections to earlier notes" and the dead ends first: they will
save you more time than the confirmed layouts.

The reference sample: one 100 GB NTFS volume on an MBR disk, spanned across 14
files, written by Norton Ghost 10.0.0.1 in 2008.

## Source material

The backup set used as ground truth throughout:

```
<backup folder>\
  BACKUP.sv2i              1,472 bytes   - descriptor (see below)
  C_Drive001.v2i          4,044,357,632 bytes  (base image)
  C_Drive001_s01.v2i .. s12.v2i   4,044,357,632 bytes each (spans)
  C_Drive001_s13.v2i       201,981,952 bytes  (final, shorter span)
```

Created 2008-09-30. Total image size ~48.6 GB across the base file plus 12
full spans and one partial final span. The 4,044,357,632-byte span size looks
deliberately chosen (just under 4 GiB / a FAT32-friendly ceiling), consistent
with Ghost's known behavior of splitting images for FAT32 destination media.

Reverse engineering this needs random access across the whole set, so keep the
files on local storage while working: probing offsets and hex-diffing spans is
latency-bound, not bandwidth-bound, and doing it over a network share is
painfully slow even when sequential throughput looks fine.

## BACKUP.sv2i: plain-text XML sidecar

Not binary. It is a "Storage Descriptor Object" (`SDO`) XML document, one
`<VolumeN>` element per volume on the original disk, each carrying a
`vt="NN"` type tag (looks like a serialized `VARIANT` type code, e.g. `vt="8"`
is BSTR/string, `vt="21"` is a 64-bit int, `vt="11"` is bool, `vt="19"` is
int32, `vt="13"` is a nested struct) and one or more `<SegmentN>` children
describing where that volume's data sits.

Full captured content (from `BACKUP.sv2i`, reformatted for readability):

```xml
<SDO clsid="{E097FFA2-58F0-4EDC-8489-4A4BD6230F26}">
  <Volume1 vt="13" clsid="{C85BC36B-53ED-4760-A388-DE72B0A04119}">
    <VolumeType vt="8">Simple</VolumeType>
    <IsHidden vt="11">0</IsHidden>
    <IsActive vt="11">0</IsActive>
    <ImageFile vt="8"></ImageFile>
    <Size vt="21">7501422592</Size>
    <Segment1 vt="13" clsid="{C9D92A04-7744-4697-A02A-A0AAEB01A9AD}">
      <DeviceNumber vt="19">0</DeviceNumber>
      <IsLogical vt="11">0</IsLogical>
      <Size vt="21">7501423104</Size>
      <OffsetOnMedia vt="21">63</OffsetOnMedia>
    </Segment1>
  </Volume1>
  <Volume2 vt="13" clsid="{C85BC36B-53ED-4760-A388-DE72B0A04119}">
    <VolumeType vt="8">Simple</VolumeType>
    <IsHidden vt="11">0</IsHidden>
    <IsActive vt="11">-1</IsActive>
    <ImageFile vt="8">D:\Norton Ghost Backups\C_Drive001.v2i</ImageFile>
    <Size vt="21">100002951168</Size>
    <Segment1 vt="13" clsid="{C9D92A04-7744-4697-A02A-A0AAEB01A9AD}">
      <DeviceNumber vt="19">0</DeviceNumber>
      <IsLogical vt="11">0</IsLogical>
      <Size vt="21">100002954240</Size>
      <OffsetOnMedia vt="21">14651280</OffsetOnMedia>
    </Segment1>
  </Volume2>
  <Volume3 vt="13" clsid="{C85BC36B-53ED-4760-A388-DE72B0A04119}">
    <VolumeType vt="8">Simple</VolumeType>
    <IsHidden vt="11">0</IsHidden>
    <IsActive vt="11">0</IsActive>
    <ImageFile vt="8"></ImageFile>
    <Size vt="21">92542590976</Size>
    <Segment1 vt="13" clsid="{C9D92A04-7744-4697-A02A-A0AAEB01A9AD}">
      <DeviceNumber vt="19">0</DeviceNumber>
      <IsLogical vt="11">-1</IsLogical>
      <Size vt="21">92542593024</Size>
      <OffsetOnMedia vt="21">209969613</OffsetOnMedia>
    </Segment1>
  </Volume3>
</SDO>
```

Reading: only **Volume2** has a non-empty `ImageFile`, pointing at
`C_Drive001.v2i` (the base file; the `s01`..`s13` spans are presumably found
by the reader via naming convention, not listed individually in the sv2i).
Volume2's `Size` (~100 GB) is the *original partition* size, not the image
file size (~48.6 GB), so the image is compressed and/or sparse
(unallocated-cluster-aware), matching Ghost's known behavior of only imaging
used sectors. Volume1 (~7.5 GB, offset 63 sectors) and Volume3 (~92.5 GB,
"IsLogical") look like a small first partition (recovery/boot?) and an
extended/logical partition, both present on the original disk but *not*
imaged (empty `ImageFile`), so the backup only covers the C: drive (Volume2).

Open questions this raises:
- Where exactly do span files (`_s01.v2i` etc.) get named/ordered? By
  convention (`_sNN` suffix, zero-padded, sequential) or is there an
  in-file pointer to the next span?
- Is `OffsetOnMedia` in bytes or sectors? (63 for Volume1 strongly suggests
  sectors, the classic MBR "first partition starts at sector 63", so
  probably sectors elsewhere too; needs confirming against a `.sv2i` for a
  disk with a known partition table.)

## .v2i binary format — confirmed structure

### File header (96 bytes, at offset 0x00)

Both base and span files begin with a 96-byte header. The header length is
confirmed by the field at offset 0x08 (`0x60` = 96) and by the observation
that offset 0x60 is where either zero-padding (base) or compressed payload
data (span) begins.

**Base file** (`C_Drive001.v2i`):

```
Offset  Hex                                               Field
0x00    78 89 26 12                                       Magic: 0x12268978
0x04    00 08 00 00                                       First data block offset: 0x800 (2048)
0x08    60 00 00 00                                       Header length: 96
0x0C    00 00 01 01                                       Version/flags: 0x01010000
0x10    76 8f c9 45                                       Image ID: 0x45c98f76
0x14    03 00 07 00                                       Format version: 7.3 (or 3.7?)
0x18    00 00 00 00                                       (zero)
0x1C    00 00 02 00                                       Block size: 131072 (128 KB)
0x20    00 00 02 00                                       Block size (duplicate): 131072
0x24-2F 00 00 00 00 00 00 00 00 00 00 00 00               (zeros)
0x30    00 00 00 00                                       Span boundary table offset?: 0 (base)
0x34    02 00 00 00                                       Counter/type: 2
0x38-3F 00 00 00 00 00 00 00 00                           (zeros in base)
0x40    a0 ff 01 00                                       Data field A: 130,976
0x44    a0 07 00 00                                       Data field B: 1,952 (= 0x800 - 0x60)
0x48-57 00 00 00 00 ... 00 00 00 00                       (zeros)
0x58    f7 db 89 3a 0d 94 52 bd                           Checksum or hash (8 bytes)
```

**Span file** (`C_Drive001_s01.v2i`):

```
Offset  Hex                                               Field
0x00    24 43 41 4e                                       Magic: "$CAN" (0x4e414324)
0x04    60 00 00 00                                       First data offset: 0x60 (96)
0x08    60 00 00 00                                       Header length: 96
0x0C    00 00 01 01                                       Version/flags: 0x01010000  (SAME)
0x10    76 8f c9 45                                       Image ID: 0x45c98f76       (SAME)
0x14    03 00 07 00                                       Format version: 7.3        (SAME)
0x18    00 00 00 00                                       (zero)                     (SAME)
0x1C    00 00 02 00                                       Block size: 131072         (SAME)
0x20    00 00 02 00                                       Block size (duplicate)     (SAME)
0x24-2F 00 00 00 00 ...                                   (zeros)                    (SAME)
0x30    88 78 00 00                                       Block sequence number: 30,856
0x34    01 00 00 00                                       Counter/type: 1
0x38    90 cf a0 8d                                       Unknown
0x3C    01 00 00 00                                       Unknown: 1
0x40    70 ff 01 00                                       Data field A: 130,928
0x48    c2 fe 01 00                                       Data field C: 130,754
0x58    30 57 1b c7 cf 16 a1 62                           Checksum or hash (different)
```

Key findings from the comparison:

- **Two distinct magic numbers**: base file uses `0x12268978`, span files
  use `$CAN` (`0x4e414324`). This means they are NOT the same format — the
  base file is the "master" container and the spans are continuation data.
- **Offsets 0x0C–0x28 are byte-identical** across base and span — these are
  image-wide constants (version, block size, image ID).
- **Offsets 0x30–0x5C differ** — per-file metadata (counters, checksums).
- **Offset 0x04**: in the base file this is `0x800` (2048), pointing to
  the `$CDH` block; in the span this is `0x60` (96), meaning compressed
  data starts immediately after the 96-byte header.
- **Span data at offset 0x60** has entropy of **7.18 bits/byte** — very
  high, consistent with compressed (probably zlib) data, not encryption.

### `$CDH` block (at offset 0x800 in base file only)

The base file contains a "Compressed Data Header" block starting at offset
0x800 (pointed to by the base header's offset 0x04 field). The span files
do NOT have this block; they begin compressed payload immediately at 0x60.

```
Offset  Hex                                               Field
0x800   24 43 44 48                                       Magic: "$CDH"
0x804   fc 2f 00 00                                       Block total size: 12,284 bytes
0x808   60 00 00 00                                       Sub-header length: 96
0x80C   8e 03 00 00                                       Entry count: 910
0x810   08 a6 86 f5 0e 00 00 00                           Total logical stream size: 64,248,784,392
0x818   ed 24 06 00                                       Total block count: 402,669
0x81C   0e 00 00 00                                       Span count: 14
0x820   2c a5 00 00                                       42,284
0x824   00 02 00 00                                       Sector size: 512
0x828   00 04 00 00                                       1,024
0x82C   e7 03 00 00                                       999
0x830-85F  00 00 ...                                      (zero padding to sub-header boundary)
```

Immediately after the `$CDH` sub-header (at offset 0x860), there is an
**offset table**: `910` entries of `uint64` LE values. These appear to be
cumulative byte offsets into the concatenated compressed stream, mapping
from block indices to the compressed-data position where that block's data
begins. The entries are monotonically increasing, with the last several
entries clamped to the total compressed size `64,248,784,392`.

```
Entry     Offset (hex)              Offset (decimal)
[0]       0x0000000009426a61        155,347,553
[1]       0x000000000d980715        228,067,093
...
[905-909] 0x0000000ef586a608        64,248,784,392 (clamped)
```

Delta between entries averages ~67 MB (range: 0 to ~230 MB), consistent
with ~128 KB blocks compressed at varying ratios.

After the offset table (at 0x24D0), there is a **repeated value region**:
the uint64 value `0x0000000ef586a608` (= 64,248,784,392 = total compressed
size) repeated many times. This is the same value recorded at `$CDH` +0x10,
confirming it as the total logical stream size across all spans.

### Span boundary table (at offset 0x2860 in base file)

At offset 0x2860 in the base file, there is a table of `uint32` LE values
representing **cumulative block counts at span boundaries**:

```
Index   Value       Delta     Interpretation
[0]     30,856      30,856    Blocks in span 0 (base file)
[1]     61,712      30,856    Cumulative through span 1
...
[12]    401,128     30,856    Cumulative through span 12
[13+]   401,128     0         (clamped / padding)
```

Critical identity: `30,856 * 131,072 = 4,044,357,632` — that is, the
number of blocks per full span multiplied by the block size (128 KB) equals
**exactly** the span file size. This confirms:

- Block size = 131,072 bytes (128 KB) — **confirmed**
- Each full span holds exactly 30,856 blocks of compressed data
- The span file size (4,044,357,632) is *not* arbitrary but equals
  `block_count * block_size` — spans are block-aligned

The last unique value (`401,128`) times block size gives `52,576,649,216`
bytes (~49.0 GB), close to the total image size (~48.6 GB). The slight
discrepancy may be due to the final partial span (`C_Drive001_s13.v2i`,
only ~192 MB) contributing fewer blocks.

### `PART` block (at offset 0x3938 in base file)

At offset 0x3938 there is a volume/partition descriptor block:

```
Offset  Hex                                               Field
0x3938  50 41 52 54                                       Magic: "PART"
0x393C  2e 01 00 00                                       Block size: 302
0x3940  09 00 00 00                                       Unknown: 9
0x3944  7e 8f c9 45                                       Image ID (matches header 0x10)
0x3948  07 00 00 00                                       Unknown: 7
0x394C  04 00 00 00                                       Unknown: 4
0x3950  43 00 00 00                                       67 (ASCII 'C' — drive letter?)
0x3954  00 02 00 00                                       Sector size: 512
0x3958  08 00 00 00                                       Unknown: 8
0x395C  00 00 00 00                                       (zero)
0x3960  fe 51 a4 0b                                       Vol2 size in sectors: 195,318,270
0x3964  fe 51 a4 0b                                       (duplicate)
0x3968  01 00 00 00                                       (1)
0x396C  fe 51 a4 0b                                       (triplicate)
0x3970  98 ba 7a 07                                       125,631,128 (used sectors?)
0x3974  47 c9 6c 0a                                       174,868,807
0x3978  47 c9 6c 0a                                       (duplicate)
```

Cross-check: `195,318,270 * 512 = 100,002,954,240` bytes, which matches
**exactly** the `<Size>` of Volume2's Segment1 in the .sv2i. This confirms
both the sector-size and that the PART block stores the original partition
geometry.

Further in the PART block (at 0x39C0):
```
0x39C0  90 8f df 00                                       Vol2 OffsetOnMedia: 14,651,280
```

This also matches the sv2i's `OffsetOnMedia` for Volume2 — sectors from
the start of the disk to this partition. Combined with the sector-size
confirmation, **OffsetOnMedia is in sectors** (not bytes), resolving the
earlier open question.

## The logical stream

Everything above 0x20000 in the base file, and every span file, feeds one
**logical byte stream**. The stream is what the rest of the format is
addressed in; the physical slots only carry it.

### Slots

Every file is a sequence of 128 KB slots, and every slot is a 96-byte
header plus a 130,976-byte payload.

- The base file's **first slot** is the metadata slot (file header, `$CDH`,
  `$CDED`, `PART`). Its payload is stored **raw**, so file offsets
  `96 .. 131,071` are stream offsets `0 .. 130,975`.
- Every later slot, and every slot of a span file, is a `$CAN` block whose
  payload is compressed.

The base file header's field at 0x40 (130,976) is the metadata slot's own
contribution to the stream, which is why the first `$CAN` block reports a
stream offset of exactly 130,976.

This 96-byte shift is easy to get wrong and silently *almost* works: the
`ubmap` sub-stream still appears to parse if you assume file offsets equal
stream offsets, because the mistake is absorbed by its header. It shows up
as three chunk records apparently missing at the metadata/first-block seam.

### `$CAN` block header

```
Offset  Size   Field                       Notes
0x00    4      Magic "$CAN"
0x30    uint32 Block sequence number       1-based, continuous across spans
0x34    uint32 Unknown                     1 in both base and span files
0x38    uint64 Stream offset               Absolute position in the stream
0x40    uint64 Stream length               Bytes this block contributes
0x48    uint64 Deflate size                Compressed bytes + 1 (the flag byte)
0x58    uint64 Per-block checksum
```

`stream_offset[n+1] = stream_offset[n] + stream_length[n]`, verified across
all 61,711 blocks of the base file and first span, and the first span's
first block continues the base's last block exactly (offset 6,671,093,648,
sequence 30,856). Because the offset is stored per block, a reader can
binary-search the headers and decompress only the block it needs — no
sequential scan, and only 96 bytes read per 128 KB slot.

### Block payload: deflate plus a literal tail

A payload is `[1 flag byte 0x74][raw deflate stream][literal tail]`.

The deflate stream ends before the payload does, and **the leftover bytes
are real data, not padding** — they are the continuation of the stream,
stored uncompressed. The block contributes `inflate(stream) + tail`, and
that total equals the header's stream length exactly:

```
stream_length = len(inflate(deflate_stream)) + (130,976 - deflate_size)
```

Confirmed on every block read so far. The tail is easy to mistake for
padding; in base block 1 it is 1,017 bytes of UTF-16LE filename fragments.
Treating it as padding shifts everything after the first block and quietly
corrupts the whole image.

## Named sub-streams: the `$CDED` directory

The metadata slot holds a directory of named sub-streams, one `$CDED`
entry each:

```
Offset  Size   Field
0x00    8      Magic "$CDED" + 3 zero bytes
0x08    uint32 Entry id
0x0C    uint32 Kind (4 for all four observed entries)
0x18    uint64 Stream offset
0x20    uint64 Length in bytes
0x28    uint32 Offset of the name within the entry (0x38)
0x2C    uint32 Name length in UTF-16 characters, including the terminator
0x38    ...    Name, UTF-16LE
```

For the reference sample:

```
Name    Id  Stream offset        Length
gptmd    5             76,582                 12
ldmmd    6             76,594                 12
ubmap    7             76,606          1,054,528
udata    8          1,131,134     64,247,640,064
```

`gptmd` and `ldmmd` are 12 bytes each (GPT and LDM metadata, empty on this
MBR disk). `ubmap` and `udata` are the image proper.

## `ubmap`: the used-block map

`udata` holds only the sectors that were in use — 64,247,640,064 bytes of a
100,002,954,240-byte volume (64.2%). `ubmap` says where each stored sector
belongs.

```
Offset  Size   Field
+0      uint32 Unknown (2,130,708)
+4      uint32 Total sectors on the volume (195,318,270)
+8      uint32 Zero
+12     uint32 Chunk record count (5,961)
+16     uint32 Unknown (0x83140020)
+32     ...    Chunk records, 32 bytes each
```

Each chunk record covers a run of consecutive volume sectors — 32,768
(16 MB) except the last, which covers the remainder:

```
Offset  Size   Field
+0      uint16 Magic 0x3474
+2      uint32 Chunk index (sequential from 0)
+6      uint16 Sectors spanned
+8      uint16 Sectors stored
+10     uint16 Kind: 0x000 absent, 0x100 whole, 0x200 run list, 0x300 bitmap
+12     uint16 First stored sector, relative to the chunk
+14     uint16 Last stored sector
+16     uint16 First absent sector
+18     uint16 Last absent sector
```

For the reference sample: 2,402 whole chunks, 1,886 absent, 1,671 run-list and
2 bitmap. The spans sum to exactly 195,318,270 sectors and the stored
counts to exactly 125,483,672 sectors, which is exactly `udata`'s length.

### Per-chunk detail

Chunks of kind 0x200 and 0x300 describe themselves in a table of 512-byte
slots that follows the chunk records. Slots are consumed **in chunk order**:
one slot for a run list, eight consecutive slots for a bitmap. For the
reference sample that is `1,671 * 1 + 2 * 8 = 1,687` slots, which is exactly
the space between the end of the chunk records and the end of `ubmap`.

Run-list slot:

```
Offset  Size     Field
+0      uint16   Magic 0x2290
+2      uint32   Number of stored runs
+10     uint16   Magic 0x2290 again
+12     uint16   Start sector of the first stored run
+14     uint16[] Run length, next run start, run length, ... (2n-1 values)
```

The values alternate: a run length, then the absolute (chunk-relative)
start of the next run. A leading gap is expressed by the start at +12
being non-zero; a trailing gap is implicit, since the last run need not
reach the end of the chunk. Both cases occur in the sample and both are
easy to miss — chunks 0..44 have neither.

Bitmap slot: 4,096 bytes, one bit per sector of the chunk, set when the
sector is stored, LSB first. Used when a run list would not fit.

All 4,075 non-empty chunks decode with their run/bit counts matching the
record's stored count exactly.

### Mapping a volume offset to `udata`

Walk the chunks in order, accumulating a `udata` cursor over each stored
run. That yields 14,787 extents of `(volume_sector, data_sector, count)`
for the sample. Sectors not covered by an extent were never stored and
read back as zeros.

## Verification

Independent checks, none of which our own parser can manufacture:

- The NTFS boot sector is at volume offset 0, with `hidden sectors` =
  14,651,280 (matching the sv2i's `OffsetOnMedia`) and `total sectors` =
  195,318,269 (one less than the `PART` block, as the VBR does not count
  itself).
- `$MFT` is at the LCN the boot sector names (786,432, i.e. volume offset
  3,221,225,472). MFT records there self-report record numbers 0, 1, 5,
  100 and 10,000 at exactly the offsets `record_number * 1024` predicts.
  This was first found by binary-searching the block index to base block
  16,042 — so the stream offsets hold across thousands of blocks.
- `$MFTMirr` is at LCN 16 (volume offset 65,536) and its first four
  records are **byte-identical** to the first four records of `$MFT`,
  as NTFS requires. The two copies come from different chunks, different
  `$CAN` blocks and different sparse extents.
- Records 0..5 of `$MFT` carry the names `$MFT`, `$MFTMirr`, `$LogFile`,
  `$Volume`, `$AttrDef` and `.`, and records 11 and 26 `$Extend` and
  `$Reparse`.

`tests/test_samples.py` encodes these and skips when `samples/` is absent.

## Corrections to earlier notes

- `$CDH` +0x10 (64,248,784,392) is the total **logical stream** size, not
  the total compressed size. The compressed set is about 48.6 GB; the
  stream it encodes is about 64.2 GB. It sits 13,194 bytes past the end of
  `udata`; what occupies that tail is not yet known.
- The span file's header field at 0x30 (30,856) is the block sequence
  number, not a span boundary count. Span files have no separate file
  header: their first slot is simply the next `$CAN` block.
- The `$CAN` field at 0x38 is a stream offset, not a "cumulative
  compressed offset", and 0x40 is the block's stream contribution, not its
  compressed size.
- The ~1 MB of data before the NTFS boot sector in base block 1 is not a
  preamble of unknown purpose: it is the tail of `ubmap`, which starts in
  the raw metadata slot and continues into the first compressed block.
- The apparent 32-byte "cluster map" records found in block 1 are `ubmap`
  chunk records, and the "0x7434 marker" at the end of each is the magic
  at the *start* of the next one.
- Decompressed data being "not 512-byte aligned" was an artefact of
  measuring from the start of a block rather than from `udata`. Volume
  data is sector-aligned within `udata`.

## Prior art (reference only, not a shortcut around building our own reader)

Worth a literature/tool survey before committing to a byte layout, purely to
cross-validate our own reverse-engineering (e.g. confirm a guessed field
against a tool that already gets the partition table right):
- PassMark **OSFMount** (freeware, Windows) reportedly mounts `.v2i`/`.sv2i`.
- **Arsenal Image Mounter** likewise lists v2i support.
- Symantec's own format lineage: V2I is the successor container introduced
  with Symantec/Norton Ghost 12 and Symantec System Recovery, replacing the
  older `.gho`/`.ghs` format from pre-12 Ghost (a different, older binary
  format, NOT what we have here, despite "Ghost" branding on both).

None of the above are open source; treat them only as an oracle to check
guesses against (does it report the same partition sizes we compute), never
as a source to copy code or binary layouts from.

## Findings from the complete set

With all 14 files local, several things resolve that the first two files
could not show.

### Field widths: stream length is uint32, not uint64

`$CAN` header 0x40 and 0x48 are **uint32**, with a separate uint32 at 0x44.
Reading 0x40 as a uint64 works for 402,667 of the 402,668 blocks, because
0x44 is zero in all of them. In the set's **last** block it is not, and the
uint64 reading produces a stream length of 109,757,889,288,029 bytes.

Correct reading of that block:

```
0x38  uint64  64,248,745,643   stream offset
0x40  uint32          38,749   stream length (matches the decompressed size)
0x44  uint32          25,555   bytes of this block that belong to udata
0x48  uint32          14,729   deflate size
```

`64,248,745,643 + 38,749 = 64,248,784,392`, which is exactly the total the
`$CDH` block declares. Summing every block's length now reproduces that
total to the byte, which is the check that catches this bug.

### A second copy of the metadata at the end of the stream

`udata` ends at 64,248,771,198, leaving 13,194 bytes before the stream ends.
That tail is a **second copy of the container metadata**: a `$CDH` block with
its 910-entry table, two `PART` blocks, and a `$CDED` directory whose four
entries are identical to the base file's. Presumably so the directory can be
recovered from the last span if the base file is lost.

Two fields differ between the head and tail copies:

- `$CDH` +0x10 is the total stream size (64,248,784,392) in the head copy and
  the last block's stream offset (64,248,745,643) in the tail copy.
- `$CDH` +0x18 is 402,669 in the head copy and 402,668 in the tail. The set
  holds 402,668 `$CAN` blocks, so the head copy is counting the metadata slot
  as well.

### The `$CDH` 910-entry table is a seek index

Entry *i* is the stream offset of block `(i + 1) * 512 - 1`, i.e. every 512th
block. 786 of the 910 entries match a block's stream offset exactly; the
remaining 124 are padding clamped to the total stream size. 786 entries at a
512-block step covers 402,432 of the 402,668 blocks, so the last ~236 are
only reachable by scanning.

It is not needed for reading, since block headers are self-locating, and the
reader does not use it: building the full index costs one 96-byte read per
slot, 12.4 seconds for the whole 52.8 GB set, and extraction reuses it.

### Per-block checksum (header 0x58)

A uint64 holding two CRC-32s: the high 32 bits over the whole 130,976-byte
payload, the low 32 bits over the header's first 0x58 bytes.

All 402,668 blocks of the sample set verify. This doubles as a check that a
copy of a backup is intact. Exposed as `nortonghost verify`.

### `gptmd` and `ldmmd`

12 bytes each, three uint32s:

```
gptmd  1, 3, 0
ldmmd  2, 0, 0
```

The leading value looks like a record type (1 for GPT metadata, 2 for LDM).
Both are effectively empty on this MBR basic disk. A GPT or dynamic-disk
sample would be needed to learn more.


### Census of the remaining header fields (all 402,668 blocks)

Scanning every block's header and first payload byte across the complete set:

```
payload flag byte   0x74        402,668 blocks   (no other value occurs)
header 0x34         1           402,667 blocks
                    3                 1 block    (the set's final block)
header 0x44         0           402,667 blocks
                    25,555            1 block    (the final block)
header 0x0C         0x01010000  402,668 blocks
header 0x14         0x00070003  402,668 blocks
```

So **the final block identifies itself**: `0x34` is 1 for a data block and 3
for the last one, which is the block carrying the trailing metadata copy.
A reader does not have to infer it from position. `Block.kind` exposes it.

The flag byte is 0x74 on every block in the set, so this sample cannot say
what other values would mean. It is presumably a compression-method code.
## Next steps

**Done:**
1. ~~`.sv2i` parser~~ — `src/nortonghost/sv2i.py`.
2. ~~Hex-diff base vs span, locate metadata blocks~~.
3. ~~Compression algorithm~~ — raw deflate, `wbits=-15`, per block.
4. ~~Locate the NTFS boot sector~~.
5. ~~Decompressed block sizing~~ — `stream_length = inflate + literal tail`.
6. ~~The block index~~ — every `$CAN` header carries its absolute stream
   offset, so no index reconstruction is needed.
7. ~~The full container parser~~ — `src/nortonghost/v2i.py` and
   `src/nortonghost/volume.py`, driving `nortonghost info` and
   `nortonghost extract`.
8. ~~The `$CDH` 910-entry table~~ — a seek index at every 512th block.
9. ~~The bytes after `udata`~~ — a second copy of the container metadata.
10. ~~The per-block checksum~~ — two CRC-32s; `nortonghost verify`.
11. ~~`gptmd` / `ldmmd`~~ — 12-byte type records, empty on an MBR disk.

**Open:**
12. **Mount the extracted image read-only.** Our own NTFS checks pass (see
    `scripts/verify_ntfs.py`), but confirming with OSFMount or Arsenal Image
    Mounter would be an outside opinion. Needs a human: install, admin
    rights, GUI.
13. **The uint32 at `$CAN` +0x44.** Zero in every block but the set's last,
    where it is 25,555 — exactly the bytes of that block belonging to
    `udata`, the rest being the trailing metadata copy. Whether it always
    means "bytes of payload belonging to the preceding sub-stream" cannot
    be settled from one sample.
14. **The flag byte (0x74) in each payload.** Constant across every block
    examined; likely a compression-method code, which would matter for
    images written by other Ghost versions.
15. **Other images.** Everything here comes from one backup set: one NTFS
    volume, MBR, Ghost 10.0.0.1. A GPT disk, a dynamic disk, a FAT volume or
    a different Ghost version would each test a different assumption.
