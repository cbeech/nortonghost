# nortonghost

**Recover your files from old Norton Ghost `.v2i` backups.**

If you have `.v2i` files sitting on a drive somewhere and nothing that will
open them any more, this reads them and gets your files back out.

> **Not affiliated with, endorsed by, or connected to Symantec, NortonLifeLock,
> Gen Digital, or Norton in any way.** "Norton", "Ghost" and "Symantec" are
> trademarks of their respective owners and are used here only to describe
> which file format this software reads. This is an independent, clean-room
> implementation written from scratch, for people who created backups with
> Norton Ghost and would now like their files back.

## The problem this solves

Norton Ghost and Symantec System Recovery were discontinued. Their `.v2i`
images are a proprietary, undocumented container, and if you no longer have a
working installation, the data is effectively locked up. Backups made to keep
files safe became the reason those files are unreachable.

This reads the format directly. No Symantec software, no license keys, no
mounting drivers, and no need to restore a whole disk just to get one folder.

## Get your files back

Install Python 3.11 or newer, then:

```
pip install git+https://github.com/cbeech/nortonghost
```

Point every command at the **base** `.v2i` file. The spanned parts
(`_s01.v2i`, `_s02.v2i` and so on) are found automatically as long as they sit
in the same folder.

**See what is in the backup:**

```
nortonghost ls  "D:\Backups\C_Drive001.v2i"
nortonghost ls  "D:\Backups\C_Drive001.v2i"  "/Documents and Settings"
```

**Find files by name, anywhere on the volume:**

```
nortonghost find "D:\Backups\C_Drive001.v2i" "*.jpg"
nortonghost find "D:\Backups\C_Drive001.v2i" "*.doc" --dir "/Documents and Settings"
```

**Recover a file or a whole folder:**

```
nortonghost cp "D:\Backups\C_Drive001.v2i" "/Documents and Settings/You/My Documents" "C:\Recovered"
```

That is the whole workflow for most people. It reads only what it needs, so
recovering one folder does not require space for the entire disk image.

## If you would rather have a disk image

```
nortonghost info    "D:\Backups\C_Drive001.v2i"   # geometry, how much is readable
nortonghost verify  "D:\Backups\C_Drive001.v2i"   # check every block's checksum
nortonghost extract "D:\Backups\C_Drive001.v2i" -o c_drive.img
```

`extract` writes a raw volume image you can mount read-only (OSFMount,
Arsenal Image Mounter, `mount -o loop` on Linux) or open with 7-Zip. It only
transfers sectors that were actually stored, and takes `--offset` / `--length`
for a partial range.

Note that this produces a **volume** image, starting at the boot sector. It is
not a whole-disk image and has no partition table.

To check an extracted image against NTFS's own structures, without trusting
this tool's word for it:

```
python scripts/verify_ntfs.py --raw c_drive.img --ubmap "D:\Backups\C_Drive001.v2i"
```

It walks every MFT record, compares `$MFTMirr` against `$MFT`, and checks that
every cluster NTFS marks allocated is present in the image, naming the file
that owns any that are not.

## What works, and what is not yet proven

Everything here is verified against a real 2008 backup: a 100 GB NTFS volume
on an MBR disk, spanned across 14 files, written by Norton Ghost 10.0.0.1.

Verified on that set:

- All 402,668 container blocks pass their own stored checksums.
- Every allocated cluster is present. Of the 16,340,347 clusters NTFS marks in
  use, the only ones missing are `pagefile.sys` and `hiberfil.sys`, which Ghost
  skips by design.
- All 176,160 MFT records read cleanly, and `$MFTMirr` matches `$MFT`.
- Compressed and heavily fragmented files come back byte-exact, including a
  2.1 MB kernel binary stored compressed across 68 fragments.

**Not yet tested, because no sample exists:** GPT disks, dynamic disks, FAT
volumes, encrypted or password-protected images, incremental `.iv2i` backups,
and other Ghost versions. The reader refuses loudly rather than guessing when
it meets something it does not recognise.

**If it fails on your backup, please open an issue.** That is how support for
other variants gets added. Include the output of `nortonghost info`, and see
the issue template for the small header sample that helps most. It contains
your machine name and partition layout, but none of your files.

## The format

`docs/format-notes.md` documents the container at byte level: the logical
stream, the block headers, the compression, the sub-stream directory, and the
sparse map that says which sectors were stored. It is written so someone can
build another reader without repeating the reverse engineering, and it records
the wrong turns as well as the answers.

Nothing here was taken from any existing tool. The format was worked out from
sample data, and every claim in those notes is backed by a check against real
NTFS structures rather than a plausible-looking hex dump.

## Development

```
git clone https://github.com/cbeech/nortonghost
cd nortonghost
python -m venv .venv
.venv\Scripts\activate          # source .venv/bin/activate on Linux/macOS
pip install -e ".[dev]"
pytest
```

The test suite needs no sample data: it builds a synthetic container that
exercises the same structures. Tests that need a real image skip themselves
unless a `samples/` directory is present.

## License

MIT. See `LICENSE`.
