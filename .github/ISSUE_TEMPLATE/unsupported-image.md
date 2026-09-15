---
name: It will not read my backup
about: Report a .v2i image this tool cannot open, so support can be added
title: "Unsupported image: "
labels: unsupported-image
---

## What happened

Paste the command you ran and the error it printed.

```
nortonghost info "path\to\your\base.v2i"
```

## About the backup, if you know

- Which product wrote it (Norton Ghost, Symantec System Recovery, version)?
- Roughly what year?
- One file, or a base plus `_s01`, `_s02`... spans?
- Was it a full backup, or an incremental one (often `.iv2i`)?
- Was the backup password-protected or encrypted?
- Do you know what was on the disk (Windows version, one partition or several)?

## The header sample that helps most

Almost every unsupported image can be diagnosed from the first 128 KB of the
**base** file. That region holds the container's own metadata: the block
layout, the sub-stream directory and the partition table.

Windows PowerShell:

```powershell
$in  = [System.IO.File]::OpenRead("D:\path\to\base.v2i")
$buf = New-Object byte[] 131072
$in.Read($buf, 0, 131072) | Out-Null
$in.Close()
[System.IO.File]::WriteAllBytes("$env:USERPROFILE\Desktop\v2i-header.bin", $buf)
```

Linux or macOS:

```
dd if=base.v2i of=v2i-header.bin bs=131072 count=1
```

**What that file contains:** the computer name the backup was taken from, the
partition layout, the Ghost version string, and the master boot record. It
does **not** contain any of your documents, photos or other file data, because
none of that is stored in the first 128 KB.

If you would rather not share even that, say so and attach the output of
`nortonghost info` instead. It is less to go on, but it is often enough.

Please do not upload the whole `.v2i` file to an issue. It is your entire disk.
