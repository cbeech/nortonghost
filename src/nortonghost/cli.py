"""Command-line entry point for nortonghost."""

from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path

from rich.console import Console
from rich.progress import (
    BarColumn,
    DownloadColumn,
    Progress,
    TimeRemainingColumn,
    TransferSpeedColumn,
)
from rich.table import Table

from fnmatch import fnmatch

from .ntfs import NtfsError, NtfsVolume
from .sv2i import parse_sv2i
from .v2i import MissingSpanError, V2iError, V2iImage
from .volume import Volume

console = Console()


def _info_sv2i(path: str) -> int:
    volumes = parse_sv2i(path)
    table = Table(title=path)
    table.add_column("Volume")
    table.add_column("Type")
    table.add_column("Size (bytes)", justify="right")
    table.add_column("Image file")
    table.add_column("Segments", justify="right")
    for i, v in enumerate(volumes, start=1):
        table.add_row(
            str(i),
            v.volume_type,
            f"{v.size:,}",
            v.image_file or "-",
            str(len(v.segments)),
        )
    console.print(table)
    return 0


def _info_v2i(path: str) -> int:
    with V2iImage(path) as image:
        info = image.set_info
        blocks = image.index_blocks()

        files = Table(title=f"{Path(path).name} — container")
        files.add_column("Field")
        files.add_column("Value", justify="right")
        files.add_row("Files present", f"{len(image.files)} of {info.file_count}")
        files.add_row("Blocks present", f"{len(blocks):,} of {info.total_blocks:,}")
        files.add_row("Stream available", f"{image.stream_size:,} bytes")
        files.add_row("Stream total", f"{info.total_stream_size:,} bytes")
        console.print(files)

        streams = Table(title="Sub-streams")
        streams.add_column("Name")
        streams.add_column("Offset", justify="right")
        streams.add_column("Length", justify="right")
        for entry in image.streams:
            streams.add_row(entry.name, f"{entry.offset:,}", f"{entry.length:,}")
        console.print(streams)

        try:
            volume = Volume(image)
        except V2iError as exc:
            console.print(f"[yellow]Volume map unavailable:[/yellow] {exc}")
            return 0

        available = max(0, image.stream_size - volume.data_stream.offset)
        readable = volume.readable_size(available)
        vol = Table(title="Volume")
        vol.add_column("Field")
        vol.add_column("Value", justify="right")
        vol.add_row("Size", f"{volume.size:,} bytes")
        vol.add_row("Sectors", f"{volume.total_sectors:,}")
        vol.add_row(
            "Stored",
            f"{volume.stored_size:,} bytes "
            f"({100 * volume.stored_size / volume.size:.1f}%)",
        )
        vol.add_row("Stored extents", f"{len(volume.extents):,}")
        vol.add_row(
            "Readable now",
            f"{readable:,} bytes ({100 * readable / volume.size:.1f}%)",
        )
        console.print(vol)
    return 0


def cmd_info(args: argparse.Namespace) -> int:
    path = args.path
    suffix = Path(path).suffix.lower()
    if suffix == ".sv2i":
        return _info_sv2i(path)
    if suffix == ".v2i":
        return _info_v2i(path)
    console.print(f"[red]Unrecognised extension[/red] {suffix!r}: expected .v2i or .sv2i")
    return 1


def cmd_extract(args: argparse.Namespace) -> int:
    out = Path(args.output)
    with V2iImage(args.path) as image:
        volume = Volume(image)
        available = max(0, image.stream_size - volume.data_stream.offset)
        readable = volume.readable_size(available)

        offset = args.offset
        length = args.length if args.length is not None else volume.size - offset
        end = offset + length

        if len(image.files) < image.set_info.file_count:
            console.print(
                f"[yellow]{len(image.files)} of {image.set_info.file_count} "
                f"files present[/yellow]: readable through volume offset "
                f"{readable:,}"
            )
        if end > readable:
            console.print(
                f"[red]Requested range ends at {end:,} but only {readable:,} "
                f"bytes are readable[/red]; pass --length to extract a prefix."
            )
            return 1

        with open(out, "wb") as fh, Progress(
            "[progress.description]{task.description}",
            BarColumn(),
            DownloadColumn(),
            TransferSpeedColumn(),
            TimeRemainingColumn(),
            console=console,
        ) as progress:
            task = progress.add_task(f"Extracting to {out.name}", total=length)
            try:
                stored = volume.write_image(
                    fh,
                    offset,
                    length,
                    progress=lambda n: progress.update(task, advance=n),
                )
            except MissingSpanError as exc:
                console.print(f"[red]Stopped:[/red] {exc}")
                return 1

    console.print(
        f"Wrote [green]{length:,}[/green] bytes to {out} "
        f"({stored:,} transferred, {length - stored:,} unallocated)"
    )
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    with V2iImage(args.path) as image:
        blocks = image.index_blocks()
        failures: list[int] = []
        with Progress(
            "[progress.description]{task.description}",
            BarColumn(),
            "{task.completed:,}/{task.total:,}",
            TimeRemainingColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Verifying block checksums", total=len(blocks))
            for block, good in image.verify():
                if not good:
                    failures.append(block.sequence)
                progress.advance(task)

        if failures:
            console.print(
                f"[red]{len(failures):,} of {len(blocks):,} blocks failed[/red]: "
                f"{failures[:10]}{' ...' if len(failures) > 10 else ''}"
            )
            return 1
        console.print(f"[green]All {len(blocks):,} blocks verified[/green]")
        if len(image.files) < image.set_info.file_count:
            console.print(
                f"{len(image.files)} of {image.set_info.file_count} files present"
            )
    return 0


def _open_filesystem(path: str):
    """Open the NTFS volume inside a .v2i set, or a raw .img."""
    if Path(path).suffix.lower() == ".v2i":
        image = V2iImage(path)
        return image, NtfsVolume(Volume(image))
    return None, NtfsVolume(_RawImage(path))


class _RawImage:
    def __init__(self, path: str) -> None:
        self.fh = open(path, "rb")

    def read(self, offset: int, length: int) -> bytes:
        self.fh.seek(offset)
        return self.fh.read(length)


# Names that address a device rather than a file on Windows. Writing to one
# of these does not create a file, it talks to the console or a serial port.
_RESERVED_NAMES = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}


def _safe_parts(path: str) -> list[str]:
    """Turn a path from inside the image into safe destination components.

    Names in an image are not trustworthy: a corrupt or malicious one can hold
    ``..``, a drive letter, a device name or control characters. Anything that
    could escape the destination directory or address a device is neutralised.
    """
    parts = []
    for part in path.replace("\\", "/").split("/"):
        if part in ("", ".", ".."):
            continue
        cleaned = "".join(
            "_" if c in '<>:"|?*' or ord(c) < 0x20 else c for c in part
        )
        # Windows silently strips trailing dots and spaces, which makes such a
        # file awkward to open or delete afterwards.
        cleaned = cleaned.rstrip(". ") or "_"
        stem = cleaned.split(".", 1)[0].upper()
        if stem in _RESERVED_NAMES:
            cleaned = "_" + cleaned
        parts.append(cleaned)
    return parts


def cmd_ls(args: argparse.Namespace) -> int:
    image, fs = _open_filesystem(args.path)
    try:
        entry = fs.resolve(args.dir)
        if not entry.is_directory:
            console.print(f"{args.dir} is a file ({entry.size:,} bytes)")
            return 0
        rows = sorted(
            fs.listdir(entry.record_number), key=lambda e: (not e.is_directory, e.name.lower())
        )
        table = Table(title=f"{args.dir or '/'}  ({len(rows)} entries)")
        table.add_column("")
        table.add_column("Size", justify="right")
        table.add_column("Name")
        for row in rows:
            if row.name == "." or (row.name.startswith("$") and not args.all):
                continue
            table.add_row(
                "d" if row.is_directory else "-",
                "" if row.is_directory else f"{row.size:,}",
                row.name,
            )
        console.print(table)
    except NtfsError as exc:
        console.print(f"[red]{exc}[/red]")
        return 1
    finally:
        if image is not None:
            image.close()
    return 0


def cmd_find(args: argparse.Namespace) -> int:
    image, fs = _open_filesystem(args.path)
    pattern = args.pattern.lower()
    matches = 0
    try:
        start = fs.resolve(args.dir)
        for path, entry in fs.walk(start.record_number, args.dir.rstrip("/")):
            if fnmatch(entry.name.lower(), pattern):
                matches += 1
                kind = "d" if entry.is_directory else f"{entry.size:,}"
                console.print(f"{kind:>14}  {path}")
                if matches >= args.limit:
                    console.print(f"[yellow]stopped at {args.limit} matches[/yellow]")
                    break
    except NtfsError as exc:
        console.print(f"[red]{exc}[/red]")
        return 1
    finally:
        if image is not None:
            image.close()
    if not matches:
        console.print("no matches")
    return 0


def cmd_cp(args: argparse.Namespace) -> int:
    image, fs = _open_filesystem(args.path)
    destination = Path(args.destination)
    copied = failed = 0
    total = 0
    try:
        entry = fs.resolve(args.source)

        prefix = args.source.rstrip("/")
        if entry.is_directory:
            # paths come back absolute; store them relative to the source
            # directory, so `cp ... /a/b/c dest` fills dest with c's contents
            jobs = [
                (path[len(prefix) :], path, found)
                for path, found in fs.walk(entry.record_number, prefix)
                if not found.is_directory
            ]
        else:
            jobs = [(args.source.rsplit("/", 1)[-1], args.source, entry)]

        for relative, path, found in jobs:
            if len(jobs) == 1 and not entry.is_directory:
                # a lone file goes to the exact destination given, unless
                # that destination is an existing directory
                target = (
                    destination / _safe_parts(relative)[-1]
                    if destination.is_dir()
                    else destination
                )
            else:
                target = destination.joinpath(*_safe_parts(relative))
            target.parent.mkdir(parents=True, exist_ok=True)
            try:
                with open(target, "wb") as fh:
                    for chunk in fs.iter_file(found.record_number):
                        fh.write(chunk)
                        total += len(chunk)
                copied += 1
                if not args.quiet:
                    console.print(f"  {found.size:>12,}  {path}")
            except NtfsError as exc:
                failed += 1
                console.print(f"[yellow]  skipped {path}: {exc}[/yellow]")
    except NtfsError as exc:
        console.print(f"[red]{exc}[/red]")
        return 1
    finally:
        if image is not None:
            image.close()

    console.print(
        f"Recovered [green]{copied:,}[/green] file(s), {total:,} bytes"
        + (f", [yellow]{failed} skipped[/yellow]" if failed else "")
    )
    return 1 if failed and not copied else 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="nortonghost",
        description=(
            "Read and recover files from Symantec/Norton Ghost .v2i disk "
            "images. Point commands at the base .v2i file; spanned parts "
            "beside it are found automatically. Not affiliated with Symantec "
            "or Norton."
        ),
        epilog=(
            'Typical use: nortonghost find backup.v2i "*.jpg", then '
            'nortonghost cp backup.v2i "/path/in/image" "C:\\Recovered"'
        ),
    )
    sub = p.add_subparsers(dest="command", required=True)

    info = sub.add_parser("info", help="Inspect a .v2i image or .sv2i descriptor")
    info.add_argument("path", help="Path to a .v2i or .sv2i file")
    info.set_defaults(func=cmd_info)

    extract = sub.add_parser(
        "extract", help="Write the volume image from a .v2i set to a raw file"
    )
    extract.add_argument("path", help="Path to the base .v2i file")
    extract.add_argument("-o", "--output", required=True, help="Output .img path")
    extract.add_argument(
        "--offset", type=int, default=0, help="Volume byte offset to start at"
    )
    extract.add_argument(
        "--length", type=int, default=None, help="Bytes to write (default: to the end)"
    )
    extract.set_defaults(func=cmd_extract)

    verify = sub.add_parser(
        "verify", help="Check every block's stored checksum against its bytes"
    )
    verify.add_argument("path", help="Path to the base .v2i file")
    verify.set_defaults(func=cmd_verify)

    ls = sub.add_parser("ls", help="List a directory inside the image")
    ls.add_argument("path", help="Path to the base .v2i file (or a raw .img)")
    ls.add_argument("dir", nargs="?", default="/", help="Directory inside the image")
    ls.add_argument("-a", "--all", action="store_true", help="Include $ metadata files")
    ls.set_defaults(func=cmd_ls)

    find = sub.add_parser("find", help="Search the image for files by name")
    find.add_argument("path", help="Path to the base .v2i file (or a raw .img)")
    find.add_argument("pattern", help="Glob pattern, e.g. '*.jpg'")
    find.add_argument("--dir", default="/", help="Directory to search under")
    find.add_argument("--limit", type=int, default=500, help="Stop after N matches")
    find.set_defaults(func=cmd_find)

    cp = sub.add_parser("cp", help="Recover a file or directory out of the image")
    cp.add_argument("path", help="Path to the base .v2i file (or a raw .img)")
    cp.add_argument("source", help="File or directory inside the image")
    cp.add_argument("destination", help="Where to write it on this machine")
    cp.add_argument("-q", "--quiet", action="store_true", help="Do not list each file")
    cp.set_defaults(func=cmd_cp)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (V2iError, NtfsError) as exc:
        console.print(f"[red]Error:[/red] {exc}")
        return 1
    except struct.error as exc:
        # A field ran past the end of a structure, which means the image is
        # damaged or is a variant this reader does not know.
        console.print(
            f"[red]This image could not be parsed:[/red] {exc}\n"
            "If the file is not damaged, this is a variant the reader does not "
            "handle yet. Please report it: "
            "https://github.com/cbeech/nortonghost/issues"
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())
