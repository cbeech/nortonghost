"""Parser for .sv2i sidecar descriptors.

An .sv2i file is a plain-text XML "Storage Descriptor Object" (SDO) that
lists the volumes and segments of a Ghost backup set. See
docs/format-notes.md for the annotated format writeup this parser
implements.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from xml.etree import ElementTree as ET


@dataclass
class Segment:
    device_number: int
    is_logical: bool
    size: int
    offset_on_media: int


@dataclass
class Volume:
    volume_type: str
    is_hidden: bool
    is_active: bool
    image_file: str | None
    size: int
    segments: list[Segment]


def _text(el: ET.Element | None) -> str:
    return el.text if el is not None and el.text is not None else ""


def _bool(el: ET.Element | None) -> bool:
    # Observed encoding: "0" false, "-1" true (classic VARIANT_BOOL).
    return _text(el).strip() == "-1"


def _int(el: ET.Element | None) -> int:
    t = _text(el).strip()
    return int(t) if t else 0


def parse_segment(el: ET.Element) -> Segment:
    return Segment(
        device_number=_int(el.find("DeviceNumber")),
        is_logical=_bool(el.find("IsLogical")),
        size=_int(el.find("Size")),
        offset_on_media=_int(el.find("OffsetOnMedia")),
    )


def parse_volume(el: ET.Element) -> Volume:
    segments = [
        parse_segment(child)
        for child in el
        if child.tag.startswith("Segment")
    ]
    image_file = _text(el.find("ImageFile")).strip() or None
    return Volume(
        volume_type=_text(el.find("VolumeType")),
        is_hidden=_bool(el.find("IsHidden")),
        is_active=_bool(el.find("IsActive")),
        image_file=image_file,
        size=_int(el.find("Size")),
        segments=segments,
    )


def parse_sv2i(path: str | Path) -> list[Volume]:
    """Parse an .sv2i file, returning its volumes in document order."""
    root = ET.parse(path).getroot()
    return [
        parse_volume(child)
        for child in root
        if child.tag.startswith("Volume")
    ]
