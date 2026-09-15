from pathlib import Path

from nortonghost.sv2i import parse_sv2i

FIXTURE = Path(__file__).parent / "fixtures" / "sample.sv2i"


def test_parses_three_volumes():
    volumes = parse_sv2i(FIXTURE)
    assert len(volumes) == 3


def test_volume2_has_the_image_file():
    volumes = parse_sv2i(FIXTURE)
    imaged = [v for v in volumes if v.image_file]
    assert len(imaged) == 1
    v = imaged[0]
    assert v.image_file == r"D:\Norton Ghost Backups\C_Drive001.v2i"
    assert v.size == 100002951168
    assert v.is_active is True


def test_volume1_is_not_hidden_and_not_active():
    volumes = parse_sv2i(FIXTURE)
    v1 = volumes[0]
    assert v1.is_hidden is False
    assert v1.is_active is False
    assert v1.image_file is None


def test_segment_offset_on_media():
    volumes = parse_sv2i(FIXTURE)
    v1 = volumes[0]
    assert len(v1.segments) == 1
    seg = v1.segments[0]
    assert seg.offset_on_media == 63
    assert seg.size == 7501423104


def test_volume3_segment_is_logical():
    volumes = parse_sv2i(FIXTURE)
    v3 = volumes[2]
    assert v3.segments[0].is_logical is True


def test_names_from_an_image_cannot_escape_the_destination():
    """Paths inside an image are untrusted input to cp."""
    from nortonghost.cli import _safe_parts

    assert _safe_parts("../../../../Windows/evil.dll") == ["Windows", "evil.dll"]
    assert _safe_parts(r"C:\Windows\evil.dll") == ["C_", "Windows", "evil.dll"]
    assert _safe_parts(r"\server\share\x") == ["server", "share", "x"]
    assert _safe_parts("a/../../b") == ["a", "b"]
    # device names, trailing dots/spaces and control characters are defused
    assert _safe_parts("CON") == ["_CON"]
    assert _safe_parts("com1.txt") == ["_com1.txt"]
    assert _safe_parts("trailing. ") == ["trailing"]
    assert _safe_parts("\x01ctl") == ["_ctl"]
    assert _safe_parts("normal.txt") == ["normal.txt"]
