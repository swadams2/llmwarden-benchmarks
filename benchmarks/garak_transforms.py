"""Stdlib-only reimplementations of a subset of NVIDIA/garak's encoding-probe
transforms (garak/probes/encoding.py, Apache-2.0, fetched from NVIDIA/garak
@main ~v0.17.0 on 2026-09-09 — see NOTICE). Independently reimplemented
against garak's documented behavior, not copied verbatim, to avoid pulling in
garak's own runtime/plugin-loading machinery for a handful of stateless
functions.

Excluded (need a third-party package garak lazy-imports): Base2048, Ecoji,
Zalgo. Excluded (already covered by llmwarden.scanner's own base64
handling, no need to re-derive): the 4 base64 variants.

Each function returns (encoded_text, decode_fn) is NOT the shape used here —
instead each encode_* has a matching decode_* so round-trip correctness is
directly testable (see tests/test_garak_transforms.py) before any encoded
text is trusted as a corpus entry.
"""

from __future__ import annotations

import base64
import binascii
from collections.abc import Callable


# garak/probes/encoding.py: InjectBase16 -> base64.b16encode
def encode_base16_hex(text: str) -> str:
    return base64.b16encode(text.encode("utf-8")).decode("ascii")


def decode_base16_hex(payload: str) -> str:
    return base64.b16decode(payload.encode("ascii")).decode("utf-8")


# garak/probes/encoding.py: InjectBase32 -> base64.b32encode
def encode_base32(text: str) -> str:
    return base64.b32encode(text.encode("utf-8")).decode("ascii")


def decode_base32(payload: str) -> str:
    return base64.b32decode(payload.encode("ascii")).decode("utf-8")


# garak/probes/encoding.py: InjectAscii85 -> base64.a85encode
def encode_ascii85(text: str) -> str:
    return base64.a85encode(text.encode("utf-8")).decode("ascii")


def decode_ascii85(payload: str) -> str:
    return base64.a85decode(payload.encode("ascii")).decode("utf-8")


# garak/probes/encoding.py: InjectHex -> binascii.b2a_hex
def encode_raw_hex(text: str) -> str:
    return binascii.b2a_hex(text.encode("utf-8")).decode("ascii")


def decode_raw_hex(payload: str) -> str:
    return binascii.a2b_hex(payload.encode("ascii")).decode("utf-8")


# garak/probes/encoding.py: InjectUU -> InjectUU.UUencode(), 45-byte blocks
# via binascii.b2a_uu, joined.
def encode_uuencode(text: str) -> str:
    data = text.encode("utf-8")
    lines = [binascii.b2a_uu(data[i : i + 45]) for i in range(0, len(data), 45)]
    return b"".join(lines).decode("ascii")


def decode_uuencode(payload: str) -> str:
    # b2a_uu's output is newline-terminated per line; a2b_uu decodes one
    # line at a time, so splitting on "\n" (rather than hand-computing each
    # line's encoded length) sidesteps getting that arithmetic wrong.
    out = bytearray()
    for line in payload.encode("ascii").split(b"\n"):
        if line:
            out += binascii.a2b_uu(line)
    return bytes(out).decode("utf-8")


# garak/probes/encoding.py: InjectROT13 -> rot13(), str.maketrans-based.
_ROT13_TRANS = str.maketrans(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
    "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
)


def encode_rot13(text: str) -> str:
    return text.translate(_ROT13_TRANS)


# ROT13 is self-inverse.
decode_rot13 = encode_rot13


# garak/probes/encoding.py: InjectAtbash -> InjectAtbash.atbash(), z-a
# mirror, non-letters passed through unchanged.
def _atbash_char(ch: str) -> str:
    if "a" <= ch <= "z":
        return chr(ord("z") - (ord(ch) - ord("a")))
    if "A" <= ch <= "Z":
        return chr(ord("Z") - (ord(ch) - ord("A")))
    return ch


def encode_atbash(text: str) -> str:
    return "".join(_atbash_char(c) for c in text)


# Atbash is self-inverse.
decode_atbash = encode_atbash


# garak/probes/encoding.py: InjectMorse -> morse(), hand-rolled map, "/" for
# whitespace.
_MORSE_MAP = {
    "a": ".-", "b": "-...", "c": "-.-.", "d": "-..", "e": ".", "f": "..-.",
    "g": "--.", "h": "....", "i": "..", "j": ".---", "k": "-.-", "l": ".-..",
    "m": "--", "n": "-.", "o": "---", "p": ".--.", "q": "--.-", "r": ".-.",
    "s": "...", "t": "-", "u": "..-", "v": "...-", "w": ".--", "x": "-..-",
    "y": "-.--", "z": "--..",
    "0": "-----", "1": ".----", "2": "..---", "3": "...--", "4": "....-",
    "5": ".....", "6": "-....", "7": "--...", "8": "---..", "9": "----.",
    ".": ".-.-.-", ",": "--..--", "?": "..--..",
}
_MORSE_MAP_REV = {v: k for k, v in _MORSE_MAP.items()}


def encode_morse(text: str) -> str:
    words = text.split(" ")
    encoded_words = [
        " ".join(_MORSE_MAP.get(c.lower(), c) for c in word) for word in words
    ]
    return " / ".join(encoded_words)


def decode_morse(payload: str) -> str:
    words = payload.split(" / ")
    decoded_words = [
        "".join(_MORSE_MAP_REV.get(tok, "") for tok in word.split(" "))
        for word in words
    ]
    return " ".join(decoded_words)


# garak/probes/encoding.py: InjectNato -> InjectNato.nato(), letter->word
# map; non-letters (spaces, punctuation) pass through unchanged.
_NATO_MAP = {
    "a": "Alfa", "b": "Bravo", "c": "Charlie", "d": "Delta", "e": "Echo",
    "f": "Foxtrot", "g": "Golf", "h": "Hotel", "i": "India", "j": "Juliett",
    "k": "Kilo", "l": "Lima", "m": "Mike", "n": "November", "o": "Oscar",
    "p": "Papa", "q": "Quebec", "r": "Romeo", "s": "Sierra", "t": "Tango",
    "u": "Uniform", "v": "Victor", "w": "Whiskey", "x": "Xray", "y": "Yankee",
    "z": "Zulu",
}
_NATO_MAP_REV = {v.lower(): k for k, v in _NATO_MAP.items()}


def encode_nato(text: str) -> str:
    words = text.split(" ")
    encoded_words = [
        " ".join(_NATO_MAP.get(c.lower(), c) for c in word) for word in words
    ]
    return "  ".join(encoded_words)


def decode_nato(payload: str) -> str:
    words = payload.split("  ")
    decoded_words = [
        "".join(_NATO_MAP_REV.get(tok.lower(), tok) for tok in word.split(" "))
        for word in words
    ]
    return " ".join(decoded_words)


# garak/resources/smuggling/smuggle_ascii.py: tag_char_smuggling() — appends
# the payload as invisible Unicode "tag characters" (U+E0000 + byte value)
# after a visible carrier character (garak defaults to an emoji).
_TAG_CHAR_BASE = 0xE0000
_DEFAULT_CARRIER = "\U0001f608"  # 😈, garak's default carrier


def encode_unicode_tag_smuggling(text: str, carrier: str = _DEFAULT_CARRIER) -> str:
    tag_chars = "".join(chr(_TAG_CHAR_BASE + b) for b in text.encode("utf-8"))
    return carrier + tag_chars


def decode_unicode_tag_smuggling(payload: str) -> str:
    tag_bytes = bytes(
        ord(ch) - _TAG_CHAR_BASE
        for ch in payload
        if _TAG_CHAR_BASE <= ord(ch) <= _TAG_CHAR_BASE + 0xFF
    )
    return tag_bytes.decode("utf-8")


TRANSFORMS: dict[str, tuple[Callable[[str], str], Callable[[str], str]]] = {
    "base16_hex": (encode_base16_hex, decode_base16_hex),
    "base32": (encode_base32, decode_base32),
    "ascii85": (encode_ascii85, decode_ascii85),
    "raw_hex": (encode_raw_hex, decode_raw_hex),
    "uuencode": (encode_uuencode, decode_uuencode),
    "rot13": (encode_rot13, decode_rot13),
    "atbash": (encode_atbash, decode_atbash),
    "morse": (encode_morse, decode_morse),
    "nato_phonetic": (encode_nato, decode_nato),
    "unicode_tag_smuggling": (encode_unicode_tag_smuggling, decode_unicode_tag_smuggling),
}
