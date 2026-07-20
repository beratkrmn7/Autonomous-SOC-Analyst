import re
from dataclasses import dataclass


TCP_FLAG_ORDER = (
    "FIN",
    "SYN",
    "RST",
    "PSH",
    "ACK",
    "URG",
    "ECE",
    "CWR",
)
MAX_TCP_FLAG_INPUT_CHARS = 128

_TCP_FLAG_SET = frozenset(TCP_FLAG_ORDER)
_PF_FLAG_MAP = {
    "F": "FIN",
    "S": "SYN",
    "R": "RST",
    "P": "PSH",
    "A": "ACK",
    "U": "URG",
    "E": "ECE",
    "W": "CWR",
}
_EXPLICIT_NONE_VALUES = frozenset({"", "0", "NONE", "NULL", "-"})


@dataclass(frozen=True)
class TcpFlagNormalization:
    canonical: str | None
    tokens: tuple[str, ...]
    explicit_none: bool
    recognized: bool


def _ordered_tokens(tokens: frozenset[str]) -> tuple[str, ...]:
    return tuple(flag for flag in TCP_FLAG_ORDER if flag in tokens)


def _parse_known_tokens(value: str) -> frozenset[str] | None:
    normalized = value.strip().upper()
    if len(normalized) > MAX_TCP_FLAG_INPUT_CHARS:
        return None
    if normalized in _EXPLICIT_NONE_VALUES:
        return frozenset()

    verbose_tokens = tuple(
        token for token in re.split(r"[\s,|]+", normalized) if token
    )
    if verbose_tokens and all(token in _TCP_FLAG_SET for token in verbose_tokens):
        return frozenset(verbose_tokens)

    if normalized and all(character in _PF_FLAG_MAP for character in normalized):
        return frozenset(_PF_FLAG_MAP[character] for character in normalized)

    return None


def parse_tcp_flag_tokens(value: str | None) -> frozenset[str]:
    """Return known TCP flag tokens without guessing invalid representations."""
    if value is None:
        return frozenset()
    parsed = _parse_known_tokens(value)
    return parsed if parsed is not None else frozenset()


def canonicalize_tcp_flags(
    value: object,
    *,
    field_present: bool,
) -> TcpFlagNormalization:
    """Canonicalize compact PF or verbose flags while preserving missing semantics."""
    if not field_present:
        return TcpFlagNormalization(
            canonical=None,
            tokens=(),
            explicit_none=False,
            recognized=True,
        )

    normalized = "" if value is None else str(value).strip().upper()
    if normalized in _EXPLICIT_NONE_VALUES:
        return TcpFlagNormalization(
            canonical="NONE",
            tokens=(),
            explicit_none=True,
            recognized=True,
        )

    parsed = _parse_known_tokens(normalized)
    if parsed is None:
        return TcpFlagNormalization(
            canonical=None,
            tokens=(),
            explicit_none=False,
            recognized=False,
        )

    ordered = _ordered_tokens(parsed)
    return TcpFlagNormalization(
        canonical=",".join(ordered),
        tokens=ordered,
        explicit_none=False,
        recognized=True,
    )
