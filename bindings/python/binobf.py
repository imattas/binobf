"""Small ctypes binding for the stable binobf C ABI."""

from __future__ import annotations

import ctypes
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Union


class _Error(ctypes.Structure):
    _fields_ = [
        ("struct_size", ctypes.c_uint32),
        ("code", ctypes.c_char_p),
        ("code_capacity", ctypes.c_size_t),
        ("message", ctypes.c_char_p),
        ("message_capacity", ctypes.c_size_t),
    ]


class _Detection(ctypes.Structure):
    _fields_ = [
        ("struct_size", ctypes.c_uint32),
        ("format", ctypes.c_uint32),
        ("type", ctypes.c_uint32),
        ("architecture", ctypes.c_uint32),
        ("entry_point", ctypes.c_uint64),
    ]


@dataclass(frozen=True)
class Detection:
    format: int
    type: int
    architecture: int
    entry_point: int


class BinobfError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


def _default_library() -> Path:
    configured = os.environ.get("BINOBF_C_LIBRARY")
    if configured:
        return Path(configured)
    names = ("binobf_c.dll", "libbinobf_c.dylib", "libbinobf_c.so")
    for root in (Path.cwd(), Path(__file__).resolve().parent):
        for name in names:
            candidate = root / name
            if candidate.exists():
                return candidate
    raise FileNotFoundError("could not locate binobf_c shared library")


class Binobf:
    def __init__(self, library: Union[os.PathLike[str], str, None] = None) -> None:
        self._library = ctypes.CDLL(
            os.fspath(library) if library is not None else os.fspath(_default_library())
        )
        self._library.binobf_version.restype = ctypes.c_char_p
        self._library.binobf_detect.argtypes = [
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.c_char_p,
            ctypes.POINTER(_Detection),
            ctypes.POINTER(_Error),
        ]
        self._library.binobf_detect.restype = ctypes.c_int

    @property
    def version(self) -> str:
        return self._library.binobf_version().decode("utf-8")

    def detect(self, data: bytes, source_name: str = "") -> Detection:
        buffer = ctypes.create_string_buffer(data)
        code = ctypes.create_string_buffer(128)
        message = ctypes.create_string_buffer(512)
        error = _Error(
            ctypes.sizeof(_Error), ctypes.cast(code, ctypes.c_char_p), len(code),
            ctypes.cast(message, ctypes.c_char_p), len(message)
        )
        detection = _Detection(ctypes.sizeof(_Detection), 0, 0, 0, 0)
        status = self._library.binobf_detect(
            buffer, len(data), source_name.encode("utf-8"),
            ctypes.byref(detection), ctypes.byref(error)
        )
        if status != 0:
            raise BinobfError(code.value.decode("utf-8"), message.value.decode("utf-8"))
        return Detection(
            detection.format, detection.type, detection.architecture, detection.entry_point
        )
