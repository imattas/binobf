import sys

from binobf import Binobf


def main() -> int:
    tool = Binobf()
    if not tool.version:
        return 1
    data = bytearray(64)
    data[:7] = b"\x7fELF\x02\x01\x01"
    data[16:18] = (1).to_bytes(2, "little")
    data[18:20] = (62).to_bytes(2, "little")
    data[52:54] = (64).to_bytes(2, "little")
    detection = tool.detect(bytes(data), "python-fixture.o")
    return 0 if (detection.format, detection.type, detection.architecture) == (2, 3, 1) else 2


if __name__ == "__main__":
    sys.exit(main())
