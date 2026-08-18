# Python binding

This binding uses the stable `binobf_c` shared library and does not mirror the
C++ ownership model. Build and install binobf, then point the wrapper at the
installed shared library:

```python
from binobf import Binobf

tool = Binobf(r"build/install/bin/binobf_c.dll")  # `.so` on Linux
print(tool.version)
print(tool.detect(open("input.o", "rb").read(), "input.o"))
```

The numeric detection fields are the values documented by `c_api.h`; callers
should handle unknown future enum values conservatively.

The wrapper can also be installed locally with `python -m pip install .` from
this directory. The native `binobf_c` shared library remains a separate
installable dependency and can be selected with `BINOBF_C_LIBRARY`.
