from distutils.core import setup, Extension
import pybind11
import sys
import os

in_path = os.path.dirname(sys.executable)

module = Extension(
    "AMNCMHack",
    sources=[
        "hack.cpp",
    ],
    include_dirs=[],
    language="c++",
    extra_compile_args=["/std:c++17", "/utf-8", "/Zc:__cplusplus"],
    libraries=[
        "libcrypto",
        "zlib",
        "tag",
        "python310",
        "libssl",
    ],
)

setup(
    name="NCMUnlocker",
    version="0.1",
    description="NCMUnlocker, a python wrapper for Netease Cloud Music Unlocker",
    ext_modules=[module],
)
