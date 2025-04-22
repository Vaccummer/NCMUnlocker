from distutils.core import setup, Extension
import pybind11
import sys
import os

in_path = os.path.dirname(sys.executable)

module = Extension(
    "NCMUnlocker",
    sources=[
        "hack.cpp",
    ],
    include_dirs=[
        pybind11.get_include(),
        "E:\\Softwares\\Anaconda\\envs\\Launcher\\include",
        "C:\\Program Files (x86)\\Windows Kits\\10\\Include\\10.0.22000.0\\ucrt",
        "E:\\vcpkg\\installed\\x64-windows\\include",
        "C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\VC\\Tools\\MSVC\\14.43.34808\\atlmfc\\include",
        "C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\VC\\Tools\\MSVC\\14.43.34808\\include",
    ],
    language="c++",
    extra_compile_args=["/std:c++17", "/utf-8", "/MD"],
    # library_dirs=["E:\\vcpkg\\installed\\x64-windows\\lib", r'E:\Softwares\Anaconda\envs\Launcher\libs'],
    library_dirs=[
        "E:\\vcpkg\\installed\\x64-windows\\lib",
        r"E:\Softwares\Anaconda\envs\Launcher\libs",
    ],
    libraries=["libcrypto", "zlib", "libssl", "tag", "python310"],
)

setup(
    name="NCMUnlocker",
    version="0.1",
    description="NCMUnlocker, a python wrapper for Netease Cloud Music Unlocker",
    ext_modules=[module],
)
