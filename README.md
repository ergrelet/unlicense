# Unlicense [![](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/) ![CI status x64](https://github.com/ergrelet/unlicense/actions/workflows/py310-win64-ci.yml/badge.svg?branch=main) ![CI status x86](https://github.com/ergrelet/unlicense/actions/workflows/py310-win32-ci.yml/badge.svg?branch=main)

A Python 3 tool to dynamically unpack executables protected with
Themida/WinLicense 2.x and 3.x.

Warning: This tool will execute the target executable. Make sure to use this
tool in a VM if you're unsure about what the target executable does.

Note: You need to use a 32-bit Python interpreter to dump 32-bit executables.

## Features

* Handles Themida/Winlicense 2.x and 3.x
* Handles 32-bit and 64-bit PEs (EXEs and DLLs)
* Handles 32-bit and 64-bit .NET assemblies (EXEs only)
* Recovers the original entry point (OEP) automatically
* Recovers the (obfuscated) import table automatically

## Known Limitations

* Doesn't handle .NET assembly DLLs
* Doesn't produce runnable dumps in most cases
* Resolving imports for 32-bit executables packed with Themida 2.x is pretty slow

## How To

### Download

You can either download the PyInstaller-generated executables from the "Releases"
section or fetch the project with `git` and install it with `pip`:
```
$ pip install git+https://github.com/ergrelet/unlicense.git
```

### Use

If you don't want to deal the command-line interface (CLI) you can simply
drag-and-drop the target binary on the appropriate (32-bit or 64-bit) `unlicense`
executable (which is available in the "Releases" section).

Otherwise here's what the CLI looks like:
```
$ unlicense --help
NAME
    unlicense - Unpack executables protected with Themida/WinLicense 2.x and 3.x

SYNOPSIS
    unlicense EXE_TO_DUMP <flags>

DESCRIPTION
    Unpack executables protected with Themida/WinLicense 2.x and 3.x

POSITIONAL ARGUMENTS
    EXE_TO_DUMP
        Type: str

FLAGS
    --verbose=VERBOSE
        Type: bool
        Default: False
    --pause_on_oep=PAUSE_ON_OEP
        Type: bool
        Default: False
    --force_oep=FORCE_OEP
        Type: Optional[typing.Optional[int]]
        Default: None
    --target_version=TARGET_VERSION
        Type: Optional[typing.Optional[int]]
        Default: None
    --timeout=TIMEOUT
        Type: int
        Default: 10

NOTES
    You can also use flags syntax for POSITIONAL ARGUMENTS
```
