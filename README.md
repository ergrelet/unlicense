# Unlicense [![](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)

A Python 3 tool to dynamically unpack executables protected with
WinLicense/Themida 2.x and 3.x.

Warning: This tool will execute the target executable. Make sure to use this
tool in a VM if you're unsure about what the target executable does.

Note: You need to use a 32-bit Python interpreter to dump 32-bit executables.

## Features

* Handles Themida/Winlicense 2.x and 3.x
* Handles 32-bit and 64-bit executables
* Recovers the original entry point (OEP) automatically
* Recovers the (obfuscated) import table automatically

## Known Limitations

* Original entry point resolution works only for targets using the MSVC runtime
* Doesn't automatically recover OEPs for executables with virtualized entry points
* Doesn't produce runnable dumps in most cases
* Resolving imports for 32-bit executables packed with Themida 2.x is pretty slow
* Doesn't handle DLL files

## How To

### Install

```
$ git clone https://github.com/ergrelet/unlicense.git
$ pip install unlicense/
```

### Use

```
$ unlicense --help
NAME
    unlicense - Unpack executables protected with WinLicense/Themida.

SYNOPSIS
    unlicense EXE_TO_DUMP <flags>

DESCRIPTION
    Unpack executables protected with WinLicense/Themida.

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

NOTES
    You can also use flags syntax for POSITIONAL ARGUMENTS
```
