# Changelog

## [Unreleased]
### Fixed
- Fix a potential deadlock when dumping DLLs
- Improve version detection for Themida/Winlicense 3.x
- Improve .text section detection for Themida/Winlicense 3.x
- Fix `lief.not_found` exception happening when dumping certain MinGW EXEs
- Fix TLS callback detection for some 32-bit EXEs
- Handle wrapped imports from Themida/Winlicense 3.1.4.0
- Improve IAT search algorithm for Themida/Winlicense 3.x
- Allow dumping EXEs that require admin privilege at medium integrity level

### Changed
- Silence some misleading "error" logs that were emitted

## [0.3.0] - 2022-07-22
### Fixed
- Fix a couple of bugs with the IAT search and resolution for Themida/Winlicense 3.x
- Fix potentially invalid IAT truncations for Themida/WinLicense 3.x
- OEP detection now works in a runtime-agnostic manner (and handles virtualized entry points and Delphi executables)
- TLS callbacks are now properly detected and skipped

## [0.2.0] - 2022-05-31
### Added
- Handle unpacking of 32-bit and 64-bit DLLs
- Handle unpacking of 32-bit and 64-bit .NET assembly PEs (EXE only)
- OEP detection times out after 10 seconds by default. The duration can be
  changed through the CLI.

### Fixed
- Improve .text section detection for Themida/Winlicense 2.x

## [0.1.1] - 2022-04-06
### Fixed
- Fix IAT patching in some cases for Themida/Winlicense 3.x
- Fix inability to read remote chunks of memory bigger than 128 MiB
- Improve version detection to handle packed Delphi executables
- Improve IAT search algorithm for Themida/Winlicense 3.x
- Gracefully handle bitness mismatch between interpreter and target PEs
- Fix IAT truncation issue for IATs bigger than 4 KiB

## [0.1.0] - 2021-11-13

Initial release with support for Themida/Winlicense 2.x and 3.x.  
This release has been tested on Themida 2.4 and 3.0.
