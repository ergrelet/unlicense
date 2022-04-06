# Changelog

## [Unreleased]

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
