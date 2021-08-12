# ShittyUxTheme

## About

A file patching UxTheme patcher. If you don't intentionally seek this, I recommend using [SecureUxTheme](https://github.com/namazso/SecureUxTheme) instead.

## Features

* Patches system files
* Probably breaks your install on Windows update
* Grabs patch sites from Microsoft symbols
* Compatible Windows XP -> Windows 11 (and probably future versions)
* Does patches same way as UltraUxThemePatcher
* x86, x64, ARM64 supported
* Easy to embed into silent installers

## Usage

1. Compile for your architecture
2. Put `dbghelp.dll`, `symsrv.dll`, `symsrv.yes` files next to the output binary
3. Run as Administrator

## Donations

This software is provided completely free of charge to you, however I spent time and effort developing it. If you like this software, please consider making a donation:

* Bitcoin: 1N6UzYgzn3sLV33hB2iS3FvYLzD1G4CuS2
* Monero: 83sJ6GoeKf1U47vD9Tk6y2MEKJKxPJkECG3Ms7yzVGeiBYg2uYhBAUAZKNDH8VnAPGhwhZeqBnofDPgw9PiVtTgk95k53Rd

## License Statement

	MIT License

	Copyright (c) 2021 namazso <admin@namazso.eu>

	Permission is hereby granted, free of charge, to any person obtaining a copy
	of this software and associated documentation files (the "Software"), to deal
	in the Software without restriction, including without limitation the rights
	to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
	copies of the Software, and to permit persons to whom the Software is
	furnished to do so, subject to the following conditions:

	The above copyright notice and this permission notice shall be included in all
	copies or substantial portions of the Software.

	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
	IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
	AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
	OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
	SOFTWARE.