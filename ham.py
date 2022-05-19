#!/usr/bin/env python3

import re
from argparse import ArgumentParser
from struct import pack, unpack_from

HEX_EXP = re.compile(r"^[a-f\d]+$", re.IGNORECASE)

# https://github.com/arngll/arnce-spec/blob/main/n6drc-arnce.md#base-40-character-set
BASE40_TAB = "\x00ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/-^"

# https://github.com/arngll/arnce-spec/blob/main/n6drc-arnce.md#escapingunescaping-optional
ESCAPE_TAB = {
	# indicator suffix
	"/RPTR-": "^R",  # Repeater/Digipeater Indicator
	"/PORT-": "^P",  # Portable Indicator
	"/MOBI-": "^M",  # Mobile Indicator
	"/MARI-": "^S",  # Maritime Mobile Indicator
	"/AIRM-": "^A",  # Aeronautical Mobile Indicator
	"/CTST-": "^C",  # Contest Indicator
	"/RPTR": "^R",
	"/PORT": "^P",
	"/MOBI": "^M",
	"/MARI": "^S",
	"/AIRM": "^A",
	"/CTST": "^C",
	# characters
	":": "^/",
	"_": "^-",
	".": "^D",
	"|": "^V",
}

# https://github.com/arngll/arnce-spec/blob/main/n6drc-arnce.md#escapingunescaping-optional
UNESCAPE_TAB = {
	# characters
	"^/": ":",
	"^-": "_",
	"^D": ".",
	"^V": "|",
	# indicator suffix
	"^R": "/RPTR",  # Repeater/Digipeater Indicator
	"^P": "/PORT",  # Portable Indicator
	"^M": "/MOBI",  # Mobile Indicator
	"^S": "/MARI",  # Maritime Mobile Indicator
	"^A": "/AIRM",  # Aeronautical Mobile Indicator
	"^C": "/CTST"   # Contest Indicator
}

is_hex = lambda s: len(s) % 2 == 0 and HEX_EXP.fullmatch(s)

def escape(callsign: str) -> str:
	# https://github.com/arngll/arnce-spec/blob/main/n6drc-arnce.md#escapingunescaping-optional
	for (f, r) in ESCAPE_TAB.items():
		loc = callsign.find(f)
		if loc > -1:
			callsign = f"{callsign[:loc]}{r}{callsign[loc + len(f):]}"
	return callsign

def unescape(callsign: str) -> str:
	# https://github.com/arngll/arnce-spec/blob/main/n6drc-arnce.md#escapingunescaping-optional
	for (f, r) in UNESCAPE_TAB.items():
		loc = callsign.find(f)
		if loc > -1:
			last_chars = callsign[loc + len(f):]
			if len(last_chars) > 0:
				callsign = f"{callsign[:loc]}{r}-{last_chars}"
			else:
				callsign = f"{callsign[:loc]}{r}{last_chars}"
	return callsign

def _16_bit_encode(callsign: str) -> bytes:
	# https://github.com/arngll/arnce-spec/blob/main/n6drc-arnce.md#16-bit-chunk-encoding-chunk-encoding
	dst = b""
	for i in range(0, len(callsign), 3):
		chars_left = len(callsign) - i
		if chars_left >= 3:
			a = BASE40_TAB.index(callsign[i]) * 1600
			b = BASE40_TAB.index(callsign[i + 1]) * 40
			c = BASE40_TAB.index(callsign[i + 2])
		elif chars_left == 2:
			a = BASE40_TAB.index(callsign[i]) * 1600
			b = BASE40_TAB.index(callsign[i + 1]) * 40
			c = 0
		elif chars_left == 1:
			a = BASE40_TAB.index(callsign[i]) * 1600
			b = 0
			c = 0
		else:
			a = b = c = 0
		dst += pack(">H", a + b + c)
	return dst

def _16_bit_decode(callsign: str | bytes) -> str:
	# https://github.com/arngll/arnce-spec/blob/main/n6drc-arnce.md#16-bit-chunk-encoding-chunk-encoding

	if isinstance(callsign, str) and is_hex(callsign):
		callsign = bytes.fromhex(callsign)

	dst = ""
	for i in range(0, len(callsign), 2):
		(s,) = unpack_from(">H", callsign, i)
		a = BASE40_TAB[s // 1600 % 40]
		b = BASE40_TAB[s // 40 % 40]
		c = BASE40_TAB[s % 40]
		dst += (a + b + c)
	dst = dst.rstrip("\x00")

	return dst

def ham64_encode(callsign: str) -> bytes:
	# https://github.com/arngll/arnce-spec/blob/main/n6drc-arnce.md#ham-64-link-layer-address-format
	return _16_bit_encode(callsign).ljust(8, b"\x00")

def eui48_encode(callsign: str) -> bytes:
	# https://github.com/arngll/arnce-spec/blob/main/n6drc-arnce.md#eui-48-encoding-details
	if len(callsign) == 9:
		cs_last = callsign[8]
		if cs_last == "1":
			callsign = callsign[:8] + "H"
		elif cs_last == "2":
			callsign = callsign[:8] + "P"
		elif cs_last == "3":
			callsign = callsign[:8] + "X"
		elif cs_last == "4":
			callsign = callsign[:8] + "5"
		else:
			return b""

	enc = _16_bit_encode(callsign)
	enc_len = len(enc)
	enc_last_ord = enc[-1] & 0x7
	enc = enc.ljust(6, b"\x00")

	if enc_len > 5 and (enc_len != 6 or enc_last_ord != 0):
		return b""

	dst = pack(">B5s", (enc[5] & 0xF8) + 2, enc[:5])

	return dst

def eui64_encode(callsign: str) -> bytes:
	# https://github.com/arngll/arnce-spec/blob/main/n6drc-arnce.md#eui-64-encoding-details
	no_eui48 = False
	if len(callsign) == 9:
		cs_last = callsign[8]
		if cs_last == "1":
			callsign = callsign[:8] + "H"
		elif cs_last == "2":
			callsign = callsign[:8] + "P"
		elif cs_last == "3":
			callsign = callsign[:8] + "X"
		elif cs_last == "4":
			callsign = callsign[:8] + "5"
		else:
			no_eui48 = True

	if len(callsign) == 12:
		cs_last = callsign[11]
		if cs_last == "1":
			callsign = callsign[:11] + "H"
		elif cs_last == "2":
			callsign = callsign[:11] + "P"
		elif cs_last == "3":
			callsign = callsign[:11] + "X"
		elif cs_last == "4":
			callsign = callsign[:11] + "5"
		else:
			return b""

	enc = _16_bit_encode(callsign)
	enc_len = len(enc)
	enc_last_ord = enc[-1] & 0x7
	enc = enc.ljust(8, b"\x00")

	if enc_len > 7 and (enc_len != 8 or enc_last_ord != 0):
		return b""

	if (not no_eui48 and enc_len < 6) or (not no_eui48 and enc_len == 6 and enc_last_ord == 0):
		first_byte = enc[5]
		dst = pack(">B5s", (first_byte & 0xF8) + 2, enc[:5])
		dst = dst[:3] + b"\xFF\xFE" + dst[3:6]
	else:
		first_byte = enc[7]
		dst = pack(">B7s", (first_byte & 0xF8) + 2, enc[:7])

	return dst

# formatters
format_16_bit = lambda data: "-".join([data[i:i + 2].hex().upper() for i in range(0, len(data), 2)])
format_ham64 = lambda data: "-".join([data[i:i + 2].hex().upper() for i in range(0, len(data), 2)])
format_eui48 = lambda data: ":".join([f"{x:02X}" for x in data])
format_eui64 = lambda data: ":".join([f"{x:02X}" for x in data])

# deformatters
deformat_16_bit = lambda data: bytes.fromhex(data.replace("-", ""))
deformat_ham64 = lambda data: bytes.fromhex(data.replace("-", ""))
deformat_eui48 = lambda data: bytes.fromhex(data.replace(":", ""))
deformat_eui64 = lambda data: bytes.fromhex(data.replace(":", ""))

def run_tests() -> None:
	# https://github.com/arngll/arnce-spec/blob/main/n6drc-arnce.md#examples-and-test-vectors
	tests = {
		"N6DRC": {
			"ham64": "5CAC-70F8-0000-0000",
			"eui48": "02:5C:AC:70:F8:00",
			"eui64": "02:5C:AC:FF:FE:70:F8:00"
		},
		"N6DRC^M2": {
			"ham64": "5CAC-711F-55C8-0000",
			"eui48": "CA:5C:AC:71:1F:55",
			"eui64": "CA:5C:AC:FF:FE:71:1F:55"
		},
		"KJ6QOH/P": {
			"ham64": "4671-6CA0-E9C0-0000",
			"eui48": "C2:46:71:6C:A0:E9",
			"eui64": "C2:46:71:FF:FE:6C:A0:E9"
		},
		"KJ6QOH-23": {
			"ham64": "4671-6CA0-F226-0000",
			"eui48": "22:46:71:6C:A0:F2",
			"eui64": "22:46:71:FF:FE:6C:A0:F2"
		},
		"KJ6QOH-2X": {
			"ham64": "4671-6CA0-F220-0000",
			"eui48": "",
			"eui64": "02:46:71:6C:A0:F2:20:00"
		},
		"KJ6QOH-99": {
			"ham64": "4671-6CA0-F344-0000",
			"eui48": "",
			"eui64": "02:46:71:6C:A0:F3:44:00"
		},
		"D9K": {
			"ham64": "1EAB-0000-0000-0000",
			"eui48": "02:1E:AB:00:00:00",
			"eui64": "02:1E:AB:FF:FE:00:00:00"
		},
		"NA1SS": {
			"ham64": "57C4-79B8-0000-0000",
			"eui48": "02:57:C4:79:B8:00",
			"eui64": "02:57:C4:FF:FE:79:B8:00"
		},
		"VI2BMARC50": {
			"ham64": "8B05-0E89-7118-A8C0",
			"eui48": "",
			"eui64": "C2:8B:05:0E:89:71:18:A8"
		},
		"VI2BMARC50-1": {
			"ham64": "8B05-0E89-7118-AECC",
			"eui48": "",
			"eui64": "BA:8B:05:0E:89:71:18:AE"
		},
		"VI2BMARC50-X": {
			"ham64": "8B05-0E89-7118-AEC8",
			"eui48": "",
			"eui64": ""
		}
	}

	for (callsign, expected) in tests.items():
		ham64 = ham64_encode(callsign)
		eui48 = eui48_encode(callsign)
		eui64 = eui64_encode(callsign)

		assert ham64 == bytes.fromhex(expected["ham64"].replace("-", "")), f"Invalid HAM-64 for \"{callsign}\""
		assert eui48 == bytes.fromhex(expected["eui48"].replace(":", "")), f"Invalid EUI-48 for \"{callsign}\""
		assert eui64 == bytes.fromhex(expected["eui64"].replace(":", "")), f"Invalid EUI-64 for \"{callsign}\""

def main() -> int:
	parser = ArgumentParser(description="A script to convert callsigns to 16-bit, HAM-64, EUI-48, and EUI-64")
	subparsers = parser.add_subparsers(dest="command")

	_16_bit_parser = subparsers.add_parser("16bit")
	_16_bit_parser.add_argument("-f", "--format", action="store_true", help="Apply formatting")
	_16_bit_parser.add_argument("callsign", type=str, help="The callsign to convert")

	ham64_parser = subparsers.add_parser("ham64")
	ham64_parser.add_argument("-f", "--format", action="store_true", help="Apply formatting")
	ham64_parser.add_argument("callsign", type=str, help="The callsign to convert")

	eui48_parser = subparsers.add_parser("eui48")
	eui48_parser.add_argument("-f", "--format", action="store_true", help="Apply formatting")
	eui48_parser.add_argument("callsign", type=str, help="The callsign to convert")

	eui64_parser = subparsers.add_parser("eui64")
	eui64_parser.add_argument("-f", "--format", action="store_true", help="Apply formatting")
	eui64_parser.add_argument("callsign", type=str, help="The callsign to convert")

	tests_parser = subparsers.add_parser("tests")

	args = parser.parse_args()

	if args.command == "16bit":
		enc = _16_bit_encode(args.callsign)
		if args.format:
			print(format_16_bit(enc))
		else:
			print(enc.hex().upper())
	elif args.command == "ham64":
		enc = ham64_encode(args.callsign)
		if args.format:
			print(format_ham64(enc))
		else:
			print(enc.hex().upper())
	elif args.command == "eui48":
		enc = eui48_encode(args.callsign)
		if args.format:
			print(format_eui48(enc))
		else:
			print(enc.hex().upper())
	elif args.command == "eui64":
		enc = eui64_encode(args.callsign)
		if args.format:
			print(format_eui64(enc))
		else:
			print(enc.hex().upper())
	elif args.command == "tests":
		run_tests()
		print("ALL TESTS PASSED!")

	return 0

if __name__ == "__main__":
	exit(main())