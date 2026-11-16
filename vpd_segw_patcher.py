#!/usr/bin/env python3
"""
Airvana Airave 2.5+ (PSC9131E) VPD fng_url (Primary Security Gateway) Changer.
Updates only fng_url at offset 0x0056 and recalculates the 32-bit XOR checksum.
"""
import argparse
import struct
from pathlib import Path

VPD_STRUCT_SIZE = 0x678  # 1,656 bytes
FNG_URL_OFFSET = 0x0056
FNG_URL_MAX_LEN = 64     # 63 ASCII chars + null terminator
CHECKSUM_OFFSET = 0x0674


def compute_vpd_xor(buf: bytes) -> int:
    if len(buf) < VPD_STRUCT_SIZE:
        raise ValueError(f"VPD buffer too short: {len(buf)} < {VPD_STRUCT_SIZE}")
    xor_val = 0
    for off in range(0, CHECKSUM_OFFSET, 4):
        (word,) = struct.unpack(">I", buf[off : off + 4])
        xor_val ^= word
    return xor_val & 0xFFFFFFFF


def read_cstr(buf: bytes, off: int, max_len: int) -> str:
    return buf[off : off + max_len].split(b"\x00", 1).decode("ascii", errors="replace")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Change only fng_url in an Airave 2.5+ VPD dump and recalculate its XOR checksum."
    )
    parser.add_argument("input", type=Path, help="Input VPD dump (1656B struct or 256KiB/384KiB flash dump)")
    parser.add_argument("fng_url", nargs="?", help="New Primary Security Gateway hostname (omit to inspect/verify only)")
    parser.add_argument("-o", "--output", type=Path, help="Output patched VPD file")
    args = parser.parse_args()

    raw = bytearray(args.input.read_bytes())
    if len(raw) < VPD_STRUCT_SIZE:
        raise SystemExit(f"Error: {args.input} is {len(raw)} bytes (expected at least {VPD_STRUCT_SIZE} bytes).")

    (struct_len,) = struct.unpack(">I", raw[0x0010:0x0014])
    if struct_len != VPD_STRUCT_SIZE:
        raise SystemExit(f"Error: Invalid VPD struct length 0x{struct_len:x} (expected 0x{VPD_STRUCT_SIZE:x}).")

    (orig_csum,) = struct.unpack(">I", raw[CHECKSUM_OFFSET : CHECKSUM_OFFSET + 4])
    calc_orig_csum = compute_vpd_xor(raw)
    old_url = read_cstr(raw, FNG_URL_OFFSET, FNG_URL_MAX_LEN)

    print(f"Input file   : {args.input} ({len(raw)} bytes)")
    print(f"Serial / MAC : {read_cstr(raw, 0x36, 32)} / {raw[0:6].hex(':')}")
    print(f"Current URL  : {old_url}")
    print(f"Input XOR    : 0x{orig_csum:08x} ({'VALID' if orig_csum == calc_orig_csum else 'INVALID'})")

    if not args.fng_url:
        return

    if not args.output:
        raise SystemExit("Error: -o / --output is required when setting a new fng_url.")

    encoded_url = args.fng_url.encode("ascii")
    if len(encoded_url) >= FNG_URL_MAX_LEN:
        raise SystemExit(f"Error: fng_url must be <= {FNG_URL_MAX_LEN - 1} ASCII characters.")

    raw[FNG_URL_OFFSET : FNG_URL_OFFSET + FNG_URL_MAX_LEN] = b"\x00" * FNG_URL_MAX_LEN
    raw[FNG_URL_OFFSET : FNG_URL_OFFSET + len(encoded_url)] = encoded_url

    new_csum = compute_vpd_xor(raw)
    struct.pack_into(">I", raw, CHECKSUM_OFFSET, new_csum)

    args.output.write_bytes(raw)
    print(f"Updated URL  : {read_cstr(raw, FNG_URL_OFFSET, FNG_URL_MAX_LEN)}")
    print(f"New XOR      : 0x{new_csum:08x} ({new_csum})")
    print(f"Saved to     : {args.output}")


if __name__ == "__main__":
    main()
