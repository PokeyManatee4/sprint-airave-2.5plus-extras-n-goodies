#!/usr/bin/env python3
"""
Airvana Airave 2.5+ (PSC9131E) U-Boot Multi-File Kernel MTD Read-Only Unlock Patcher.
Unpacks Kern1 uImage, patches 'read-only' -> 'read-onlX' in vmlinux so MTD partitions
mount with MTD_WRITEABLE (0x400), and recalculates U-Boot data and header CRC32s.
"""
import argparse
import gzip
import struct
import zlib
from pathlib import Path

UIMAGE_MAGIC = 0x27051956
UIMAGE_HEADER_SIZE = 64


def parse_multifile_uimage(raw: bytes):
    if len(raw) < UIMAGE_HEADER_SIZE:
        raise ValueError("Input file is smaller than 64-byte U-Boot header.")

    magic, hcrc, timestamp, data_size, load, ep, dcrc, os_t, arch, itype, comp, name = struct.unpack(
        ">IIIIIIIBBBB32s", raw[:UIMAGE_HEADER_SIZE]
    )
    if magic != UIMAGE_MAGIC:
        raise ValueError(f"Invalid U-Boot magic: 0x{magic:08x} (expected 0x{UIMAGE_MAGIC:08x}).")

    # Verify original header CRC
    hdr_zero = struct.pack(">IIIIIIIBBBB32s", magic, 0, timestamp, data_size, load, ep, dcrc, os_t, arch, itype, comp, name)
    if (zlib.crc32(hdr_zero) & 0xFFFFFFFF) != hcrc:
        raise ValueError("Original U-Boot header CRC32 mismatch.")

    payload = raw[UIMAGE_HEADER_SIZE : UIMAGE_HEADER_SIZE + data_size]
    if len(payload) != data_size:
        raise ValueError(f"Truncated payload: got {len(payload)} bytes, expected {data_size}.")

    if (zlib.crc32(payload) & 0xFFFFFFFF) != dcrc:
        raise ValueError("Original U-Boot payload CRC32 mismatch.")

    # Parse null-terminated size table at start of multi-file payload
    sizes = []
    pos = 0
    while True:
        (sz,) = struct.unpack(">I", payload[pos : pos + 4])
        pos += 4
        if sz == 0:
            break
        sizes.append(sz)

    if not sizes:
        raise ValueError("No sub-images found in U-Boot multi-file payload.")

    # Extract each 4-byte aligned sub-image
    images = []
    for sz in sizes:
        images.append(payload[pos : pos + sz])
        pos += sz + ((4 - (sz % 4)) % 4)

    header_fields = (magic, timestamp, load, ep, os_t, arch, itype, comp, name)
    return header_fields, images


def build_multifile_uimage(header_fields, images: list[bytes]) -> bytes:
    magic, timestamp, load, ep, os_t, arch, itype, comp, name = header_fields

    payload = bytearray()
    for img in images:
        payload += struct.pack(">I", len(img))
    payload += struct.pack(">I", 0)

    for img in images:
        payload += img
        payload += b"\x00" * ((4 - (len(img) % 4)) % 4)

    new_dcrc = zlib.crc32(payload) & 0xFFFFFFFF
    hdr_zero = struct.pack(
        ">IIIIIIIBBBB32s", magic, 0, timestamp, len(payload), load, ep, new_dcrc, os_t, arch, itype, comp, name
    )
    new_hcrc = zlib.crc32(hdr_zero) & 0xFFFFFFFF
    final_hdr = struct.pack(
        ">IIIIIIIBBBB32s", magic, new_hcrc, timestamp, len(payload), load, ep, new_dcrc, os_t, arch, itype, comp, name
    )
    return final_hdr + bytes(payload)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Patch vmlinux inside an Airave 2.5+ Kern1 uImage to unlock read-only MTD partitions."
    )
    parser.add_argument("input", type=Path, help="Input Kern1 dump (/dev/mtd1)")
    parser.add_argument("-o", "--output", type=Path, required=True, help="Output patched uImage file")
    args = parser.parse_args()

    raw = args.input.read_bytes()
    header_fields, images = parse_multifile_uimage(raw)
    print(f"Loaded valid multi-file uImage: {len(images)} sub-images (Image 0 = {len(images[0])} bytes)")

    # Locate gzip stream inside Image 0 (kernel)
    gz_offset = images[0].find(b"\x1f\x8b\x08")
    if gz_offset < 0:
        raise SystemExit("Error: Could not find gzip header inside Image 0.")

    prefix = images[0][:gz_offset]
    vmlinux = bytearray(gzip.decompress(images[0][gz_offset:]))
    print(f"Decompressed vmlinux: {len(vmlinux)} bytes")

    matches = [i for i in range(len(vmlinux)) if vmlinux[i : i + 10] == b"read-only\x00"]
    if not matches:
        raise SystemExit("Error: 'read-only\\x00' string not found in vmlinux (already patched?).")

    for off in matches:
        vmlinux[off : off + 10] = b"read-onlX\x00"
    print(f"Patched 'read-only\\x00' -> 'read-onlX\\x00' at offsets: {[hex(m) for m in matches]}")

    images[0] = prefix + gzip.compress(bytes(vmlinux), compresslevel=9)
    out_uimage = build_multifile_uimage(header_fields, images)
    args.output.write_bytes(out_uimage)
    print(f"Saved patched uImage to {args.output} ({len(out_uimage)} bytes)")


if __name__ == "__main__":
    main()
