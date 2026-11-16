# Sprint Airave 2.5+ (`PSC9131E`) — VPD, Kernel MTD Unlock & Flash Guide

> **AI Assistance Notice:** Portions of the reverse-engineering notes, Python scripts, and documentation in this repository were drafted and verified with the assistance of an AI coding assistant during hands-on hardware testing.

Technical findings, NAND partition maps, checksum details, and standalone Python tooling for unlocking `/dev/mtd4` (`VPD`) and updating the Primary Security Gateway (`fng_url`) on the **Sprint Airave 2.5+ (`cdmaFAP3`, Freescale `PSC9131E` PowerPC `e500v2`)**.

---

## 1. Hardware & NAND Partition Layout (`AirvNand`)

The Airave 2.5+ boots via Freescale KPOST (`Train-7 Diags`) into U-Boot and runs a real-time Linux `2.6.33.9-rt31` kernel on an `e500v2` (`SPE`) core.

| MTD | Partition | Offset | Size | Purpose |
| :--- | :--- | :--- | :--- | :--- |
| `mtd0` | `Boot` (`ro`) | `0x00000000` | `1 MiB` | SPL / KPOST Hardware Diagnostics (`10.01` VPD, `10.02` Cal) |
| `mtd1` | `Kern1` | `0x00100000` | `2944 KiB` | Primary multi-file `uImage` (gzip `vmlinux` + Train 5/7 DTBs) |
| `mtd2` | `Kern2` | `0x003e0000` | `2944 KiB` | Fallback multi-file `uImage` (keep untouched as recovery safety net) |
| `mtd3` | `Dir` | `0x006c0000` | `256 KiB` | Partition directory / metadata |
| `mtd4` | `VPD` (`ro`) | `0x00700000` | `384 KiB` | **Vital Product Data** (MACs, Serial, `fng_url`, `mgmt_url`, EAP creds) |
| `mtd5` | `UBoot1` | `0x00760000` | `1 MiB` | Primary U-Boot bootloader |
| `mtd6` | `UBoot2` | `0x00860000` | `1 MiB` | Secondary U-Boot bootloader |
| `mtd7` | `HRCW` (`ro`) | `0x00960000` | `256 KiB` | RF Calibration Table (`10.02 - Valid Cal Tables Test`) |
| `mtd8` | `Env` | `0x009a0000` | `384 KiB` | U-Boot Environment (`fw_printenv` / `fw_setenv`) |
| `mtd9` | `ImageA` | `0x00a00000` | `48 MiB` | Primary JFFS2 Rootfs (`pri=4`) |
| `mtd10` | `ImageB` | `0x03a00000` | `48 MiB` | Secondary / Fallback JFFS2 Rootfs (`pri=5`, `bootlimit=3`) |
| `mtd11` | `Config` | `0x06a00000` | `~22 MiB` | Persistent JFFS2 storage mounted at `/conf_files` |

---

## 2. Why `/dev/mtd4` Is Locked Read-Only & How the Kernel Patch Unlocks It

Even if `ro` is removed from U-Boot's `mtdparts` environment variable or `read-only;` is stripped from the DTB on flash, U-Boot's compiled `ft_board_setup()` actively re-injects the `read-only` property into `/proc/device-tree/ifc@ff71e000/nand@0,0/partition@700000/` in RAM before jumping to Linux. As a result, `/sys/class/mtd/mtd4/flags` remains `0x0` (not writable).

### Kernel Patch (`Kern1` `/dev/mtd1` Only)
1. Dump `/dev/mtd1` (`Kern1`) and unpack the U-Boot multi-file `uImage` (leaving `Kern2` `/dev/mtd2` completely stock as an automatic fallback).
2. Decompress `Image 0` (the gzip-compressed `vmlinux` kernel image).
3. Replace the literal string `"read-only\x00"` with `"read-onlX\x00"` inside `vmlinux`. When Linux's OF MTD parser (`of_mtd_parse_partitions`) calls `of_get_property(pp, "read-only", &len)`, it gets `NULL` and mounts every MTD partition with `MTD_WRITEABLE` (`0x400`).
4. Recompress `vmlinux` (`gzip -9`), rebuild the multi-file `uImage` with recalculated payload CRC32 (`dcrc`) and 64-byte header CRC32 (`hcrc`), write it to `/dev/mtd1`, and reboot.

---

## 3. VPD Structure (`0x678` Bytes) & 32-Bit XOR Checksum

KPOST (`10.01 - Valid VPD Test`) and `libPlatformABSLayer.so` (`GetAllVpdData`) validate `/dev/mtd4` on every cold boot. If the checksum is wrong, KPOST logs `POST Error Code: 0x10000013`.

### Checksum Algorithm
* **Coverage:** Bytes `0x0000` through `0x0673` (`1,652` bytes = **`413` big-endian 32-bit `uint32` words**).
* **Operation:** Sequential 32-bit XOR (`xor_sum ^= word`) across all `413` words.
* **Storage:** The resulting big-endian `uint32` is stored at offset **`0x0674`–`0x0677`**, making the complete VPD struct **`0x678` (`1,656`) bytes**.

### Complete VPD Byte Offset Map

| Offset | Size | Field | Description / Example |
| :--- | :--- | :--- | :--- |
| `0x0000` | `6` | `eth0` MAC | Raw 6-byte MAC address (`00 05 b9 xx xx xx`) |
| `0x0006` | `6` | `eth1` MAC | Secondary MAC (`eth0 + 1`) |
| `0x0010` | `4` | Struct Length | Big-endian `uint32`: `0x00000678` (`1656`) |
| `0x0018` | `4` | VPD Version | `00 02 02 01` (`Major 2, Minor 1`) |
| `0x002c` | `10` | `HLA` | Hardware Assembly ID (`"410100"` for Train 7) |
| `0x0036` | `32` | `HOSTNAME` / Serial | Uppercase MAC string (`"0005B9XXXXXX"`) |
| `0x0056` | `64` | **`fng_url`** | **Primary Security Gateway (`SecBrkApplication`)** |
| `0x0096` | `64` | `fng_url_sec` | Secondary Security Gateway (`" "` default) |
| `0x00d6` | `64` | NAI / Device ID | `<OUI>-cdmaFAP3-<SERIAL>` |
| `0x0116` | `320` | EAP-MD5 Password | Per-unit IKEv2 EAP-MD5 peer secret |
| `0x0256` | `32` | ACS Username | Per-unit TR-069 HTTP Digest username |
| `0x0276` | `32` | ACS Password | Per-unit TR-069 HTTP Digest password |
| `0x0296` | `128` | `mgmt_url` | TR-069 CWMP ACS Management Server URL |
| `0x0316` | `16` | OUI | `"0005B9 "` |
| `0x046c` | `16` | EAP Method | `"EAP-md5-rfc822"` |
| `0x057c` | `64` | Realm | IKEv2 / EAP domain realm (`"femto.sprint.net"`) |
| `0x05bc` | `16` | Vendor Tag | `"VEND_RADOM"` |
| `0x060c` | `16` | Product Class | `"cdmaFAP3"` |
| `0x061c` | `8` | Part Number | `"750721"` |
| `0x0634` | `12` | Lot Code | Factory lot string |
| `0x0640` | `12` | Mfg Serial Ext | Factory manufacturing string |
| `0x0650` | `8` | Hardware Rev | `"0015 "` |
| `0x0674` | `4` | **XOR Checksum** | Big-endian `uint32` XOR of `0x0000..0x0673` |

---

## 4. Flashing & Bad-Block Handling Notes

* **Bad Blocks on `/dev/mtd4`:** `/dev/mtd4` is `384 KiB` (three `128 KiB` erase blocks). On many units, block `0` (`0x00000000`) is factory-marked bad, leaving `256 KiB` (`0x20000` + `0x40000`) of usable space. Always back up with `nanddump -o -b` (which skips bad blocks cleanly) and write with `nandwrite -p`.
* **Expected `nandwrite` End-of-Partition Message:** Writing a `256 KiB` (`0x40000`) VPD image to a `384 KiB` partition with 1 bad block writes all `256 KiB` into blocks `0x20000` and `0x40000` and prints `Data was only partially written due to error: Success` when it hits the physical end of the partition. Always verify the written partition with `nanddump -o -b` + `md5sum`.
* **Do Not Touch `HWCW` (`/dev/mtd7`) Unless Restoring a Valid Calibration Table:** KPOST `10.02 - Valid Cal Tables Test` validates `/dev/mtd7`.

### Step-by-Step Workflow
```sh
# 1. On the Airave (with unlocked Kern1 booted, verify flags == 0x400):
cat /sys/class/mtd/mtd4/flags
nanddump -o -b -f /conf_files/vpd_backup.bin /dev/mtd4

# 2. Transfer vpd_backup.bin to your PC, patch ONLY fng_url, and recalculate XOR:
python3 vpd_segw_patcher.py vpd_backup.bin ://example.com -o vpd_new.bin

# 3. Transfer vpd_new.bin back to the Airave, flash /dev/mtd4, and sync U-Boot env:
flash_eraseall /dev/mtd4
nandwrite -p /dev/mtd4 /tmp/vpd_new.bin
fw_setenv fng_url ://example.com
sync
reboot
```
