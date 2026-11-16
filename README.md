# Sprint Airave 2.5+ (`PSC9131E`) — VPD, Kernel MTD Unlock & Flash Guide

> **Prerequisite / Precursor Repository:** Before following this guide, you must first obtain root shell access and extract your unit's SeGW/ACS credentials using **[`dondaplayer1/Sprint-Airave-Airvana-2.5-Root`](https://github.com/dondaplayer1/Sprint-Airave-Airvana-2.5-Root/tree/main)** (follow the **Airave 2.5+ (`2-5plus`)** guide).

> **AI Use Disclosure:** Portions of the reverse-engineering notes, Python scripts (`kernel_mtd_unlock.py`, `vpd_fng_changer.py`), and documentation in this repository were drafted and verified with the assistance of an AI coding assistant during hands-on hardware testing. Review scripts before running them on your device.

Technical findings, NAND partition maps, checksum details, and standalone Python tooling for unlocking `/dev/mtd4` (`VPD`) and updating the Primary Security Gateway (`fng_url`) on the **Sprint Airave 2.5+ (`cdmaFAP3`, Freescale `PSC9131E` PowerPC `e500v2`, tested on firmware `6.5.01.010` / hardware `750721.00.03`)**.

---

## 1. Hardware & NAND Partition Layout (`AirvNand`)

The Airave 2.5+ boots via Freescale KPOST (`Train-7 Diags`) into U-Boot and runs a real-time Linux `2.6.33.9-rt31` kernel on an `e500v2` (`SPE`) core.

| MTD | Partition | Offset | Size | Purpose |
| :--- | :--- | :--- | :--- | :--- |
| `mtd0` | `Boot` (`ro`) | `0x00000000` | `1 MiB` | SPL / KPOST Hardware Diagnostics (`10.01` VPD, `10.02` Cal) |
| `mtd1` | `Kern1` | `0x00100000` | `2944 KiB` | Primary multi-file `uImage` (gzip `vmlinux` + Train 5/7 DTBs) |
| `mtd2` | `Kern2` | `0x003e0000` | `2944 KiB` | Fallback multi-file `uImage` (leave untouched as a recovery safety net) |
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

Even if `ro` is removed from U-Boot's `mtdparts` environment variable or `read-only;` is stripped from the DTB on flash, U-Boot's compiled `ft_board_setup()` re-injects the `read-only` property into `/proc/device-tree/ifc@ff71e000/nand@0,0/partition@700000/` in RAM before jumping to Linux. As a result, `/sys/class/mtd/mtd4/flags` stays `0x0` (locked read-only).

### Kernel Patch (`Kern1` `/dev/mtd1` Only)
1. `kernel_mtd_unlock.py` unpacks the U-Boot multi-file `uImage` from `/dev/mtd1` (`Kern1` only—leaving `Kern2` `/dev/mtd2` completely stock as an automatic fallback).
2. It decompresses `Image 0` (the gzip-compressed `vmlinux` kernel image).
3. It replaces `"read-only\x00"` with `"read-onlX\x00"` inside `vmlinux`. When Linux's OF MTD parser (`of_mtd_parse_partitions`) calls `of_get_property(pp, "read-only", &len)`, it gets `NULL` and mounts all MTD partitions with `MTD_WRITEABLE` (`0x400`).
4. It recompresses `vmlinux` (`gzip -9`) and rebuilds the multi-file `uImage` with recalculated payload CRC32 (`dcrc`) and 64-byte header CRC32 (`hcrc`).

---

## 3. VPD Structure (`0x678` Bytes) & 32-Bit XOR Checksum

KPOST (`10.01 - Valid VPD Test`) and `libPlatformABSLayer.so` (`GetAllVpdData`) validate `/dev/mtd4` on every cold boot. If the checksum fails, KPOST logs `POST Error Code: 0x10000013`.

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

## 4. Step-by-Step Instructions

> **Safety Notes:**
> * Always keep backups of `/dev/mtd1` and `/dev/mtd4` on your PC before erasing any partition.
> * Leave `Kern2` (`/dev/mtd2`) and `ImageB` (`/dev/mtd10`) untouched so U-Boot retains its automatic fallback bank.
> * Leave `HWCW` (`/dev/mtd7`) untouched (`10.02 - Valid Cal Tables Test` validates `/dev/mtd7` on boot).
> * BusyBox `nc` on the Airave only supports client mode (`nc <PC_IP> <PORT>`), so always run `nc -l -p <PORT>` on your PC and connect outward from the Airave.

### Step 1: Dump `Kern1` (`/dev/mtd1`) & `VPD` (`/dev/mtd4`) to Your PC

1. **On the Airave (via root Telnet/SSH from the precursor guide):**
   ```sh
   nanddump -o -b -f /tmp/kern1_backup.bin /dev/mtd1
   nanddump -o -b -f /conf_files/vpd_backup.bin /dev/mtd4
   ```
2. **Transfer `kern1_backup.bin` to your PC (replace `192.168.17.1` with your PC's IP):**
   * On your PC:
     ```bash
     nc -l -p 9998 > kern1_backup.bin
     ```
   * On the Airave:
     ```sh
     nc 192.168.17.1 9998 < /tmp/kern1_backup.bin
     rm -f /tmp/kern1_backup.bin
     ```
3. **Transfer `vpd_backup.bin` to your PC:**
   * On your PC:
     ```bash
     nc -l -p 9998 > vpd_backup.bin
     ```
   * On the Airave:
     ```sh
     nc 192.168.17.1 9998 < /conf_files/vpd_backup.bin
     ```

---

### Step 2: Patch `Kern1` & Your VPD on Your PC

Run both scripts on your PC (requires Python 3.10+, standard library only):

```bash
# 1. Unlock MTD partitions in Kern1 (patches 'read-only' -> 'read-onlX' and recalculates U-Boot CRCs)
python3 kernel_mtd_unlock.py kern1_backup.bin -o kern1_unlock.bin

# 2. Patch ONLY fng_url in your VPD backup and recalculate the 32-bit XOR checksum
python3 vpd_fng_changer.py vpd_backup.bin segw.femto.example.com -o vpd_new.bin
```

---

### Step 3: Flash `kern1_unlock.bin` to `/dev/mtd1` & Reboot

1. **On your PC, serve `kern1_unlock.bin`:**
   ```bash
   nc -l -p 9998 < kern1_unlock.bin
   ```
2. **On the Airave, pull `kern1_unlock.bin`, flash `/dev/mtd1`, and reboot:**
   ```sh
   nc 192.168.17.1 9998 > /tmp/kern1_unlock.bin
   flash_eraseall /dev/mtd1
   nandwrite -p /dev/mtd1 /tmp/kern1_unlock.bin
   rm -f /tmp/kern1_unlock.bin
   sync
   reboot
   ```

---

### Step 4: Verify `/dev/mtd4` Is Writable & Flash `vpd_new.bin`

1. **After reboot, confirm `/dev/mtd4` now reports `0x400` (`MTD_WRITEABLE`):**
   ```sh
   cat /sys/class/mtd/mtd4/flags
   ```
2. **On your PC, serve `vpd_new.bin`:**
   ```bash
   nc -l -p 9998 < vpd_new.bin
   ```
3. **On the Airave, pull `vpd_new.bin`, flash `/dev/mtd4`, verify the checksum/MD5, and sync U-Boot `fng_url`:**
   ```sh
   nc 192.168.17.1 9998 > /tmp/vpd_new.bin
   flash_eraseall /dev/mtd4
   nandwrite -p /dev/mtd4 /tmp/vpd_new.bin

   # Verify written VPD matches vpd_new.bin
   nanddump -o -b -f /tmp/vpd_verify.bin /dev/mtd4
   md5sum /tmp/vpd_new.bin /tmp/vpd_verify.bin

   # Sync U-Boot environment variable and reboot
   fw_setenv fng_url segw.femto.example.com
   rm -f /tmp/vpd_new.bin /tmp/vpd_verify.bin
   sync
   reboot
   ```
4. **Confirm the new Security Gateway is active after reboot:**
   ```sh
   fw_printenv fng_url
   grep "Primary Security Gateway" /conf_files/logfiles/Startup.log
   ```
   *(Optional: You can restore your untouched `kern1_backup.bin` onto `/dev/mtd1` afterward if you want `Kern1` back to 100% stock.)*
