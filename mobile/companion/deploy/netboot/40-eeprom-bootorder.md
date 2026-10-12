# Pi 4 EEPROM: enable network boot

The Pi 4 Model B boots firmware from its SPI EEPROM, not the (absent) SD card.
To netboot you must set the EEPROM's `BOOT_ORDER` to try the network, and make
sure the firmware is recent enough to support TFTP/NFS netboot.

You only do this once per device, and it needs a one-time writable boot medium
(any spare SD card or USB stick) to run `raspi-config` / `rpi-eeprom-config`.
After the EEPROM is set, remove it -- the Pi keeps the setting.

## 1. Check / update the EEPROM

On a Pi booted from any medium:

```bash
sudo rpi-eeprom-update            # shows current version
sudo rpi-eeprom-update -a         # update if needed, then reboot
```

## 2. Set the boot order to network

```bash
sudo -E rpi-eeprom-config --edit
```

Set:

```
[all]
BOOT_ORDER=0xf2
# Optional: use a flat TFTP root instead of a per-serial directory.
# TFTP_PREFIX=0
```

`BOOT_ORDER` nibbles are read **right to left**:

| nibble | meaning                 |
|--------|-------------------------|
| `0x1`  | SD card                 |
| `0x2`  | network (TFTP)          |
| `0x4`  | USB mass storage        |
| `0xf`  | restart / retry (loop)  |

- `0xf2` = try **network**, then **restart and retry** -- correct for a diskless
  drop that must come back after a power blip and has no local media.
- `0xf21` = SD, then network, then retry (useful only if you keep an SD as a
  fallback).

Save; the tool writes the new EEPROM image and reboots.

## 3. Serial directory

By default the Pi 4 requests its TFTP files from a directory named after the
**last 8 hex digits of its serial number**. Find the serial with:

```bash
vcgencmd otp_dump | grep '^28:'      # or: grep Serial /proc/cpuinfo
```

Put that value in `PI_SERIAL` in `deploy.conf` (the default `TFTP_SERIAL_DIR=1`
publishes firmware under `$TFTP_ROOT/$PI_SERIAL`). If you prefer a single flat
TFTP root for one device, set `TFTP_PREFIX=0` in the EEPROM config **and**
`TFTP_SERIAL_DIR=0` in `deploy.conf`.

## 4. Watch the first boot

Attach a USB-serial adapter to the UART (GND/TX/RX on the 40-pin header) at
115200 baud, or watch your TFTP/NFS server logs. You should see the bootloader
request `start4.elf`, then the kernel mount the NFS root.
