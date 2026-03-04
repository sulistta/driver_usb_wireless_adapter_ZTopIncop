# Driver WiFi ZTopInc for Linux

Linux WiFi driver for the ZTopInc 802.11n USB adapter (`350b:9101`), based on the original upstream project and updated for newer Ubuntu kernels.

## Tested Environment
- Device: ZTopInc 802.11n USB adapter (`350b:9101`)
- OS: Ubuntu 24.04 LTS
- Kernel tested: `6.17.0-14-generic`

## What Was Updated
- Build system fixes for newer Kbuild behavior.
- Timer API updates for newer kernels.
- `cfg80211` callback signature updates for kernel 6.17+.
- File I/O compatibility update in Android helper code path.

## Build and Load
```bash
make -j"$(nproc)"
sudo modprobe cfg80211
sudo insmod ./zt9101_ztopmac_usb.ko cfg=./wifi.cfg
```

## Validate
```bash
lsmod | grep zt9101
ip link | grep -Ei 'wl|wlan'
sudo dmesg -T | tail -n 120
```

## Auto-load on Boot
1. Install the module into the current kernel module tree:
```bash
sudo install -D -m 644 ./zt9101_ztopmac_usb.ko "/lib/modules/$(uname -r)/extra/zt9101_ztopmac_usb.ko"
sudo depmod -a
```

2. Install firmware to a boot-safe path and update config:
```bash
sudo install -D -m 644 ./fw/ZT9101_fw_c1ab8ba.bin /lib/firmware/zt9101/ZT9101_fw_c1ab8ba.bin
sudo install -D -m 644 ./fw/ZT9101V30_fw_8546b3a.bin /lib/firmware/zt9101/ZT9101V30_fw_8546b3a.bin
sudo install -D -m 644 ./wifi.cfg /etc/zt9101/wifi.cfg
sudo sed -i "s|^fw=.*|fw=/lib/firmware/zt9101/ZT9101_fw_c1ab8ba.bin|" /etc/zt9101/wifi.cfg
sudo sed -i "s|^fw1=.*|fw1=/lib/firmware/zt9101/ZT9101V30_fw_8546b3a.bin|" /etc/zt9101/wifi.cfg
```

3. Configure module option and boot auto-load:
```bash
echo 'options zt9101_ztopmac_usb cfg=/etc/zt9101/wifi.cfg' | sudo tee /etc/modprobe.d/zt9101_ztopmac_usb.conf
echo 'zt9101_ztopmac_usb' | sudo tee /etc/modules-load.d/zt9101_ztopmac_usb.conf
```

4. Test without reboot:
```bash
sudo modprobe -r zt9101_ztopmac_usb
sudo modprobe zt9101_ztopmac_usb
```

5. Validate after reboot:
```bash
lsmod | grep zt9101
iw dev
nmcli device status
```

## Notes
- If module loading fails with signature errors, disable Secure Boot or sign the module.
- After kernel updates, rebuild and reinstall the `.ko` for the new kernel.
- Keep long commands on a single line (or use `\`) to avoid creating wrong paths by accident.

## Images
![ZTopInc WiFi Adapter](https://github.com/apris2/driver_usb_wireless_adapter_ZTopIncop/raw/main/IMG1.jpg)
![ZTopInc WiFi Adapter](https://github.com/apris2/driver_usb_wireless_adapter_ZTopIncop/raw/main/IMG2.jpg)
