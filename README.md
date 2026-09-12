USB packet fuzzer (libusb) - README
==================================

Overview
- This fuzzer targets USB devices using libusb-1.0.
- It supports control, bulk, and interrupt transfers.
- Mutations include bit flips, overwrites, arithmetic changes, insert/delete, and splicing with optional corpus seeds.
- Crashes or interesting behaviors (device disconnects, IO errors) are saved to a crash directory for offline analysis.

Build dependencies
- libusb-1.0 development headers
  - On Debian/Ubuntu/Kali: sudo apt install libusb-1.0-0-dev
- gcc or clang
- pthreads (provided by the system)

Build
- make
- Or for debug: make debug
- Or with ASan: make asan

Basic usage
- Example: fuzz bulk OUT transfers with a chosen device
  ./usb_fuzzer --vid 0x1234 --pid 0xabcd --out-ep 0x02 --in-ep 0x81 --type bulk --corpus ./corpus --crashes ./crashes --jobs 4 --timeout 500

- Example: control fuzzing
  ./usb_fuzzer --vid 0x1234 --pid 0xabcd --type control --crashes ./crashes --jobs 2

Options (summary)
- --vid 0xVVVV    Vendor ID (hex)
- --pid 0xPPPP    Product ID (hex)
- --interface N   Interface number to claim (optional)
- --out-ep 0xEE   OUT endpoint (required for bulk/interrupt)
- --in-ep 0xEE    IN endpoint (optional)
- --type T        control | bulk | interrupt
- --corpus DIR    optional directory of binary seed packets
- --crashes DIR   where to save interesting inputs (required)
- --timeout MS    transfer timeout (default 500)
- --jobs N        number of worker threads (default 1)
- --iterations N  per-thread iterations (0 = forever)
- --max-input BYTES  maximum generated packet size (default 16 KiB)
- --dry-run       don't send packets; simulate (useful for testing)

