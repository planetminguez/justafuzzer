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

Safety & operational guidance
- Use dedicated test devices. USB fuzzing can brick devices or corrupt firmware.
- Prefer using virtual USB backends (USB/IP, QEMU USB passthrough) or disposable hardware.
- Consider monitoring kernel logs (dmesg) concurrently to observe device disconnects or kernel-level errors:
  sudo dmesg -w
- To allow non-root access on Linux, add udev rules granting access to the VID/PID under test. Otherwise run as root (careful).

Interpreting results
- When libusb reports LIBUSB_ERROR_NO_DEVICE the device disconnected; this may indicate a severe fault.
- IO / PIPE / OVERFLOW / ACCESS errors may indicate the device entered an invalid state or the host driver prevented an operation.
- The fuzzer writes binary files named usb_crash_<timestamp>.bin plus a .txt metadata file; these contain sent and received payloads (binary format described in code).

Extending the fuzzer
- For protocol-specific fuzzing (e.g., HID, Mass Storage, CDC), add format-aware mutators and sequence models.
- To gather coverage of device firmware you would need hardware-instrumentation or a simulator/emulator.
- Add heuristics to detect stateful faults (e.g., repeated disconnects on specific request sequences).
- Integrate with a USB protocol analyzer (e.g., Wireshark with usbmon) to correlate PC-side traffic and kernel logs.

If you'd like, I can:
- Add support for sequence templates (multi-step exchange scripts) and mutate across sequences.
- Add an option to automatically parse descriptors and fuzz specific class requests (HID, MSC, CDC).
- Add an optional "safe mode" that limits destructive requests (e.g., avoid vendor-specific OUTs unless explicitly enabled).