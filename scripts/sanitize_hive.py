#!/usr/bin/env python3
"""Sanitize VM-identifying strings out of an offline Windows registry hive.

The Brovan Windows dependency (WinReg/*) is exported with `reg save` from a real
Windows box. When that box is a Hyper-V / Azure VM, the SYSTEM hive carries the
VM's own hardware identity -- most visibly the storage device id
`SCSI\\Disk&Ven_Msft&Prod_Virtual_Disk` under `...\\Enum\\SCSI`. A guest that
enumerates the storage buses then reads "Virtual" and concludes it is running in
a sandbox (e.g. al-khaser "Enum\\IDE and Enum\\SCSI entries for VM strings").

Fixing this at the *dependency* layer -- rather than masking the string at every
registry read -- keeps every registry surface (enumerate, open, query-value)
coherent and needs no runtime code. Each replacement is byte-length preserving
and applied in BOTH ASCII and UTF-16LE (registry key names may be stored
compressed/ASCII while values are UTF-16LE), so the hive stays structurally
valid: cell sizes are unchanged and the base-block checksum (which covers only
the header, not the HBIN string data) never needs recomputing. Brovan's hive
reader resolves subkeys by their actual stored name (name-keyed dictionary, not
the on-disk name hash), so a renamed key round-trips through both enumeration
and open with no hash fix-up. The pass is idempotent.

Usage:
    sanitize_hive.py <hive> [<hive> ...]
"""

import sys

# (vm_string, realistic_replacement) -- MUST be equal length. Realistic values
# are ordinary consumer-hardware identifiers carrying no virtualization marker.
# Extend this table as further hive-resident VM tells are confirmed (e.g. ACPI
# OEM ids), keeping the length-preserving invariant.
REPLACEMENTS = [
    # Hyper-V / Azure synthetic disk. The disk surfaces in two id forms that must stay
    # INTERNALLY COHERENT after rewriting: the device-instance path
    # `SCSI\Disk&Ven_Msft&Prod_Virtual_Disk` and the hardware/compatible id
    # `SCSI\DiskMsft____Virtual_Disk____`. Rewriting only the product (the previous
    # single "Virtual_Disk"->"WDC_WD10EZEX" rule) left the `Ven_Msft` / `Msft____`
    # Microsoft synthetic-VENDOR marker in place, producing the impossible pairing
    # "Ven_Msft & Prod_WDC..." (a Microsoft vendor never ships a Western Digital
    # product) -- itself a VM tell. A real SATA/ATA disk enumerates with an EMPTY
    # SCSI vendor (`Ven_&Prod_<model>` / 8 blanks -> `________` in the padded id), so
    # both forms are rewritten to an empty vendor + a real WD Blue 1 TB model. All
    # replacements stay byte-length preserving (26 / 24 / 12 chars).
    # -- ORDER MATTERS: longest/most-specific first, so the disk's vendor+product are
    #    rewritten together before the generic vendor rule can nibble the shared prefix.
    ("Ven_Msft&Prod_Virtual_Disk", "Ven_&Prod_WDC_WD10EZEX-08W"),  # instance path (26)
    ("Msft____Virtual_Disk____", "________WDC_WD10EZEX____"),        # hardware/compat id (24)
    ("Virtual_Disk", "WDC_WD10EZEX"),                                # product-only fallback (12)
    # Generic Microsoft synthetic-VENDOR marker in the padded 8-char SCSI vendor field.
    # After the disk-specific rules above have run, the only remaining `Msft____` are on
    # the other Hyper-V synthetic storage devices (PMEM disk, synthetic DVD-ROM); emptying
    # their vendor removes the "Msft" tell uniformly. `________` = an 8-blank ATA vendor.
    # The byte pattern is storage-id specific, so there is no non-device collateral.
    ("Msft____", "________"),                                        # generic vendor (8)
    # KNOWN RESIDUAL (untouched -- no probe currently reads them, and a desktop would not
    # carry these synthetic devices at all, so there is no coherent length-preserving
    # consumer-hardware PRODUCT substitute to fabricate. Revisit only if a sample keys on
    # them): `VirtualPMEM_Disk`, `Virtual_DVD-ROM_` product ids and the `Msft Virtual Disk`
    # friendly-name / device-description strings.
]


def sanitize(data: bytearray) -> int:
    total = 0
    for vm, real in REPLACEMENTS:
        if len(vm) != len(real):
            raise ValueError(f"non-length-preserving replacement: {vm!r} -> {real!r}")
        for encoding in ("latin-1", "utf-16-le"):
            needle = vm.encode(encoding)
            repl = real.encode(encoding)
            if len(needle) != len(repl):
                raise ValueError(f"encoding {encoding} changed length for {vm!r}")
            count = data.count(needle)
            if count:
                data[:] = data.replace(needle, repl)
                total += count
    return total


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2

    rc = 0
    for path in argv[1:]:
        try:
            with open(path, "rb") as f:
                data = bytearray(f.read())
        except OSError as ex:
            print(f"[-] {path}: {ex}", file=sys.stderr)
            rc = 1
            continue

        original_len = len(data)
        replaced = sanitize(data)
        if len(data) != original_len:
            print(f"[-] {path}: length changed ({original_len} -> {len(data)}), refusing to write",
                  file=sys.stderr)
            rc = 1
            continue

        if replaced:
            with open(path, "wb") as f:
                f.write(data)
            print(f"[+] {path}: sanitized {replaced} VM-string occurrence(s)")
        else:
            print(f"[+] {path}: already clean")

    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv))
