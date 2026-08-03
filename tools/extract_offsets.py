#!/usr/bin/env python3
"""Extract a ghostlock-oneplus offsets.h entry from a boot.img / kernel Image.

Usage:
  python3 tools/extract_offsets.py boot.img
  python3 tools/extract_offsets.py kernel.bin --kallsyms ksyms.txt

Requires the `kallsyms-finder` CLI (pip install vmlinux-to-elf) unless you
pass a pre-extracted kallsyms file with --kallsyms (format: "addr type name").

The script prints a ready-to-paste OFFSETS_ENTRY block and runs
cross-validation reads against the kernel image (init_task.comm,
init_cred.usage, init_uts_ns.release) so you can trust the result without
a rooted device.
"""

import argparse
import struct
import subprocess
import sys
import tempfile
import os

BASE_SYMBOLS = [
    "init_task", "init_cred", "init_uts_ns", "empty_zero_page",
    "root_task_group", "selinux_state", "kptr_restrict",
    "selinux_blob_sizes", "kmalloc_caches", "anon_pipe_buf_ops",
    "nfulnl_logger", "loggers", "sysctl_bootid",
    "configfs_bin_read_iter", "configfs_bin_write_iter",
    "copy_splice_read", "noop_llseek",
    "system_unbound_wq", "call_usermodehelper_exec_work",
]

# ghostlock struct field -> kallsyms name (empty string = set 0)
ENTRY_MAP = [
    ("off_init_task", "init_task"),
    ("off_init_cred", "init_cred"),
    ("off_init_uts_ns", "init_uts_ns"),
    ("off_empty_zero_page", "empty_zero_page"),
    ("off_root_task_group", "root_task_group"),
    ("off_selinux_enforcing", "selinux_state"),
    ("off_kptr_restrict", "kptr_restrict"),
    ("off_selinux_blob_sizes", "selinux_blob_sizes"),
    ("off_security_hook_heads", None),
    ("off_kmalloc_caches", "kmalloc_caches"),
    ("off_anon_pipe_buf_ops", "anon_pipe_buf_ops"),
    ("off_ashmem_misc_fops", None),  # Rust ashmem on 6.12 GKI -> 0 (Path B only)
    ("off_ashmem_fops", "ASHMEM_FOPS_PTR"),
    ("off_ashmem_ioctl", ("fops_ioctl", "ashmem_rust6Ashmem")),
    ("off_ashmem_compat_ioctl", ("fops_compat_ioctl", "ashmem_rust6Ashmem")),
    ("off_ashmem_mmap", ("fops_mmap", "ashmem_rust6Ashmem")),
    ("off_ashmem_open", ("fops_open", "ashmem_rust6Ashmem")),
    ("off_ashmem_release", ("fops_release", "ashmem_rust6Ashmem")),
    ("off_ashmem_show_fdinfo", ("fops_show_fdinfo", "ashmem_rust6Ashmem")),
    ("off_configfs_read_iter", "configfs_bin_read_iter"),
    ("off_configfs_bin_write_iter", "configfs_bin_write_iter"),
    ("off_copy_splice_read", "copy_splice_read"),
    ("off_noop_llseek", "noop_llseek"),
    ("off_cap_capable_active", None),
    ("off_slide_nfulnl_logger", "nfulnl_logger"),
    ("off_slide_loggers_0_1", ("loggers", 0x10)),
    ("off_slide_boot_id", "sysctl_bootid"),
    ("off_system_unbound_wq", "system_unbound_wq"),
    ("off_call_usermodehelper_exec_work", "call_usermodehelper_exec_work"),
]

# BTF-verified field offsets used for cross-validation
TASK_COMM_OFF = 0x910
UTS_SYSNAME_OFF = 0
UTS_RELEASE_OFF = 130


def extract_kernel(path):
    data = open(path, "rb").read()
    if data[:8] == b"ANDROID!":
        kernel_size = struct.unpack_from("<I", data, 8)[0]
        page = 4096
        return data[page:page + kernel_size]
    return data


def run_kallsyms_finder(kernel):
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(kernel)
        tmp = f.name
    try:
        out = subprocess.run(["kallsyms-finder", tmp], capture_output=True,
                             text=True, timeout=600)
        if out.returncode != 0 or not out.stdout.strip():
            sys.exit("kallsyms-finder failed; pass --kallsyms <file> instead")
        return out.stdout
    except FileNotFoundError:
        sys.exit("kallsyms-finder not installed (pip install vmlinux-to-elf); "
                 "or pass --kallsyms <file>")
    finally:
        os.unlink(tmp)


def parse_kallsyms(text):
    syms = {}
    for line in text.splitlines():
        p = line.split()
        if len(p) >= 3:
            try:
                syms[p[2]] = (int(p[0], 16), p[1])
            except ValueError:
                pass
    return syms


def find_rust_fn(syms, frag, marker):
    for name, (addr, _t) in syms.items():
        if frag in name and marker in name and "toggle" not in name.lower():
            return addr
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("image", help="boot.img or raw kernel Image")
    ap.add_argument("--kallsyms", help="pre-extracted kallsyms text file")
    ap.add_argument("--uname", help="expected uname -r (for the entry comment)")
    args = ap.parse_args()

    kernel = extract_kernel(args.image)
    print(f"[*] kernel image: {len(kernel)} bytes", file=sys.stderr)

    if args.kallsyms:
        text = open(args.kallsyms).read()
    else:
        text = run_kallsyms_finder(kernel)
    syms = parse_kallsyms(text)
    print(f"[*] symbols: {len(syms)}", file=sys.stderr)

    base = syms["_text"][0]
    print(f"[*] _text = {hex(base)}", file=sys.stderr)

    offs = {}
    for field, spec in ENTRY_MAP:
        if spec is None:
            offs[field] = 0
        elif isinstance(spec, tuple) and len(spec) == 2 and isinstance(spec[1], int):
            addr = syms.get(spec[0], (None,))[0]
            offs[field] = (addr - base + spec[1]) if addr else None
        elif isinstance(spec, tuple):
            addr = find_rust_fn(syms, spec[0], spec[1])
            offs[field] = (addr - base) if addr else None
        else:
            hit = syms.get(spec)
            if not hit and spec == "ASHMEM_FOPS_PTR":
                for name, (a, _t) in syms.items():
                    if "ASHMEM_FOPS_PTR" in name:
                        hit = (a, _t)
                        break
            offs[field] = (hit[0] - base) if hit else None

    missing = [k for k, v in offs.items() if v is None]
    for k in missing:
        print(f"[!] {k}: NOT FOUND (set 0 and review manually)", file=sys.stderr)
        offs[k] = 0

    # --- cross-validation reads -------------------------------------------
    def read_at(va, n):
        return kernel[va - base:va - base + n]

    ok = True
    comm = read_at(base + offs["off_init_task"] + TASK_COMM_OFF, 16).split(b"\x00")[0]
    print(f"[check] init_task.comm = {comm!r} (expect b'swapper')", file=sys.stderr)
    ok &= comm.startswith(b"swapper")

    usage = struct.unpack("<i", read_at(base + offs["off_init_cred"], 4))[0]
    print(f"[check] init_cred.usage = {usage} (expect small int)", file=sys.stderr)
    ok &= 0 < usage < 64

    sysname = read_at(base + offs["off_init_uts_ns"] + UTS_SYSNAME_OFF, 65).split(b"\x00")[0]
    release = read_at(base + offs["off_init_uts_ns"] + UTS_RELEASE_OFF, 65).split(b"\x00")[0]
    print(f"[check] uts sysname = {sysname!r}", file=sys.stderr)
    print(f"[check] uts release = {release!r}", file=sys.stderr)
    ok &= sysname == b"Linux" and b"-" in release
    if args.uname and release.decode() != args.uname:
        print(f"[!] release != --uname ({args.uname})", file=sys.stderr)
        ok = False

    uname = args.uname or release.decode()
    print()
    print(f'OFFSETS_ENTRY("{uname}",'
          + (f"  /* TODO: ROM version e.g. OS3.0.x.0.WXXXXXM */" if not args.uname else "")
    )
    print("  .kernel_phys_load=0x0, /* TODO: read /proc/iomem 'Kernel code' on a rooted")
    print("     unit of the same SoC, minus 0x10000. SM8850 uses 0xc7800000. */")
    print("  STRUCT_OFFSETS_6_12,  /* verify with tools/check_btf.py first! */")
    fields = [f".{k}=0x{v:08X}" for k, v in offs.items()]
    for i in range(0, len(fields), 3):
        print("  " + ", ".join(fields[i:i + 3]) + ",")
    print("),")
    print(file=sys.stderr)
    print(f"[{'OK' if ok else 'FAIL'}] cross-validation "
          + ("passed" if ok else "FAILED — do not use these offsets"), file=sys.stderr)


if __name__ == "__main__":
    main()
