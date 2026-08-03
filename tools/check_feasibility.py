#!/usr/bin/env python3
"""GhostLock pselect stack-overlay feasibility check for a kernel Image.

Compares the stack frame layout of futex_wait_requeue_pi (where the freed
rt_mutex_waiter lives) against core_sys_select (where the user-controlled
stack_fds buffer lands). If both match the known-good values (verified on
Xiaomi 17 / pudding and K90 Pro Max / myron TW & CN), the default
PSELECT_SHIFT=0 config should work.

Known-good (6.12 GKI, SM8850):
  futex_wait_requeue_pi: frame=0x1c0, waiter zero-init group at sp+0x80
  core_sys_select:       frame=0x1b0, stack_fds group at sp+0x18

Usage: python3 tools/check_feasibility.py <kernel.bin | boot.img>
Requires: pip install capstone
"""

import struct
import subprocess
import sys
import tempfile
import os

GOOD = {
    "futex_wait_requeue_pi": {"frame": 0x1C0, "group_start": 0x80},
    "core_sys_select":       {"frame": 0x1B0, "group_start": 0x18},
}


def extract_kernel(path):
    data = open(path, "rb").read()
    if data[:8] == b"ANDROID!":
        kernel_size = struct.unpack_from("<I", data, 8)[0]
        return data[4096:4096 + kernel_size]
    return data


def kallsyms(kernel):
    if os.path.exists("ksyms.txt"):
        return open("ksyms.txt").read()
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(kernel)
        tmp = f.name
    try:
        out = subprocess.run(["kallsyms-finder", tmp], capture_output=True,
                             text=True, timeout=600)
        if out.returncode != 0:
            sys.exit("kallsyms-finder failed; drop a ksyms.txt next to this script")
        return out.stdout
    except FileNotFoundError:
        sys.exit("kallsyms-finder not installed (pip install vmlinux-to-elf); "
                 "or drop a ksyms.txt (addr type name) in the current directory")
    finally:
        os.unlink(tmp)


def analyze(kernel, addr, base, md):
    code = kernel[addr - base:addr - base + 1200]
    frame = 0
    zeros = []
    insns = list(md.disasm(code, 0))
    for insn in insns[:40]:
        op = insn.op_str
        if insn.mnemonic == "stp" and "sp, #" in op and "!" in op:
            try:
                frame += int(op.split("#-")[1].rstrip("]!"), 0)
            except ValueError:
                pass
        if insn.mnemonic == "sub" and op.startswith("sp, sp, #"):
            try:
                frame += int(op.split("#")[1], 0)
            except ValueError:
                pass
    for insn in insns:
        op = insn.op_str
        if insn.mnemonic == "stp" and "xzr, xzr" in op and "[sp, #" in op:
            try:
                v = int(op.split("#")[1].rstrip("]"), 0)
                zeros += [v, v + 8]
            except ValueError:
                pass
        elif insn.mnemonic == "str" and "xzr" in op and "[sp, #" in op:
            try:
                zeros.append(int(op.split("#")[1].rstrip("]"), 0))
            except ValueError:
                pass
    zeros = sorted(set(zeros))
    groups = []
    if zeros:
        cur = [zeros[0]]
        for z in zeros[1:]:
            if z - cur[-1] <= 16:
                cur.append(z)
            else:
                groups.append(cur)
                cur = [z]
        groups.append(cur)
    largest = max(groups, key=len) if groups else [0]
    return frame, largest[0], len(largest)


def main():
    try:
        from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
    except ImportError:
        sys.exit("pip install capstone")

    kernel = extract_kernel(sys.argv[1])
    syms = {}
    for line in kallsyms(kernel).splitlines():
        p = line.split()
        if len(p) >= 3:
            try:
                syms[p[2]] = int(p[0], 16)
            except ValueError:
                pass
    base = syms["_text"]
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)

    all_ok = True
    for fname, want in GOOD.items():
        if fname not in syms:
            print(f"[??] {fname} not in kallsyms")
            all_ok = False
            continue
        frame, gstart, glen = analyze(kernel, syms[fname], base, md)
        ok = frame == want["frame"] and gstart == want["group_start"]
        all_ok &= ok
        print(f"[{'OK' if ok else 'DIFF'}] {fname}: "
              f"frame=0x{frame:x} (want 0x{want['frame']:x}), "
              f"group@sp+0x{gstart:x} (want 0x{want['group_start']:x}), "
              f"{glen} zero-stores")

    print()
    if all_ok:
        print("Layout matches known-good kernels — PSELECT_SHIFT=0 should work.")
    else:
        print("Layout DIFFERS from known-good kernels. The exploit may panic or "
              "miss; expect to tune PSELECT_SHIFT (-14..14) or analyze frames "
              "manually before running on a live device.")


if __name__ == "__main__":
    main()
