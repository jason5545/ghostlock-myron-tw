#!/usr/bin/env python3
"""Verify kernel struct layouts against ghostlock's STRUCT_OFFSETS_6_12
using the BTF embedded in the kernel Image (CONFIG_DEBUG_INFO_BTF).

Usage: python3 tools/check_btf.py <kernel.bin | boot.img>

Prints the field offsets ghostlock relies on and flags any mismatch.
If everything matches, STRUCT_OFFSETS_6_12 is safe to use for this kernel.
"""

import struct
import sys

EXPECT = {
    ("task_struct", "prio"): 0x94,
    ("task_struct", "normal_prio"): 0x9C,
    ("task_struct", "sched_task_group"): 0x420,
    ("task_struct", "pi_lock"): 0x9EC,
    ("task_struct", "pi_waiters"): 0xA00,
    ("task_struct", "pi_top_task"): 0xA10,
    ("task_struct", "pi_blocked_on"): 0xA18,
    ("task_struct", "pid"): 0x708,
    ("task_struct", "tgid"): 0x70C,
    ("task_struct", "real_parent"): 0x718,
    ("task_struct", "cred"): 0x900,
    ("task_struct", "real_cred"): 0x8F8,
    ("task_struct", "comm"): 0x910,
    ("task_struct", "tasks"): 0x638,
    ("task_struct", "seccomp"): 0x9C8,
    ("task_struct", "size"): 5184,
    ("cred", "uid"): 8,
    ("cred", "securebits"): 40,
    ("selinux_state", "enforcing"): 0,
    ("selinux_state", "policycap"): 2,
}


def extract_kernel(path):
    data = open(path, "rb").read()
    if data[:8] == b"ANDROID!":
        kernel_size = struct.unpack_from("<I", data, 8)[0]
        return data[4096:4096 + kernel_size]
    return data


def load_btf(data):
    i = data.find(b"\x9f\xeb\x01\x00")
    if i < 0:
        sys.exit("no embedded BTF found")
    _m, _v, _f, hdr_len, type_off, type_len, str_off, str_len = \
        struct.unpack_from("<HBBIIIII", data, i)
    base = i + hdr_len
    tdata = data[base + type_off:base + type_off + type_len]
    sdata = data[base + str_off:base + str_off + str_len]

    def s(off):
        e = sdata.find(b"\x00", off)
        return sdata[off:e].decode("utf-8", "replace")

    types = [None]
    p = 0
    while p < len(tdata):
        name_off, info, size_type = struct.unpack_from("<III", tdata, p)
        vlen = info & 0xFFFF
        kind = (info >> 24) & 0x1F
        kflag = (info >> 31) & 1
        t = {"name": s(name_off), "kind": kind,
             "size_type": size_type, "members": []}
        p += 12
        if kind in (4, 5):  # STRUCT / UNION
            for _ in range(vlen):
                m_no, m_t, m_off = struct.unpack_from("<III", tdata, p)
                p += 12
                bit = (m_off & 0xFFFFFF) if kflag else m_off
                t["members"].append((s(m_no), bit // 8))
        elif kind == 1:
            p += 4
        elif kind == 6:
            p += 8 * vlen
        elif kind == 19:
            p += 12 * vlen
        elif kind == 13:
            p += 8 * vlen
        elif kind == 14:
            p += 4
        elif kind == 15:
            p += 12 * vlen
        elif kind == 17:
            p += 4
        types.append(t)
    return types


def main():
    data = extract_kernel(sys.argv[1])
    types = load_btf(data)
    structs = {}
    for t in types:
        if t and t["kind"] == 4 and t["name"] in ("task_struct", "cred", "selinux_state"):
            structs.setdefault(t["name"], t)

    bad = 0
    for (sname, field), want in sorted(EXPECT.items()):
        t = structs.get(sname)
        if not t:
            print(f"[??] {sname} not found in BTF")
            bad += 1
            continue
        if field == "size":
            got = t["size_type"]
        else:
            got = next((o for n, o in t["members"] if n == field), None)
        mark = "OK" if got == want else "DIFF"
        if got != want:
            bad += 1
        got_s = f"0x{got:X}" if isinstance(got, int) else str(got)
        want_s = f"0x{want:X}" if field != "size" else str(want)
        print(f"[{mark}] {sname}.{field:<18} btf={got_s:<10} expect={want_s}")

    print()
    if bad:
        print(f"{bad} mismatch(es): DO NOT use STRUCT_OFFSETS_6_12 blindly — "
              f"fill the per-kernel fields in kernel_offsets from the BTF values above.")
    else:
        print("All fields match STRUCT_OFFSETS_6_12 — safe to use.")


if __name__ == "__main__":
    main()
