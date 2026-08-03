# GhostLock for POCO F8 Ultra / REDMI K90 Pro Max — Global & Taiwan Variant (myron, WPMTWXM)

GhostLock (CVE-2026-43499) kernel exploit port for the **global/Taiwan firmware** of the
POCO F8 Ultra / REDMI K90 Pro Max (codename `myron`, Snapdragon 8 Elite Gen 5 / SM8850).

**Target**: HyperOS `OS3.0.6.0.WPMTWXM` — kernel
`6.12.23-android16-5-g5a0e85dd9db0-ab14499855-4k`

English summary below / 下方有英文摘要。

---

## 為什麼需要這個 port

同一支手機、同一個 codename,國際/臺灣版(WPMTWXM,即 POCO F8 Ultra)和大陸版(WPMCNXM)的核心**不是同一個 binary**:

| ROM | kernel release | 編譯時間 |
|---|---|---|
| 臺版 3.0.1.0.WPMTWXM | `...-ga5f232d1ead0-ab14083253-4k` | 2025-09-11 |
| 臺版 3.0.6.0.WPMTWXM | `...-g5a0e85dd9db0-ab14499855-4k` | 2025-11-26 |
| 陸版 3.0.306/308.WPMCNXM | `...-g16e473de48a3-abogki462654244-4k` | 2025-11-19 |

- 陸版追蹤 Google 官方 GKI 分支(`abogki*`),臺版是小米自己的整合分支
- 兩邊 git commit 不同、config 差 7 個選項,而且全部 `+pgo +bolt +lto` 編譯——
  任何程式碼差異都會把符號配置整個洗亂
- 實測:`init_task`/`init_cred` 差 0x10000,`selinux_state` 差 0x120c8(非固定位移)

GhostLock 這類 data-only exploit 需要該次編譯的精確位址,所以**所有為陸版算的
payload 在國際版全部無效**。這個 repo 就是補上國際版缺少的那張偏移表。

## 內容

- `offsets/myron_tw/offsets.h` — 臺版 3.0.6.0 的完整 target(給
  [JoinChang/ghostlock-oneplus](https://github.com/JoinChang/ghostlock-oneplus) 用)
- `scripts/device_step1.sh` — root 後的 ABL 備份 + unlock EFI 刷入腳本
- [Releases](../../releases) 裡有編好的 `ghostlock` binary(arm64)

## 已驗證的分析結果

1. **kallsyms 靜態提取正確性**:用 `_text` 為基準回讀 binary 交叉驗證——
   `init_task.comm="swapper"`、`init_cred.usage=4`、`init_uts_ns.release` 與 uname
   逐字元一致。不需要實機 root 就能取得可靠偏移。
2. **Struct 布局與陸版完全相同**(BTF 驗證):`task_struct` 5184 bytes、
   `cred@0x900`、`pi_blocked_on@0xA18` 等,與上游 `STRUCT_OFFSETS_6_12` 一致。
3. **棧配置可行性**:`futex_wait_requeue_pi`(frame 0x1c0,waiter@sp+0x80)和
   `core_sys_select`(frame 0x1b0,stack_fds@sp+0x18)與已驗證可行的
   Xiaomi 17 (pudding) 完全相同 → `PSELECT_SHIFT=0`。
4. `selinux_state.enforcing` 在 +0、`policycap` 在 +2,單 byte 寫入不會弄壞 policycap。
5. Rust ashmem → 只有 Path B(直接 PI write)可用,Path A (UMH) 不可用。

## 編譯

```sh
git clone https://github.com/JoinChang/ghostlock-oneplus.git
cd ghostlock-oneplus
cp /path/to/this-repo/offsets/myron_tw/offsets.h src/devices/myron_tw/offsets.h
# 在 src/devices/offsets.h 的 #include 清單加一行:
#   #include "myron_tw/offsets.h"
make NDK_CC=<你的 NDK>/toolchains/llvm/prebuilt/*/bin/aarch64-linux-android35-clang
```

## 使用

```sh
adb shell uname -r
# 必須是 6.12.23-android16-5-g5a0e85dd9db0-ab14499855-4k,否則程式會拒絕執行

adb push ghostlock /data/local/tmp/e
adb shell chmod 755 /data/local/tmp/e
adb shell /data/local/tmp/e
```

- 成功 → root shell + SELinux permissive(軟 root,重開機失效)
- 失敗重開機 = 沒搶到時序,重跑;連續 panic 可試 `PSELECT_SHIFT=-1` 等微調
- **不要讓裝置 OTA**——更新後核心更換,偏移即失效,且新版可能已修補漏洞

## 後續(BL 解鎖)

國際版機在 root 之後可以走 ABL 替換法解鎖(不需要官方名額):備份 abl_a/b →
刷入 unlock EFI → fastboot 刷出廠 ABL + spoof → 還原。出廠 ABL 從**自己手上的
臺版 3.0.1.0 ROM** 的 `abl.img` 取得(本 repo 不放小米專有韌體檔案)。
`scripts/device_step1.sh` 是這個流程的手機端部分。此流程不清使用者資料。

## 移植到其他區域版本(MIXM / EUXM / INXM…)

這個 repo 只覆蓋 `WPMTWXM`。小米每條區域分支各自編譯核心,偏移不能共用——
但**方法可以**。`tools/` 裡是我們實際用來產生臺版 target 的三支工具:

```sh
# 1. 從你的 OTA 包解出 boot.img(payload.bin 用 payload-dumper),然後:
python3 tools/extract_offsets.py boot.img          # 產生 OFFSETS_ENTRY + 交叉驗證
python3 tools/check_btf.py boot.img                # 驗證 struct 布局(決定 STRUCT_OFFSETS 能否沿用)
python3 tools/check_feasibility.py boot.img        # 驗證 pselect 棧配置(決定 SHIFT)
```

- `extract_offsets.py`:抽 kallsyms、算全部偏移,並回讀 `init_task.comm` /
  `init_cred.usage` / `init_uts_ns.release` 做交叉驗證——不通過就不要用
- `check_btf.py`:從核心內嵌 BTF 讀出 `task_struct`/`cred`/`selinux_state`
  欄位偏移,跟 `STRUCT_OFFSETS_6_12` 逐項比對
- `check_feasibility.py`:反組譯 `futex_wait_requeue_pi` 與 `core_sys_select`
  的幀配置,跟已知可行的核心比對(需要 `pip install capstone`)

三支都過了,你的版本大概率能打。歡迎把新區域版本的 target 發 PR 加進來。

## 致謝

- [Nebula Security](https://github.com/NebuSec/CyberMeowfia) — GhostLock 原始研究與 PoC
- [JoinChang/ghostlock-oneplus](https://github.com/JoinChang/ghostlock-oneplus) — 本 port 的基底
- 酷安社群的各種移植經驗

---

## English Summary

The global firmware of the POCO F8 Ultra (REDMI K90 Pro Max) ships a **different kernel build**
than the CN firmware (different branch, config, and PGO/BOLT layout), so all
community-published GhostLock offsets — computed on CN `ogki` kernels — miss on
global devices. This repo provides the missing target offsets for
`OS3.0.6.0.WPMTWXM` (`6.12.23-android16-5-g5a0e85dd9db0-ab14499855-4k`),
statically extracted from the official OTA package and cross-validated
(kallsyms + BTF + in-image reads), plus a prebuilt binary in Releases.
Struct layouts are identical to the CN build; only symbol addresses differ.
Stack-frame layout matches the verified-working Xiaomi 17 (pudding).

**Use only on your own device.** The vulnerability is public (kernelCTF-mandated
disclosure); this port exists so global-variant owners can root their own phones.

## 免責聲明 / Disclaimer

僅供自有裝置的授權安全研究。For authorized security research on your own devices only.
不保證任何結果,使用風險自負。
