#!/system/bin/sh
# MYRON 臺版 — 在 ghostlock root shell 內執行(階段一:備份 ABL + 刷 unlock EFI)
# 用法:ghostlock 拿到 root shell 後,sh /data/local/tmp/device_step1.sh

set -e
cd /data/local/tmp

echo "[1/3] 備份 abl_a / abl_b ..."
dd if=/dev/block/by-name/abl_a of=/data/local/tmp/abl_a_backup.img
dd if=/dev/block/by-name/abl_b of=/data/local/tmp/abl_b_backup.img
chmod 644 /data/local/tmp/abl_a_backup.img /data/local/tmp/abl_b_backup.img
ls -l /data/local/tmp/abl_*_backup.img

echo ""
echo "[!] 備份完成。請到 Mac 開【第二個終端機】執行:"
echo "    adb pull /data/local/tmp/abl_a_backup.img"
echo "    adb pull /data/local/tmp/abl_b_backup.img"
echo "    adb push gbl_efi_unlock.efi /data/local/tmp/"
echo "    確認無誤後,回到這個 root shell 按 Enter 繼續"
read dummy

echo "[2/3] 刷入 gbl_efi_unlock.efi -> efisp ..."
dd if=/data/local/tmp/gbl_efi_unlock.efi of=/dev/block/by-name/efisp

echo "[3/3] 重開機進 bootloader ..."
echo "[!] 接下來換 Mac 端 fastboot 流程(見 README 階段三)"
reboot bootloader
