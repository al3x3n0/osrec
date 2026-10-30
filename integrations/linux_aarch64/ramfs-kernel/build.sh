#!/bin/sh
# Runs inside osrec-kbuild-clang19. Minimal arm64 6.10.14: tinyconfig + syscalls, initramfs (ramfs), PL011 console, DWARF.
set -e
V=/Volumes/osrec-linux-6.10.14;S=$V/linux-6.10.14;O=$V/build-ramfs
M="make -C $S O=$O ARCH=arm64 LLVM=-19 CROSS_COMPILE=aarch64-linux-gnu- -j8"
$M tinyconfig > $O/tinyconfig.log 2>&1
ENABLE="EXPERT MEMFD_CREATE MULTIUSER BLK_DEV_INITRD BINFMT_ELF PRINTK TTY SERIAL_AMBA_PL011 SERIAL_AMBA_PL011_CONSOLE DEBUG_KERNEL DEBUG_INFO_DWARF5 ARM64_4K_PAGES ARM64_VA_BITS_48"
DISABLE="ARM64_VA_BITS_52 SHMEM TMPFS BLOCK MODULES"
for o in $ENABLE;do $S/scripts/config --file $O/.config --enable $o;done
for o in $DISABLE;do $S/scripts/config --file $O/.config --disable $o;done
$M olddefconfig > $O/olddefconfig.log 2>&1
for o in $ENABLE;do grep -q "^CONFIG_$o=y" $O/.config || { echo "missing CONFIG_$o" >> $O/config-check.txt; };done
for o in $DISABLE;do grep -q "^CONFIG_$o=y" $O/.config && echo "still set CONFIG_$o" >> $O/config-check.txt || true;done
grep -E "^CONFIG_(ARM64_VA_BITS|RAMFS|INITRAMFS|CC_VERSION_TEXT)" $O/.config >> $O/config-check.txt || true
$M Image > $O/image.log 2>&1
python3 $S/scripts/clang-tools/gen_compile_commands.py -d $O -o $O/compile_commands.json
clang-19 --version | head -1 > $O/compiler.txt
ls -l $O/arch/arm64/boot/Image $O/vmlinux >> $O/config-check.txt
echo built
