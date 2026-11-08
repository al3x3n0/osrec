#!/bin/sh
# Runs inside osrec-kbuild-clang19. The whole 6.10.14 kernel under the running kernel's own config (linuxkit),
# with clang-19 and DWARF5: every translation unit's object and compile command, for whole-TU source slices.
# Compiler-dependent options follow from clang (olddefconfig); BTF is dropped (no pahole) — it does not change
# layouts, which are checked against the live kernel's BTF separately. Only vmlinux is built (no modules).
set -e
# The source volume is read-only (pinned): output goes to $O, a writable case-sensitive volume (default /kbuild).
V=/Volumes/osrec-linux-6.10.14;S=$V/linux-6.10.14;O=${O:-/kbuild}
mkdir -p $O
cp $V/linuxkit.config $O/.config
M="make -C $S O=$O ARCH=arm64 LLVM=-19 CROSS_COMPILE=aarch64-linux-gnu- -j8"
$S/scripts/config --file $O/.config --disable DEBUG_INFO_BTF --disable DEBUG_INFO_BTF_MODULES \
  --disable DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT --enable DEBUG_INFO_DWARF5
$M olddefconfig > $O/olddefconfig.log 2>&1
grep -v '^#' $V/linuxkit.config | sort > $O/config-live.txt;grep -v '^#' $O/.config | sort > $O/config-build.txt
diff $O/config-live.txt $O/config-build.txt > $O/config-delta.txt || true
$M vmlinux > $O/vmlinux.log 2>&1
python3 $S/scripts/clang-tools/gen_compile_commands.py -d $O -o $O/compile_commands.json
clang-19 --version | head -1 > $O/compiler.txt
ls -l $O/vmlinux > $O/done.txt
echo built
