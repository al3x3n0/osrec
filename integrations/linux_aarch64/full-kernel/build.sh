#!/bin/sh
# Runs inside osrec-kbuild-clang19. The whole 6.10.14 kernel under the running kernel's own config (linuxkit),
# with clang-19 and DWARF5: every translation unit's object and compile command, for whole-TU source slices.
# Compiler-dependent options follow from clang (olddefconfig); BTF is dropped (no pahole) — it does not change
# layouts, which are checked against the live kernel's BTF separately. vmlinux and Image are built (no modules).
# VA_BITS=39 selects 39-bit virtual addresses (3-level tables): the kernel's address space is then one 512 GiB
# window that a user-space executable checkpoint can relocate by a single offset.
# LAYOUT_VARIABLES=1 builds with the virtual layout as runtime variables (layout_variables.py: overlay headers placed
# first on the include path; the pinned tree is not modified), so relocating the kernel's address space is data only.
set -e
# The source volume is read-only (pinned): output goes to $O, a writable case-sensitive volume (default /kbuild).
V=/Volumes/osrec-linux-6.10.14;S=$V/linux-6.10.14;O=${O:-/kbuild}
mkdir -p $O
cp $V/linuxkit.config $O/.config
M="make -C $S O=$O ARCH=arm64 LLVM=-19 CROSS_COMPILE=aarch64-linux-gnu- -j8"
DIR=$(cd "$(dirname "$0")" && pwd)
if [ -n "$LAYOUT_VARIABLES" ]; then
  python3 $DIR/layout_variables.py $S $O/osrec-overlay
  LI="-I$O/osrec-overlay/arch/arm64/include -I$S/arch/arm64/include -I$O/arch/arm64/include/generated -I$S/include -I$O/include \
-I$S/arch/arm64/include/uapi -I$O/arch/arm64/include/generated/uapi -I$S/include/uapi -I$O/include/generated/uapi \
-include $S/include/linux/compiler-version.h -include $S/include/linux/kconfig.h"
fi
mk(){ if [ -n "$LAYOUT_VARIABLES" ]; then $M "LINUXINCLUDE=$LI" "$@"; else $M "$@"; fi; }
$S/scripts/config --file $O/.config --disable DEBUG_INFO_BTF --disable DEBUG_INFO_BTF_MODULES \
  --disable DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT --enable DEBUG_INFO_DWARF5
if [ -n "$VA_BITS" ]; then
  $S/scripts/config --file $O/.config --disable ARM64_VA_BITS_48 --disable ARM64_VA_BITS_52 \
    --enable ARM64_VA_BITS_$VA_BITS --set-val ARM64_VA_BITS $VA_BITS
fi
mk olddefconfig > $O/olddefconfig.log 2>&1
grep -v '^#' $V/linuxkit.config | sort > $O/config-live.txt;grep -v '^#' $O/.config | sort > $O/config-build.txt
diff $O/config-live.txt $O/config-build.txt > $O/config-delta.txt || true
mk vmlinux Image > $O/vmlinux.log 2>&1
python3 $S/scripts/clang-tools/gen_compile_commands.py -d $O -o $O/compile_commands.json
clang-19 --version | head -1 > $O/compiler.txt
ls -l $O/vmlinux > $O/done.txt
echo built
