#!/bin/sh
# Build the experimental QEMU virt kernel after applying low-ttbr0-6.10.14.patch.
set -eu

if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
    echo "usage: $0 PATCHED_LINUX_SOURCE BUILD_DIR [BASE_CONFIG]" >&2
    exit 2
fi

recipe=$(cd "$(dirname "$0")" && pwd)
source=$(cd "$1" && pwd)
mkdir -p "$2"
build=$(cd "$2" && pwd)
base_config=${3:-"$recipe/../ramfs-kernel/config"}

if ! grep -q '^#define OSREC_KERNEL_SLOT' "$source/arch/arm64/include/asm/memory.h"; then
    echo 'apply low-ttbr0-6.10.14.patch to the pinned Linux source first' >&2
    exit 2
fi

if [ ! -f "$build/.config" ]; then
    cp "$base_config" "$build/.config"
fi
"$source/scripts/config" --file "$build/.config" \
    --disable ARM64_VA_BITS_48 --disable ARM64_VA_BITS_52 --enable ARM64_VA_BITS_39 \
    --disable UNMAP_KERNEL_AT_EL0 --disable ARM64_SW_TTBR0_PAN --disable ARM64_CNP \
    --disable EFI --disable KVM --disable HIBERNATION --disable KEXEC --disable KEXEC_FILE \
    --disable RELOCATABLE --disable RANDOMIZE_BASE \
    --enable BLOCK --enable VIRTIO_MENU --enable VIRTIO --enable VIRTIO_MMIO --enable VIRTIO_BLK \
    --enable EXT4_FS --enable SHMEM --enable TMPFS --enable IKCONFIG --enable EARLY_PRINTK \
    --enable FUTEX --enable RT_MUTEXES

kbuild() {
    make -C "$source" O="$build" ARCH=arm64 LLVM=-19 CROSS_COMPILE=aarch64-linux-gnu- \
        -j"${OSREC_KBUILD_JOBS:-8}" "$@"
}
kbuild olddefconfig
for config in ARM64_4K_PAGES ARM64_VA_BITS_39 VIRTIO_MMIO VIRTIO_BLK EXT4_FS SHMEM IKCONFIG FUTEX FUTEX_PI; do
    if ! grep -qx "CONFIG_$config=y" "$build/.config"; then
        echo "required config CONFIG_$config was not enabled" >&2
        exit 2
    fi
done
kbuild vmlinux Image
python3 "$source/scripts/clang-tools/gen_compile_commands.py" \
    -d "$build" -o "$build/compile_commands.json"
