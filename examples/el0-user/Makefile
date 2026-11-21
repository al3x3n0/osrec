ROOT := $(abspath ../..)
OUT ?= $(ROOT)/build/el0-user
ifeq ($(origin CC),default)
CC := clang
endif
FLAGS := --target=aarch64-none-elf -mcpu=cortex-a53 -mgeneral-regs-only -mstrict-align -O2 -ffreestanding -fno-builtin -fno-stack-protector -fno-unwind-tables -Wall -Wextra -Werror
.PHONY: all ipc file-handoff
all: $(OUT)/program
ipc: $(OUT)/ipc
file-handoff: $(OUT)/file-handoff
$(OUT):
	mkdir -p $@
$(OUT)/ipc $(OUT)/file-handoff: FLAGS += -ffixed-x18
$(OUT)/program $(OUT)/ipc $(OUT)/file-handoff: $(OUT)/%: start.S %.c syscall.h | $(OUT)
	$(CC) $(FLAGS) -nostdlib -static -fuse-ld=lld -Wl,--no-undefined,-e,_start,-z,max-page-size=4096 $(filter-out %.h,$^) -o $@
