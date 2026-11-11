ROOT := $(abspath ../..)
OUT ?= $(ROOT)/build/el0-user
ifeq ($(origin CC),default)
CC := clang
endif
FLAGS := --target=aarch64-none-elf -mcpu=cortex-a53 -mgeneral-regs-only -mstrict-align -O2 -ffreestanding -fno-builtin -fno-stack-protector -fno-unwind-tables -Wall -Wextra -Werror
.PHONY: all
all: $(OUT)/program
$(OUT):
	mkdir -p $@
$(OUT)/program: start.S program.c | $(OUT)
	$(CC) $(FLAGS) -nostdlib -static -fuse-ld=lld -Wl,--no-undefined,-e,_start,-z,max-page-size=4096 $^ -o $@
