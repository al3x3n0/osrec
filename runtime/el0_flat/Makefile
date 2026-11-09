ROOT := $(abspath ../..)
CC ?= cc
OUT ?= $(ROOT)/build/el0-flat
CPPFLAGS += -I$(ROOT)/runtime/el0 -I$(ROOT)/runtime/el0_flat -I$(ROOT)/tools
CFLAGS := -O2 -g -std=c11 -Wall -Wextra -Werror -ffreestanding -fno-builtin -fno-stack-protector -fno-pic -fno-pie -mgeneral-regs-only -mno-outline-atomics -mbranch-protection=none
OBJECTS := $(addprefix $(OUT)/,gateway.o gateway-asm.o memory.o bytes.o emulate.o start.o gateway-test.o gateway-test-asm.o)
.PHONY: objects checkpoint observer program program-link
objects: $(OBJECTS)
observer: $(OUT)/flat-observe
$(OUT)/flat-observe: $(ROOT)/tools/el0_flat_observe.c | $(OUT)
	$(CC) -std=c11 -O2 -Wall -Wextra -Werror -static $< -o $@
$(OUT):
	mkdir -p $@
$(OUT)/%.o: %.c flat.h memory.h | $(OUT)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@
$(OUT)/gateway-asm.o: gateway.S | $(OUT)
	$(CC) $(CPPFLAGS) -c $< -o $@
$(OUT)/start.o: start.S | $(OUT)
	$(CC) $(CPPFLAGS) -c $< -o $@
$(OUT)/emulate.o: $(ROOT)/runtime/el0/emulate.c $(ROOT)/runtime/el0/el0.h | $(OUT)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@
$(OUT)/emulate-program.o: $(ROOT)/runtime/el0/emulate.c $(ROOT)/runtime/el0/el0.h | $(OUT)
	$(CC) $(CPPFLAGS) $(CFLAGS) -DOSREC_NATIVE -DOSREC_LOWERED -c $< -o $@
$(OUT)/lower-program.o: $(ROOT)/runtime/el0/lower.c $(ROOT)/runtime/el0/el0.h | $(OUT)
	$(CC) $(CPPFLAGS) $(CFLAGS) -DOSREC_LOWERED -c $< -o $@
$(OUT)/program.o: program.c program.h flat.h memory.h | $(OUT)
	$(CC) $(CPPFLAGS) $(CFLAGS) -DOSREC_LOWERED -c $< -o $@
$(OUT)/gateway-test.o: $(ROOT)/tests/el0_flat_gateway.c flat.h | $(OUT)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@
$(OUT)/gateway-test-asm.o: $(ROOT)/tests/el0_flat_gateway.S gateway.inc | $(OUT)
	$(CC) $(CPPFLAGS) -c $< -o $@
checkpoint: objects
	test -n "$(IMAGE)"
	cd "$(IMAGE)" && $(CC) $(CPPFLAGS) $(CFLAGS) -c $(ROOT)/tools/el0_flat_umask.c -o driver.o
	cd "$(IMAGE)" && $(CC) $(CPPFLAGS) $(CFLAGS) -c image.c -o image.o
	cd "$(IMAGE)" && $(CC) $(CPPFLAGS) -c image.S -o payload.o
	cd "$(IMAGE)" && $(CC) $(CPPFLAGS) -c kernel.S -o kernel.o
	cd "$(IMAGE)" && $(CC) -nostdlib -static -Wl,--no-undefined,--build-id=none,-e,_start,-Ttext-segment=0x40200000,-z,noexecstack,-Map,checkpoint.map $(OBJECTS) driver.o image.o payload.o kernel.o -o checkpoint
PROGRAM_OBJECTS := $(addprefix $(OUT)/,gateway.o gateway-asm.o memory.o bytes.o emulate-program.o lower-program.o program.o start.o)
ifneq ($(strip $(IMAGE)),)
program program-link: $(IMAGE)/checkpoint
$(IMAGE)/image.o: $(IMAGE)/image.c program.h memory.h
	cd "$(IMAGE)" && $(CC) $(CPPFLAGS) $(CFLAGS) -c image.c -o image.o
$(IMAGE)/payload.o: $(IMAGE)/state.S $(wildcard $(IMAGE)/*.bin)
	cd "$(IMAGE)" && $(CC) $(CPPFLAGS) -c state.S -o payload.o
$(IMAGE)/program-asm.o: $(IMAGE)/program.S gateway.inc
	cd "$(IMAGE)" && $(CC) $(CPPFLAGS) -c program.S -o program-asm.o
$(IMAGE)/text.o: $(IMAGE)/text.c program.h
	cd "$(IMAGE)" && $(CC) $(CPPFLAGS) $(CFLAGS) -c text.c -o text.o
$(IMAGE)/checkpoint: $(PROGRAM_OBJECTS) $(addprefix $(IMAGE)/,image.o payload.o program-asm.o text.o)
	cd "$(IMAGE)" && $(CC) -fuse-ld=lld -nostdlib -static -Wl,--no-undefined,--build-id=none,-e,_start,--image-base=0x40200000,-z,noexecstack,-Map,checkpoint.map $(PROGRAM_OBJECTS) image.o payload.o program-asm.o text.o -o checkpoint
else
program program-link:
	@echo 'IMAGE must name an exported checkpoint directory'; exit 1
endif
