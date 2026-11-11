ROOT := $(abspath ../..)
CC ?= cc
OUT ?= $(ROOT)/build/el0-flat
CPPFLAGS += -I$(ROOT)/runtime/el0 -I$(ROOT)/runtime/el0_flat -I$(ROOT)/tools
CFLAGS := -O2 -g -std=c11 -Wall -Wextra -Werror -ffreestanding -fno-builtin -fno-stack-protector -fno-pic -fno-pie -mgeneral-regs-only -mno-outline-atomics -mbranch-protection=none
.DEFAULT_GOAL := program
.PHONY: observer program check-gateway
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
$(OUT)/gateway-test-main.o: $(ROOT)/tests/el0_flat_gateway_main.c | $(OUT)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@
GATEWAY_TEST_OBJECTS := $(addprefix $(OUT)/,gateway.o gateway-asm.o bytes.o start.o gateway-test.o gateway-test-asm.o gateway-test-main.o)
$(OUT)/gateway-check: $(GATEWAY_TEST_OBJECTS)
	$(CC) -fuse-ld=lld -nostdlib -static -Wl,--no-undefined,--build-id=none,-e,_start,-z,noexecstack $^ -o $@
check-gateway: $(OUT)/gateway-check
	$(OUT)/gateway-check
PROGRAM_OBJECTS := $(addprefix $(OUT)/,gateway.o gateway-asm.o memory.o bytes.o emulate-program.o lower-program.o program.o start.o)
ifneq ($(strip $(IMAGE)),)
program: $(IMAGE)/checkpoint
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
program:
	@echo 'IMAGE must name an exported checkpoint directory'; exit 1
endif
