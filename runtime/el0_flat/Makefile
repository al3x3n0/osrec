ROOT := $(abspath ../..)
CC ?= cc
OUT ?= $(ROOT)/build/el0-flat
CPPFLAGS += -I$(ROOT)/runtime/el0 -I$(ROOT)/runtime/el0_flat -I$(ROOT)/tools
IMAGE_CONFIG := $(realpath $(wildcard $(IMAGE)/runtime-config.h))
ifneq ($(IMAGE_CONFIG),)
CPPFLAGS += -include $(IMAGE_CONFIG)
endif
CFLAGS := -O2 -g -std=c11 -Wall -Wextra -Werror -ffreestanding -fno-builtin -fno-stack-protector -fno-pic -fno-pie -mgeneral-regs-only -mno-outline-atomics -mbranch-protection=none
ifeq ($(LTO),1)
CFLAGS += -flto
# Preserve the flat_* model/debug ABI even when LTO folds its C references.
LINKFLAGS += -flto '-Wl,--undefined-glob=flat_*'
endif
ifneq ($(IMAGE_CONFIG),)
ifneq ($(findstring OSREC_FLAT_WHOLE_KERNEL 1,$(shell cat "$(IMAGE_CONFIG)")),)
WHOLE_KERNEL_LINKER_SCRIPT := $(ROOT)/runtime/el0_flat/whole-kernel.ld
LINKFLAGS += -Wl,-T,$(WHOLE_KERNEL_LINKER_SCRIPT)
endif
endif
ifeq ($(PROFILE),1)
CPPFLAGS += -DOSREC_FLAT_PROFILE
endif
.DEFAULT_GOAL := program
.PHONY: observer program check-gateway FORCE
FORCE:
observer: $(OUT)/flat-observe
$(OUT)/flat-observe: $(ROOT)/tools/el0_flat_observe.c | $(OUT)
	$(CC) -std=c11 -O2 -Wall -Wextra -Werror -static $< -o $@
$(OUT):
	mkdir -p $@
$(OUT)/build-config: FORCE | $(OUT)
	@printf '%s\n' "$(CC)" "$(CPPFLAGS)" "$(CFLAGS)" "$(LINKFLAGS)" > "$@.tmp"
	@if test -n "$(IMAGE_CONFIG)"; then cat "$(IMAGE_CONFIG)" >> "$@.tmp"; fi
	@if test -f "$@"; then \
	  if cmp -s "$@.tmp" "$@"; then rm "$@.tmp"; \
	  else rm "$@.tmp"; echo 'Build options changed: use a fresh OUT directory to avoid mixing runtime modes.' >&2; exit 1; fi; \
	else mv "$@.tmp" "$@"; fi
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
$(OUT)/program.o: program.c program.h flat.h memory.h admission.h compare.h profiling.h translation_watch.h | $(OUT)
	$(CC) $(CPPFLAGS) $(CFLAGS) -DOSREC_LOWERED -c $< -o $@
$(OUT)/gateway-test.o: $(ROOT)/tests/el0_flat_gateway.c flat.h | $(OUT)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@
$(OUT)/gateway-test-asm.o: $(ROOT)/tests/el0_flat_gateway.S gateway.inc | $(OUT)
	$(CC) $(CPPFLAGS) -c $< -o $@
$(OUT)/gateway-test-main.o: $(ROOT)/tests/el0_flat_gateway_main.c | $(OUT)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@
GATEWAY_TEST_OBJECTS := $(addprefix $(OUT)/,gateway.o gateway-asm.o bytes.o start.o gateway-test.o gateway-test-asm.o gateway-test-main.o)
$(OUT)/gateway-check: $(GATEWAY_TEST_OBJECTS)
	$(CC) $(LINKFLAGS) -fuse-ld=lld -nostdlib -static -Wl,--no-undefined,--build-id=none,-e,_start,-z,noexecstack $^ -o $@
check-gateway: $(OUT)/gateway-check
	$(OUT)/gateway-check
PROGRAM_OBJECTS := $(addprefix $(OUT)/,gateway.o gateway-asm.o memory.o bytes.o emulate-program.o lower-program.o program.o start.o)
ELF_IMAGE_BASE := 0x40200000
PROGRAM_SOURCE := $(IMAGE)/program.S
ifeq ($(MACOS_NATIVE),1)
ELF_IMAGE_BASE := 0x7002000000
CFLAGS += -ffixed-x18
LINKFLAGS += -Wl,-z,separate-code,-z,max-page-size=16384
LLVM_OBJDUMP ?= $(if $(findstring /,$(firstword $(CC))),$(dir $(firstword $(CC)))llvm-objdump,llvm-objdump)
PROGRAM_SOURCE := $(OUT)/program-macos.S
$(PROGRAM_SOURCE): $(IMAGE)/program.S $(IMAGE)/manifest.json $(IMAGE)/initial.bin $(ROOT)/tools/el0_macos_x18.py | $(OUT)
	python3 "$(ROOT)/tools/el0_macos_x18.py" --image "$(IMAGE)" --out "$@" --objdump "$(LLVM_OBJDUMP)"
endif
$(PROGRAM_OBJECTS): $(OUT)/build-config $(IMAGE_CONFIG) validation.h
ifneq ($(strip $(IMAGE)),)
$(addprefix $(IMAGE)/,image.o payload.o program-asm.o text.o): $(OUT)/build-config $(IMAGE_CONFIG)
program: $(IMAGE)/checkpoint
ifeq ($(PRETRANSLATE),1)
.PHONY: pretranslated
program: pretranslated
pretranslated: $(IMAGE)/checkpoint
	python3 $(ROOT)/tools/pretranslate_el0_image.py --image "$(IMAGE)" $(if $(filter 1,$(MERGE_SEGMENTS)),--merge-segments)
endif
$(IMAGE)/image.o: $(IMAGE)/image.c program.h memory.h
	cd "$(IMAGE)" && $(CC) $(CPPFLAGS) $(CFLAGS) -c image.c -o image.o
$(IMAGE)/payload.o: $(IMAGE)/state.S $(wildcard $(IMAGE)/*.bin)
	cd "$(IMAGE)" && $(CC) $(CPPFLAGS) -c state.S -o payload.o
$(IMAGE)/program-asm.o: $(PROGRAM_SOURCE) gateway.inc
	cd "$(IMAGE)" && $(CC) $(CPPFLAGS) -c "$(abspath $(PROGRAM_SOURCE))" -o program-asm.o
$(IMAGE)/text.o: $(IMAGE)/text.c program.h
	cd "$(IMAGE)" && $(CC) $(CPPFLAGS) $(CFLAGS) -c text.c -o text.o
$(IMAGE)/checkpoint: $(PROGRAM_OBJECTS) $(addprefix $(IMAGE)/,image.o payload.o program-asm.o text.o) $(WHOLE_KERNEL_LINKER_SCRIPT)
	cd "$(IMAGE)" && $(CC) $(LINKFLAGS) -fuse-ld=lld -nostdlib -static -Wl,--no-undefined,--build-id=none,-e,_start,--image-base=$(ELF_IMAGE_BASE),-z,noexecstack,-Map,checkpoint.map $(PROGRAM_OBJECTS) image.o payload.o program-asm.o text.o -o checkpoint
else
program:
	@echo 'IMAGE must name an exported checkpoint directory'; exit 1
endif
