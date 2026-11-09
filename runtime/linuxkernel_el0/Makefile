ROOT := $(abspath ../..)
OUT ?= $(ROOT)/build/liblinuxkernel-el0
CC ?= cc
AR ?= ar
CFLAGS ?= -O2 -g
CPPFLAGS += -I$(ROOT)/include -I$(ROOT)/runtime/el0 -I$(ROOT)/runtime/linuxkernel_el0 -DOSREC_LOWERED -DOSREC_NATIVE
EDGEFLAGS := -std=c11 -fPIC -Wall -Wextra -Werror -fno-builtin
ifeq ($(shell uname -m),aarch64)
EDGEFLAGS += -mgeneral-regs-only -mbranch-protection=none
endif
OBJECTS := $(OUT)/entry.o $(OUT)/emulate.o $(OUT)/veneer.o $(OUT)/native.o $(OUT)/lower.o

.PHONY: all check check-native check-standalone-host native-run checkpoint embedded-checkpoint standalone-checkpoint clean install
all: $(OUT)/liblinuxkernel-el0.a $(OUT)/liblinuxkernel-el0.so

$(OUT):
	mkdir -p $@
$(OUT)/entry.o: entry.c internal.h $(ROOT)/include/osrec/linuxkernel_el0.h $(ROOT)/runtime/el0/el0.h | $(OUT)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(EDGEFLAGS) -c $< -o $@
$(OUT)/emulate.o: $(ROOT)/runtime/el0/emulate.c $(ROOT)/runtime/el0/el0.h | $(OUT)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(EDGEFLAGS) -c $< -o $@
$(OUT)/native.o: native.c native_lower.h internal.h $(ROOT)/include/osrec/linuxkernel_el0_native.h | $(OUT)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(EDGEFLAGS) -c $< -o $@
$(OUT)/lower.o: $(ROOT)/runtime/el0/lower.c native_lower.h | $(OUT)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(EDGEFLAGS) -c $< -o $@
$(OUT)/veneer.o: veneer.S | $(OUT)
	$(CC) $(CPPFLAGS) $(CFLAGS) -fPIC -c $< -o $@
$(OUT)/liblinuxkernel-el0.a: $(OBJECTS)
	$(AR) rcs $@ $^
$(OUT)/liblinuxkernel-el0.so: $(OBJECTS)
	$(CC) -shared -Wl,-z,defs -Wl,-Bsymbolic-functions -Wl,-soname,liblinuxkernel-el0.so -o $@ $^

$(OUT)/checkpoint-archive: $(ROOT)/tests/linuxkernel_el0_host.c $(OUT)/liblinuxkernel-el0.a
	$(CC) $(CPPFLAGS) $(CFLAGS) $(EDGEFLAGS) -pthread $< $(OUT)/liblinuxkernel-el0.a -o $@
$(OUT)/checkpoint-shared: $(ROOT)/tests/linuxkernel_el0_host.c $(OUT)/liblinuxkernel-el0.so
	$(CC) $(CPPFLAGS) $(CFLAGS) $(EDGEFLAGS) -pthread $< -L$(OUT) -llinuxkernel-el0 -Wl,-rpath,'$$ORIGIN' -o $@
$(OUT)/native-run: $(ROOT)/tools/linuxkernel_native_run.c $(OUT)/liblinuxkernel-el0.a
	$(CC) $(CPPFLAGS) $(CFLAGS) $(EDGEFLAGS) $< $(OUT)/liblinuxkernel-el0.a -o $@
native-run: $(OUT)/native-run
$(OUT)/user-checkpoint: $(ROOT)/tools/linuxkernel_checkpoint.c $(ROOT)/tools/linuxkernel_checkpoint_report.h $(OUT)/liblinuxkernel-el0.a
	$(CC) $(CPPFLAGS) $(CFLAGS) $(EDGEFLAGS) $(ROOT)/tools/linuxkernel_checkpoint.c $(OUT)/liblinuxkernel-el0.a -o $@
$(OUT)/user-checkpoint-shared: $(ROOT)/tools/linuxkernel_checkpoint.c $(ROOT)/tools/linuxkernel_checkpoint_report.h $(OUT)/liblinuxkernel-el0.so
	$(CC) $(CPPFLAGS) $(CFLAGS) $(EDGEFLAGS) $(ROOT)/tools/linuxkernel_checkpoint.c -L$(OUT) -llinuxkernel-el0 -Wl,-rpath,'$$ORIGIN' -o $@
checkpoint: $(OUT)/user-checkpoint $(OUT)/user-checkpoint-shared
embedded-checkpoint: standalone-checkpoint

# A separate object tree prevents mixing libc/TLS and freestanding objects.
STANDALONE := $(OUT)/standalone
STANDALONE_FLAGS := $(CFLAGS) -std=c11 -Wall -Wextra -Werror -ffreestanding -fno-builtin -fno-stack-protector -fno-pic -fno-pie -fno-unwind-tables -fno-asynchronous-unwind-tables -mgeneral-regs-only -mbranch-protection=none -mno-outline-atomics
STANDALONE_CPPFLAGS := $(CPPFLAGS) -DOSREC_FREESTANDING -I$(ROOT)/tools
STANDALONE_LINK_FLAGS := -nostdlib -static -Wl,--no-undefined,--build-id=none,-e,_start,-z,noexecstack,-Ttext-segment=0x600000000000
STANDALONE_OBJECTS := $(addprefix $(STANDALONE)/,entry.o emulate.o lower.o native.o veneer.o standalone.o standalone_start.o)
$(STANDALONE):
	mkdir -p $@
$(STANDALONE)/%.o: %.c standalone.h internal.h | $(STANDALONE)
	$(CC) $(STANDALONE_CPPFLAGS) $(STANDALONE_FLAGS) -c $< -o $@
$(STANDALONE)/%.o: %.S | $(STANDALONE)
	$(CC) $(STANDALONE_CPPFLAGS) -c $< -o $@
$(STANDALONE)/emulate.o: $(ROOT)/runtime/el0/emulate.c $(ROOT)/runtime/el0/el0.h | $(STANDALONE)
	$(CC) $(STANDALONE_CPPFLAGS) $(STANDALONE_FLAGS) -c $< -o $@
$(STANDALONE)/lower.o: $(ROOT)/runtime/el0/lower.c native_lower.h | $(STANDALONE)
	$(CC) $(STANDALONE_CPPFLAGS) $(STANDALONE_FLAGS) -c $< -o $@
standalone-checkpoint: $(STANDALONE_OBJECTS)
	test -n "$(IMAGE)"
	cd "$(IMAGE)" && $(CC) $(STANDALONE_CPPFLAGS) $(STANDALONE_FLAGS) -c $(ROOT)/tools/linuxkernel_embedded_main.c -o checkpoint-main.o
	cd "$(IMAGE)" && $(CC) $(STANDALONE_CPPFLAGS) $(STANDALONE_FLAGS) -c image.c -o image-descriptor.o
	cd "$(IMAGE)" && $(CC) $(STANDALONE_CPPFLAGS) -c image.S -o image-payload.o
	cd "$(IMAGE)" && $(CC) $(STANDALONE_LINK_FLAGS) -Wl,-Map,user-checkpoint.map checkpoint-main.o image-descriptor.o image-payload.o $(STANDALONE_OBJECTS) -o user-checkpoint
$(STANDALONE)/host-check: $(ROOT)/tests/linuxkernel_standalone_host.c $(STANDALONE)/standalone.o $(STANDALONE)/standalone_start.o
	$(CC) $(STANDALONE_CPPFLAGS) $(STANDALONE_FLAGS) $(STANDALONE_LINK_FLAGS) $^ -o $@
check-standalone-host: $(STANDALONE)/host-check
	$(STANDALONE)/host-check
$(OUT)/native-check: $(ROOT)/tests/linuxkernel_native_host.c $(OUT)/liblinuxkernel-el0.a
	$(CC) $(CPPFLAGS) $(CFLAGS) $(EDGEFLAGS) $< $(OUT)/liblinuxkernel-el0.a -o $@
$(OUT)/native-check-shared: $(ROOT)/tests/linuxkernel_native_host.c $(OUT)/liblinuxkernel-el0.so
	$(CC) $(CPPFLAGS) $(CFLAGS) $(EDGEFLAGS) $< -L$(OUT) -llinuxkernel-el0 -Wl,-rpath,'$$ORIGIN' -o $@
check-native: $(OUT)/native-check $(OUT)/native-check-shared
	test -n "$(PACKAGE)"
	test -n "$(ORACLE)"
	$(OUT)/native-check "$(PACKAGE)" "$(ORACLE)"
	$(OUT)/native-check-shared "$(PACKAGE)" "$(ORACLE)"
check: $(OUT)/checkpoint-archive $(OUT)/checkpoint-shared
	$(OUT)/checkpoint-archive
	$(OUT)/checkpoint-shared

PREFIX ?= /usr/local
install: all
	install -d $(DESTDIR)$(PREFIX)/lib $(DESTDIR)$(PREFIX)/include/osrec
	install -m 644 $(OUT)/liblinuxkernel-el0.a $(OUT)/liblinuxkernel-el0.so $(DESTDIR)$(PREFIX)/lib/
	install -m 644 $(ROOT)/include/osrec/linuxkernel_el0.h $(ROOT)/include/osrec/linuxkernel_el0_native.h $(ROOT)/runtime/el0/el0.h $(DESTDIR)$(PREFIX)/include/osrec/

clean:
	$(RM) $(OBJECTS) $(OUT)/liblinuxkernel-el0.a $(OUT)/liblinuxkernel-el0.so $(OUT)/checkpoint-archive $(OUT)/checkpoint-shared $(OUT)/native-run $(OUT)/native-check $(OUT)/native-check-shared $(OUT)/user-checkpoint $(OUT)/user-checkpoint-shared
	$(RM) $(STANDALONE_OBJECTS) $(STANDALONE)/host-check
