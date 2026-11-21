ROOT := $(abspath ../..)
OUT ?= $(ROOT)/build/el0-macos
CC ?= cc

.PHONY: loader native-loader
.DELETE_ON_ERROR:
loader: $(OUT)/elf-loader
native-loader: $(OUT)/native-loader

$(OUT)/native-loader: native_loader.c
	mkdir -p "$(OUT)"
	$(CC) -arch arm64 -std=c11 -O2 -Wall -Wextra -Werror $< -o "$@"

$(OUT)/elf-loader: loader.c hypervisor.plist
	mkdir -p "$(OUT)"
	$(CC) -arch arm64 -std=c11 -O2 -Wall -Wextra -Werror loader.c -framework Hypervisor -o "$@"
	codesign -s - -f --entitlements hypervisor.plist "$@"
