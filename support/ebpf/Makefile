SHELL ?= bash
BPF_CLANG ?= clang-16
BPF_LINK ?= llvm-link-16
LLC ?= llc-16

DEBUG_FLAGS = -DOPTI_DEBUG -g

# Detect native architecture and translate to GOARCH.
NATIVE_ARCH := $(shell uname -m)
ifeq ($(NATIVE_ARCH),x86_64)
NATIVE_ARCH := amd64
else ifneq (,$(filter $(NATIVE_ARCH),aarch64 arm64))
NATIVE_ARCH := arm64
else
$(error Unsupported architecture: $(NATIVE_ARCH))
endif

# Valid values are: amd64, arm64.
TARGET_ARCH ?= $(NATIVE_ARCH)

TRACER_NAME ?= tracer.ebpf.$(TARGET_ARCH)

ifeq ($(TARGET_ARCH),arm64)
TARGET_FLAGS = -D__aarch64__ -D__aarch64
else
TARGET_FLAGS = -D__x86_64__ -D__x86_64
endif

FLAGS=$(TARGET_FLAGS) \
	-target bpf \
	-fno-jump-tables \
	-nostdlib \
	-nostdinc \
	-ffreestanding \
	-O2 -emit-llvm -c $< \
	-Wall -Wextra -Werror \
	-Wno-address-of-packed-member \
	-Wno-unused-label \
	-Wno-unused-parameter \
	-Wno-sign-compare \
	-fno-stack-protector

SRCS := $(wildcard *.ebpf.c)
OBJS := $(SRCS:.c=.$(TARGET_ARCH).o)

.DEFAULT_GOAL := all

all: $(TRACER_NAME)

debug: TARGET_FLAGS+=$(DEBUG_FLAGS)
debug: all

amd64:
	$(MAKE) TARGET_ARCH=amd64 all

arm64:
	$(MAKE) TARGET_ARCH=arm64 all

debug-amd64:
	$(MAKE) TARGET_ARCH=amd64 debug

debug-arm64:
	$(MAKE) TARGET_ARCH=arm64 debug

errors.h: ../../tools/errors-codegen/errors.json
	go run ../../tools/errors-codegen/main.go bpf $@

%.ebpf.c: errors.h ;

%.ebpf.$(TARGET_ARCH).o: %.ebpf.c
	$(BPF_CLANG) $(FLAGS) -o $@

$(TRACER_NAME): $(OBJS)
	$(BPF_LINK) $^ -o - | $(LLC) -march=bpf -mcpu=v2 -filetype=obj -o $@
	@./print_instruction_count.sh $@

baseline: $(TRACER_NAME)
	cp $< $(TRACER_NAME).$@

bloatcheck: $(TRACER_NAME)
	python3 bloat-o-meter $(TRACER_NAME).baseline $(TRACER_NAME)

clean:
	rm -f *.o
