MAKEFLAGS += --warn-undefined-variables
SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := help

BITS ?= 32
CC := $(or $(RISCV),$(HOME)/riscv/rv$(BITS)/bin/riscv$(BITS)-unknown-linux-gnu-gcc -static)
PLUGIN ?= libbb.so

# All targets are phony
.PHONY: $(shell egrep -o ^[a-zA-Z0-9_-]+: $(MAKEFILE_LIST) | sed 's/://')

fibo: #! Compile fibo.c
	$(CC) -o fibo fibo.c

format: #! Formats code
	(cd `git rev-parse --show-toplevel` && git diff -U0 --no-color HEAD ./examples | clang-format-diff -style "{BasedOnStyle: LLVM, IndentWidth: 4}" -i -p1)

run: fibo #! Run fibo
	../build/qemu-riscv$(BITS) fibo

run_trace: format fibo cvp_trace_plugin #! Generate trace for fibo
	../build/qemu-riscv$(BITS) -one-insn-per-tb -d plugin -plugin ./plugins/libtrace.so fibo

run_ecs_trace: format fibo ecs_trace_plugin #! Generate trace for fibo
	../build/qemu-riscv$(BITS) -one-insn-per-tb -d plugin -plugin ./plugins/libecstrace.so fibo

run_bbv: bbv_plugin #! Generate bbv
ifndef BIN
	$(error BIN is not set)
endif
	../build/qemu-x86_64 -one-insn-per-tb -d plugin -plugin ./plugins/libbbv.so $(BIN)

cvp_trace_plugin: #! Build trace plugin
	make libtrace.so -C ./plugins

ecs_trace_plugin: #! Build trace plugin
	make libecstrace.so -C ./plugins

bbv_plugin: #! Build bbv plugin
	make libbbv.so -C ./plugins

clean: #! Remove generated binaries
	rm -f fibo
	make clean -C ./plugins

help: #! Show this help
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'target:'
	@awk 'BEGIN {FS = ":.*?#! "} /^[a-zA-Z_-]+:.*?#! / {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)
