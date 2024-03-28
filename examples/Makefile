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

run_trace: format fibo trace_plugin #! Generate trace for fibo
	../build/qemu-riscv$(BITS) -one-insn-per-tb -d plugin -plugin ./plugins/libtrace.so fibo

trace_plugin: #! Build trace plugin
	make libtrace.so -C ./plugins

clean: #! Remove generated binaries
	rm -f fibo
	make clean -C ./plugins

help: #! Show this help
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'target:'
	@awk 'BEGIN {FS = ":.*?#! "} /^[a-zA-Z_-]+:.*?#! / {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)
