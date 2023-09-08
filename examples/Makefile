MAKEFLAGS += --warn-undefined-variables
SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := help

CC := $(or $(RISCV),$(HOME)/riscv/bin/riscv32-unknown-elf-gcc)
PLUGIN ?= libbb.so

# All targets are phony
.PHONY: $(shell egrep -o ^[a-zA-Z0-9_-]+: $(MAKEFILE_LIST) | sed 's/://')

fibo: #! Compile fibo.c
	$(CC) -o fibo fibo.c

format: #! Formats code
	(cd `git rev-parse --show-toplevel` && git diff -U0 --no-color HEAD ./examples | clang-format-diff -style "{BasedOnStyle: LLVM, IndentWidth: 4}" -i -p1)

run: fibo #! Run fibo
	../build/qemu-riscv32 fibo

run_plugin: fibo #! Run fibo with plugin (e.g. make run_plugin PLUGIN=libinsn.so)
	../build/qemu-riscv32 -d plugin -plugin ../build/tests/plugin/$(PLUGIN) fibo

plugins: fibo #! Build our plugins
	make -C ./plugins
	../build/qemu-riscv32 -d plugin -plugin ./plugins/libexeclog.so fibo

clean: #! Remove generated binaries
	rm -f fibo
	make clean -C ./plugins

help: #! Show this help
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'target:'
	@awk 'BEGIN {FS = ":.*?#! "} /^[a-zA-Z_-]+:.*?#! / {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)
