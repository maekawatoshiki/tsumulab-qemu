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

run: fibo #! Run fibo
	../build/qemu-riscv32 fibo

run_plugin: fibo #! Run fibo with plugin (e.g. make run_plugin PLUGIN=libinsn.so)
	../build/qemu-riscv32 -d plugin -plugin ../build/tests/plugin/$(PLUGIN) fibo

clean: #! Remove generated binaries
	rm -f fibo

help: #! Show this help
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'target:'
	@awk 'BEGIN {FS = ":.*?#! "} /^[a-zA-Z_-]+:.*?#! / {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)
