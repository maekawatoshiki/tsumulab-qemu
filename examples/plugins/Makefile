MAKEFLAGS += --warn-undefined-variables

ifndef QEMU_SRC
QEMU_SRC := $(shell pwd)/../../
endif

CC := ccache gcc
CXX := ccache g++

NAMES := execlog trace
SONAMES := $(addsuffix .so,$(addprefix lib,$(NAMES)))

CFLAGS := $(shell pkg-config --cflags glib-2.0)
CFLAGS += -fPIC -Wall -O3
CFLAGS += -I$(QEMU_SRC)/include/qemu -I$(QEMU_SRC) -I$(QEMU_SRC)/include -I$(QEMU_SRC)/build

CXXFLAGS := -fPIC -Wall -Wextra -O3 -std=c++17 -fvisibility=hidden
CXXFLAGS += $(shell pkg-config --cflags glib-2.0)
CXXFLAGS += -I$(QEMU_SRC) -I$(QEMU_SRC)/include -I$(QEMU_SRC)/build

all: $(SONAMES)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

%.o: %.cc
	$(CXX) $(CXXFLAGS) -c -o $@ $<

lib%.so: %.o
	$(CXX) -shared -Wl,-soname,$@ -o $@ $<

clean:
	rm -f *.o *.so *.d
	rm -Rf .libs

.PHONY: all clean
