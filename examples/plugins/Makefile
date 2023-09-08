MAKEFLAGS += --warn-undefined-variables

CC := ccache gcc

NAMES := execlog
SONAMES := $(addsuffix .so,$(addprefix lib,$(NAMES)))

CFLAGS := $(shell pkg-config --cflags glib-2.0)
CFLAGS += -fPIC -Wall -O3
CFLAGS += -I$(QEMU_SRC)/include/qemu -I$(QEMU_SRC) -I$(QEMU_SRC)/include -I$(QEMU_SRC)/build

all: $(SONAMES)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

lib%.so: %.o
	$(CC) -shared -Wl,-soname,$@ -o $@ $<

clean:
	rm -f *.o *.so *.d
	rm -Rf .libs

.PHONY: all clean
