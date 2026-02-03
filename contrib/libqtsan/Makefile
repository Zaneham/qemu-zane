# libqtsan Makefile
# Cross-compile for RISC-V

CC ?= riscv64-linux-gnu-gcc
CFLAGS = -Wall -Wextra -O2 -fPIC -shared
LDFLAGS = -ldl -lpthread

TARGET = libqtsan.so

all: $(TARGET)

$(TARGET): libqtsan.c qtsan_common.h
	$(CC) $(CFLAGS) -o $@ libqtsan.c $(LDFLAGS)

clean:
	rm -f $(TARGET)

.PHONY: all clean
