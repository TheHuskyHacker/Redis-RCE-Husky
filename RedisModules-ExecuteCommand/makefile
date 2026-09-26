CC       ?= gcc
CFLAGS    = -shared -fPIC -fno-stack-protector -nostartfiles -O2
SRC_DIR   = src
TARGET    = module.so

.PHONY: all clean test

all: $(TARGET)
	@echo ""
	@echo "[+] Built $(TARGET) ($$(stat -c%s $(TARGET)) bytes)"
	@file $(TARGET)

$(TARGET): $(SRC_DIR)/module.c $(SRC_DIR)/redismodule.h
	$(CC) $(CFLAGS) -I$(SRC_DIR) -o $@ $(SRC_DIR)/module.c
	strip -s $@

test: $(TARGET)
	@objdump -T $(TARGET) | grep -E 'OnLoad|DoCommand|RevShell' && echo "[+] Symbols OK" || echo "[-] Missing!"
	@objdump -p $(TARGET) | grep GLIBC

clean:
	rm -f $(TARGET)
