# Build orchestrator: pktproc binary, debug build, unit tests, install/cap helpers.
CC      ?= gcc
CSTD    := -std=c11
WARN    := -Wall -Wextra -Werror -Wshadow -Wpointer-arith -Wstrict-prototypes \
           -Wmissing-prototypes -Wunused
FEAT    := -D_GNU_SOURCE -D_POSIX_C_SOURCE=200809L
INCLUDE := -Iinclude

CFLAGS  ?= $(CSTD) $(WARN) $(FEAT) $(INCLUDE) -O2
LDFLAGS ?=

SRC_DIR  := src
OBJ_DIR  := build
TEST_DIR := tests

SRCS     := $(wildcard $(SRC_DIR)/*.c)
OBJS     := $(SRCS:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
LIB_OBJS := $(filter-out $(OBJ_DIR)/main.o, $(OBJS))

TEST_SRCS := $(wildcard $(TEST_DIR)/test_*.c)
TEST_BINS := $(TEST_SRCS:$(TEST_DIR)/%.c=$(OBJ_DIR)/%)

TARGET := pktproc

.PHONY: all debug test clean install cap help
.DEFAULT_GOAL := all

all: $(TARGET)

debug: CFLAGS := $(CSTD) $(WARN) $(FEAT) $(INCLUDE) -O0 -g -DDEBUG
debug: clean $(TARGET)

$(OBJ_DIR):
	@mkdir -p $(OBJ_DIR)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(OBJ_DIR)/test_%: $(TEST_DIR)/test_%.c $(LIB_OBJS) | $(OBJ_DIR)
	$(CC) $(CFLAGS) -I$(TEST_DIR) -o $@ $< $(LIB_OBJS) $(LDFLAGS)

test: $(TEST_BINS)
	@set -e; \
	pass=0; fail=0; \
	for t in $(TEST_BINS); do \
	    echo "== $$t =="; \
	    if $$t; then pass=$$((pass+1)); else fail=$$((fail+1)); fi; \
	done; \
	echo ""; echo "Test summary: $$pass passed, $$fail failed"; \
	[ $$fail -eq 0 ]

cap: $(TARGET)
	sudo setcap cap_net_raw,cap_net_admin=eip ./$(TARGET)

install: $(TARGET)
	install -m 0755 $(TARGET) /usr/local/bin/$(TARGET)

clean:
	rm -rf $(OBJ_DIR) $(TARGET)

help:
	@echo "Targets:"
	@echo "  make           - optimized build (default)"
	@echo "  make debug     - unoptimized build with -g and -DDEBUG"
	@echo "  make test      - build and run unit tests"
	@echo "  make cap       - grant CAP_NET_RAW to the binary (needs sudo once)"
	@echo "  make install   - install to /usr/local/bin"
	@echo "  make clean     - remove build artifacts"
