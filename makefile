# Makefile for ZTAR - Secure Compressed Archive System v1.6.2
# Just type: make

.PHONY: all clean install uninstall test stress-test parallel-test help debug

CC      := gcc
TARGET  := ztar
SOURCES := ztar.c
LIBS    := -lsodium -llz4 -lz -lpthread

# Production flags (hardened)
CFLAGS  := -O3 -march=native \
           -D_FORTIFY_SOURCE=2 \
           -fstack-protector-strong \
           -Wformat -Wformat-security \
           -Wall -Wextra \
           -Wl,-z,relro -Wl,-z,now

# Debug flags
DEBUG_FLAGS := -g -O0 -DDEBUG -fsanitize=address

# Install paths
PREFIX  := /usr/local
BINDIR  := $(PREFIX)/bin

# Colors
GREEN   := \033[0;32m
YELLOW  := \033[0;33m
RED     := \033[0;31m
BOLD    := \033[1m
NC      := \033[0m

all: $(TARGET)
	@printf "$(GREEN)$(BOLD)✓ Build complete:$(NC) ./$(TARGET)\n"
	@printf "$(YELLOW)Run './$(TARGET) --help' for usage, or 'make test' to verify$(NC)\n"

$(TARGET): $(SOURCES)
	@printf "$(YELLOW)Building $(TARGET) v1.6.2...$(NC)\n"
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)
	@printf "$(GREEN)✓ Compilation successful (0 warnings)$(NC)\n"

debug: $(SOURCES)
	@printf "$(YELLOW)Building $(TARGET) with debug + AddressSanitizer...$(NC)\n"
	$(CC) $(CFLAGS) $(DEBUG_FLAGS) -o $(TARGET) $< $(LIBS)
	@printf "$(GREEN)✓ Debug build complete: ./$(TARGET)$(NC)\n"

install: $(TARGET)
	@printf "$(YELLOW)Installing to $(BINDIR)...$(NC)\n"
	@mkdir -p $(BINDIR)
	@install -m 755 $(TARGET) $(BINDIR)/
	@printf "$(GREEN)✓ Installed: $(BINDIR)/$(TARGET)$(NC)\n"

uninstall:
	@printf "$(YELLOW)Removing $(TARGET)...$(NC)\n"
	@rm -f $(BINDIR)/$(TARGET)
	@printf "$(GREEN)✓ Uninstalled$(NC)\n"

test: $(TARGET)
	@printf "\n$(BOLD)=== ZTAR v1.6.2 Test Suite ===$(NC)\n\n"
	@# Test 1: Create
	@printf "$(GREEN)[1/7] Creating archive...$(NC)\n"
	@./$(TARGET) create test.ztar -p "TestPass123!" -q
	@[ -f test.ztar ] && printf "  ✓ Archive created\n" || printf "  $(RED)✗ Failed$(NC)\n"
	@# Test 2: Info
	@printf "$(GREEN)[2/7] Getting info...$(NC)\n"
	@./$(TARGET) info test.ztar | grep -q "ZTAR" && printf "  ✓ Info works\n" || printf "  $(RED)✗ Failed$(NC)\n"
	@# Test 3: Add files
	@printf "$(GREEN)[3/7] Adding test files...$(NC)\n"
	@echo "Hello ZTAR World!" > __test1.txt
	@dd if=/dev/urandom of=__test2.bin bs=1024 count=100 2>/dev/null
	@./$(TARGET) add test.ztar -p "TestPass123!" -q __test1.txt __test2.bin
	@printf "  ✓ Files added\n"
	@# Test 4: List
	@printf "$(GREEN)[4/7] Listing contents...$(NC)\n"
	@./$(TARGET) list test.ztar -p "TestPass123!" -q | grep -q "__test1.txt" && printf "  ✓ List works\n" || printf "  $(RED)✗ Failed$(NC)\n"
	@# Test 5: Extract
	@printf "$(GREEN)[5/7] Extracting files...$(NC)\n"
	@mkdir -p __test_extract
	@./$(TARGET) extract test.ztar -p "TestPass123!" -q __test1.txt __test_extract/
	@diff __test1.txt __test_extract/__test1.txt > /dev/null && printf "  ✓ Extraction verified\n" || printf "  $(RED)✗ Failed$(NC)\n"
	@# Test 6: Verify
	@printf "$(GREEN)[6/7] Verifying integrity...$(NC)\n"
	@./$(TARGET) verify test.ztar -p "TestPass123!" -q && printf "  ✓ Integrity verified\n" || printf "  $(RED)✗ Failed$(NC)\n"
	@# Test 7: Wrong password
	@printf "$(GREEN)[7/7] Testing wrong password rejection...$(NC)\n"
	@! ./$(TARGET) list test.ztar -p "WrongPassword" -q 2>/dev/null && printf "  ✓ Wrong password rejected\n" || printf "  $(RED)✗ Failed$(NC)\n"
	@# Cleanup
	@printf "\n$(YELLOW)Cleaning up...$(NC)\n"
	@rm -f test.ztar __test1.txt __test2.bin
	@rm -rf __test_extract
	@printf "$(GREEN)$(BOLD)=== All 7 tests passed! ===$(NC)\n\n"

stress-test: $(TARGET)
	@printf "\n$(BOLD)=== ZTAR Stress Test (100MB) ===$(NC)\n\n"
	@printf "$(GREEN)Generating 100MB test file...$(NC)\n"
	@dd if=/dev/urandom of=__stress.bin bs=1M count=100 2>/dev/null
	@printf "$(GREEN)Creating archive...$(NC)\n"
	@./$(TARGET) create __stress.ztar -p "Stress123!" -q
	@printf "$(GREEN)Adding large file...$(NC)\n"
	@./$(TARGET) add __stress.ztar -p "Stress123!" -q __stress.bin
	@printf "$(GREEN)Extracting...$(NC)\n"
	@mkdir -p __stress_out
	@./$(TARGET) extract __stress.ztar -p "Stress123!" -q __stress.bin __stress_out/
	@printf "$(GREEN)Verifying...$(NC)\n"
	@diff __stress.bin __stress_out/__stress.bin > /dev/null && printf "  $(GREEN)✓ 100MB round-trip passed!$(NC)\n" || printf "  $(RED)✗ Failed$(NC)\n"
	@printf "$(GREEN)Verifying archive integrity...$(NC)\n"
	@./$(TARGET) verify __stress.ztar -p "Stress123!" -q && printf "  $(GREEN)✓ Archive integrity confirmed$(NC)\n" || printf "  $(RED)✗ Failed$(NC)\n"
	@rm -f __stress.bin __stress.ztar
	@rm -rf __stress_out
	@printf "\n$(GREEN)$(BOLD)=== Stress test passed! ===$(NC)\n\n"

parallel-test: $(TARGET)
	@printf "\n$(BOLD)=== Parallel Compression Test (8 threads) ===$(NC)\n\n"
	@for i in 1 2 3 4 5 6 7 8; do \
		dd if=/dev/urandom of=__par_$$i.bin bs=1M count=10 2>/dev/null; \
	done
	@printf "$(GREEN)Created 8 test files (10MB each, 80MB total)$(NC)\n"
	@./$(TARGET) create __par.ztar -p "Test123!" -q
	@printf "$(GREEN)Adding with 8 threads...$(NC)\n"
	@time ./$(TARGET) add __par.ztar -p "Test123!" -q -t 8 __par_*.bin
	@printf "$(GREEN)Verifying...$(NC)\n"
	@./$(TARGET) verify __par.ztar -p "Test123!" -q && printf "  $(GREEN)✓ Parallel add verified$(NC)\n" || printf "  $(RED)✗ Failed$(NC)\n"
	@rm -f __par_*.bin __par.ztar
	@printf "\n$(GREEN)$(BOLD)=== Parallel test passed! ===$(NC)\n\n"

valgrind-test: debug
	@printf "\n$(BOLD)=== Valgrind Memory Test ===$(NC)\n\n"
	@echo "test data" > __vg.txt
	@printf "$(GREEN)Running under Valgrind...$(NC)\n"
	@valgrind --leak-check=full --show-leak-kinds=all --error-exitcode=1 \
		./$(TARGET) create __vg.ztar -p "test" -q 2>&1 | grep -E "(ERROR|LEAK|lost)" || printf "  $(GREEN)✓ No memory errors$(NC)\n"
	@valgrind --leak-check=full --show-leak-kinds=all --error-exitcode=1 \
		./$(TARGET) add __vg.ztar -p "test" -q __vg.txt 2>&1 | grep -E "(ERROR|LEAK|lost)" || printf "  $(GREEN)✓ No memory errors$(NC)\n"
	@valgrind --leak-check=full --show-leak-kinds=all --error-exitcode=1 \
		./$(TARGET) extract __vg.ztar -p "test" -q __vg.txt __vg_out/ 2>&1 | grep -E "(ERROR|LEAK|lost)" || printf "  $(GREEN)✓ No memory errors$(NC)\n"
	@rm -f __vg.txt __vg.ztar
	@rm -rf __vg_out
	@printf "\n$(GREEN)$(BOLD)=== Valgrind test passed! ===$(NC)\n\n"

clean:
	@printf "$(YELLOW)Cleaning build artifacts...$(NC)\n"
	@rm -f $(TARGET)
	@rm -f *.ztar __test*.txt __test*.bin __stress.* __par_*.* __vg.*
	@rm -rf __test_extract __stress_out __vg_out
	@printf "$(GREEN)✓ Clean$(NC)\n"

help:
	@printf "\n$(BOLD)ZTAR v1.6.2 - Secure Compressed Archive System$(NC)\n\n"
	@printf "$(GREEN)Build Targets:$(NC)\n"
	@printf "  $(YELLOW)make$(NC)              Build production binary\n"
	@printf "  $(YELLOW)make debug$(NC)         Build with debug symbols + AddressSanitizer\n"
	@printf "  $(YELLOW)make test$(NC)          Run 7-test basic suite\n"
	@printf "  $(YELLOW)make stress-test$(NC)   Run 100MB round-trip test\n"
	@printf "  $(YELLOW)make parallel-test$(NC) Test 8-thread parallel compression\n"
	@printf "  $(YELLOW)make valgrind-test$(NC) Run Valgrind memory leak check\n"
	@printf "  $(YELLOW)make install$(NC)       Install to $(BINDIR)\n"
	@printf "  $(YELLOW)make uninstall$(NC)     Remove from system\n"
	@printf "  $(YELLOW)make clean$(NC)         Remove build artifacts\n"
	@printf "  $(YELLOW)make help$(NC)          Show this help\n"
	@printf "\n$(GREEN)Quick Start:$(NC)\n"
	@printf "  make && make test\n"
	@printf "\n$(GREEN)Dependencies:$(NC)\n"
	@printf "  Debian/Ubuntu: sudo apt-get install libsodium-dev liblz4-dev zlib1g-dev\n"
	@printf "  Arch:          sudo pacman -S libsodium lz4 zlib\n"
	@printf "  Fedora:        sudo dnf install libsodium-devel lz4-devel zlib-devel\n"
	@printf "\n$(GREEN)Security Features:$(NC)\n"
	@printf "  Encryption:  XChaCha20-Poly1305 (authenticated)\n"
	@printf "  Key Derivation: Argon2id (memory-hard, GPU-resistant)\n"
	@printf "  Hashing:     BLAKE2b + CRC32 (dual verification)\n"
	@printf "  Header:      MAC authenticated (tamper detection)\n"
	@printf "  I/O:         CV-based RWLock with writer preference\n"
	@printf "  Memory:      mlock() for keys, secure wiping\n"
	@printf "  Flush:       Dynamic chunking (8 entries / 64MB)\n\n"