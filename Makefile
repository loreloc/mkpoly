
# C compiler
CC = gcc

# assembler
ASM = nasm

# compiler flags
CFLAGS = -Wall -Wextra -std=c11

# assembler flags
AFLAGS = -f elf64

# linker flags
LFLAGS = -no-pie

.PHONY: clean install

mkpoly: mkpoly.o polyeng.o
	$(CC) $(LFLAGS) $^ -o $@

mkpoly.o: mkpoly.c
	$(CC) $(CFLAGS) -c $< -o $@

polyeng.o: polyeng.asm
	$(ASM) $(AFLAGS) $< -o $@

clean:
	rm -f *.o mkpoly

install:
	install mkpoly /usr/local/bin/


