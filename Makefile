
# assembler
ASM = nasm

# c compiler
CC = gcc

# assembler flags
AFLAGS = -felf64

# compiler flags
CFLAGS = -c -Wall -O2

# linker flags
LFLAGS = -no-pie

.PHONY: clean install

all: makepoly example

makepoly: makepoly.o polyengine.o
	$(CC) $(LFLAGS) $^ -o $@

example: example.o
	$(CC) $(LFLAGS) $< -o $@

makepoly.o: makepoly.c
	$(CC) $(CFLAGS) $< -o $@

polyengine.o: polyengine.asm makepoly.inc
	$(ASM) $(AFLAGS) $< -o $@

example.o: example.asm makepoly.inc
	$(ASM) $(AFLAGS) $< -o $@

clean:
	rm -f *.o makepoly example example.poly

install:
	install makepoly /usr/local/bin/

