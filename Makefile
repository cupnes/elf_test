CFLAGS = -Wall -Wextra

all: elf_test

elf_test: main.c
	gcc $(CFLAGS) -o $@ $+

clean:
	rm -f *~ *.elf elf_test

.PHONY: clean
