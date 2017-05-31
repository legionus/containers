CFLAGS = -Wall -Wextra -W -Wshadow -Wcast-align \
	-Wwrite-strings -Wconversion -Waggregate-return -Wstrict-prototypes \
	-Wmissing-prototypes -Wmissing-declarations -Wmissing-noreturn \
	-Wmissing-format-attribute -Wredundant-decls -Wdisabled-optimization \
	-Wno-pointer-arith

TARGETS = container

build: $(TARGETS)

container: container.c
	$(CC) $(CFLAGS) -o $@ $^ -lcap

clean: $(TARGETS)
	rm -f -- $(TARGETS)
