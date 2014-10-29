all: fastdwarf
CFLAGS=-Wall -Wno-unused-function -Wno-error -Wno-error=unused-variable -O3 -ggdb -std=c11
%.o: %.c *.h */*.h Makefile
	cc $(CFLAGS) -c -o $@ $<
fastdwarf: fastdwarf.o common.o
	cc -o $@ $^
#fastpdb: fastpdb.o common.o
#	cc -o $@ $^
clean:
	rm -f *.o fastdwarf fastpdb

