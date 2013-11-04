%.o: %.c common.h
	cc -c -o $@ $< -O3
fastdwarf: fastdwarf.o common.o
	cc -o $@ $<
fastpdb: fastpdb.o common.o
	cc -o $@ $<
clean:
	rm -f *.o fastdwarf fastpdb

