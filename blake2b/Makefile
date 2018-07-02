blake2b.o: blake2b-ref-nacl.c blake2-impl.h blake2.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -o blake2b.o -c blake2b-ref-nacl.c

blake2b-ref-nacl.c: blake2b-ref.c blake2-nacl.c
	rm -f blake2b-ref-nacl.c
	cat blake2b-ref.c blake2-nacl.c > blake2b-ref-nacl.c

clean:
	rm -f blake2b-ref-nacl.c
	rm -f blake2b.o

distclean: clean

.PHONY: clean distclean
