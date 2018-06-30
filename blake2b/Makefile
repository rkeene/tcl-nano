blake2b.o: blake2b-ref.c blake2-impl.h blake2.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -DSUPERCOP=1 -o blake2b.o -c blake2b-ref.c

clean:
	rm -f blake2b.o

distclean: clean

.PHONY: clean distclean
