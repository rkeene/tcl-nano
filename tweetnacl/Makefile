all: tweetnacl.o

tweetnacl.h.new: src/tweetnacl.h
	rm -f tweetnacl.h.new tweetnacl.h
	cp src/tweetnacl.h tweetnacl.h.new

tweetnacl.c.new: src/tweetnacl.c
	rm -f tweetnacl.c.new tweetnacl.c
	cp src/tweetnacl.c tweetnacl.c.new

tweetnacl.c: tweetnacl.c.new tweetnacl.h.new
	rm -f tweetnacl.c tweetnacl.h
	patch -p1 < patches/tweetnacl-supercop.diff
	mv tweetnacl.h.new tweetnacl.h
	mv tweetnacl.c.new tweetnacl.c

tweetnacl.h: tweetnacl.c

tweetnacl.o: tweetnacl.c tweetnacl.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -DSUPERCOP=1 -I../blake2b/ -o tweetnacl.o -c tweetnacl.c

clean:
	rm -f tweetnacl.h.new tweetnacl.h
	rm -f tweetnacl.c.new tweetnacl.c
	rm -f tweetnacl.o

distclean: clean

.PHONY: all clean distclean
