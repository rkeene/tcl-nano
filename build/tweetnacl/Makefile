all: out/tweetnacl.c out/tweetnacl.h

tweetnacl.h.new: src/tweetnacl.h
	rm -f tweetnacl.h.new tweetnacl.h
	cp src/tweetnacl.h tweetnacl.h.new

tweetnacl.c.new: src/tweetnacl.c
	rm -f tweetnacl.c.new tweetnacl.c
	cp src/tweetnacl.c tweetnacl.c.new

out/tweetnacl.c: tweetnacl.c.new tweetnacl.h.new patches/tweetnacl-ed25519blake2b.diff patches/tweetnacl-derivepubkey.diff
	mkdir -p out
	rm -f tweetnacl.c tweetnacl.h
	patch -p1 < patches/tweetnacl-ed25519blake2b.diff || ( rm -f tweetnacl.c.new tweetnacl.h.new; exit 1 )
	patch -p1 < patches/tweetnacl-derivepubkey.diff || ( rm -f tweetnacl.c.new tweetnacl.h.new; exit 1 )
	rm -f tweetnacl.c.new.orig tweetnacl.h.new.orig
	mv tweetnacl.h.new tweetnacl.h
	mv tweetnacl.c.new tweetnacl.c
	mv tweetnacl.c out

out/tweetnacl.h: out/tweetnacl.c
	mv tweetnacl.h out

clean:
	rm -f tweetnacl.c.new.orig tweetnacl.h.new.orig
	rm -f tweetnacl.h.new tweetnacl.h
	rm -f tweetnacl.c.new tweetnacl.c
	rm -f out/tweetnacl.c out/tweetnacl.h
	-rmdir out

distclean: clean

.PHONY: all clean distclean
