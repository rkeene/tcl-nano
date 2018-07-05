PREFIX := $(shell pwd)/INST

all: out/blake2b.c out/blake2.h out/blake2-impl.h

out/blake2b.c: src/blake2b-ref.c blake2-nacl.c
	mkdir -p out
	cat src/blake2b-ref.c blake2-nacl.c > out/blake2b.c

out/blake2.h: src/blake2.h blake2-nacl.h
	mkdir -p out
	cat src/blake2.h blake2-nacl.h > out/blake2.h

out/blake2-impl.h: src/blake2-impl.h
	mkdir -p out
	cp src/blake2-impl.h out

install: out/blake2b.c out/blake2.h out/blake2-impl.h
	mkdir -p '$(PREFIX)'
	cp out/blake2b.c out/blake2.h out/blake2-impl.h '$(PREFIX)'

clean:
	rm -f out/blake2b.c out/blake2.h out/blake2-impl.h
	-rmdir out

distclean: clean

.PHONY: all install clean distclean
