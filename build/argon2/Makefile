PREFIX := $(shell pwd)/INST

all: out/argon2.c out/argon2.h

out/argon2.c: src/ref.c src/core.c src/blake2b.c monocypher-blake2b.h
	mkdir -p out
	echo '#define ARGON2_NO_THREADS 1' > out/argon2.c.new
	echo '#define ARGON2_INTERNAL_ONLY 1' >> out/argon2.c.new
	cat monocypher-blake2b.h >> out/argon2.c.new
	sed '/^#include "core\.h"/ d;/#include "blake2/ d;/#include "thread\.h"/ d' src/ref.c >> out/argon2.c.new
	sed '/#include "blake2/d;/#include/ b;/Argon2 Team - Begin Code/,/Argon2 Team - End Code/ b;d' src/blake2b.c >> out/argon2.c.new
	sed '/^#include "core\.h"/ d;/#include "blake2/ d;/#include "thread\.h"/ d' src/core.c >> out/argon2.c.new
	mv out/argon2.c.new out/argon2.c

out/argon2.h: src/argon2.h src/blamka-round-ref.h src/core.h
	mkdir -p out
	cat src/argon2.h > out/argon2.h.new.1
	echo '#ifdef ARGON2_INTERNAL_ONLY' >> out/argon2.h.new.1
	cat src/blamka-round-ref.h src/core.h >> out/argon2.h.new.1
	echo '#endif' >> out/argon2.h.new.1
	sed '/#include "argon2\.h"/ d;/#include "blake2/ d' out/argon2.h.new.1 > out/argon2.h.new.2
	rm -f out/argon2.h.new.1
	mv out/argon2.h.new.2 out/argon2.h

install: out/argon2.c out/argon2.h
	mkdir -p '$(PREFIX)'
	cp out/argon2.c out/argon2.h '$(PREFIX)'

clean:
	rm -f out/argon2.c out/argon2.h
	rm -f out/argon2.c.new out/argon2.h.new.1 out/argon2.h.new.2
	-rmdir out

distclean: clean

.PHONY: all install clean distclean
