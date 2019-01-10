PREFIX := $(shell pwd)/INST

all: out/argon2.c out/argon2.h

out/argon2.c: src/argon2.c src/ref.c src/core.c src/blake2b.c src/encoding.c monocypher-blake2b.h
	mkdir -p out
	echo '#define ARGON2_NO_THREADS 1' > out/argon2.c.new.1
	echo '#define ARGON2_INTERNAL_ONLY 1' >> out/argon2.c.new.1
	cat monocypher-blake2b.h >> out/argon2.c.new.1
	echo '#include "argon2.h"' >> out/argon2.c.new.1
	sed '/^#include "/ d' src/argon2.c >> out/argon2.c.new.1
	sed '/^#include "/ d' src/encoding.c >> out/argon2.c.new.1
	sed '/^#include "/ d' src/ref.c >> out/argon2.c.new.1
	sed '/#include "/ d;/#include/ b;/Argon2 Team - Begin Code/,/Argon2 Team - End Code/ b;d' src/blake2b.c >> out/argon2.c.new.1
	sed '/^#include "/ d' src/core.c >> out/argon2.c.new.1
	sed -r '/( |\*)argon(2_ctx|2_verify|2_hash|2_type2|2_error_message|2_encodedlen|2i_|2d_|2id_)/ b;/:/ b;/^(static|extern|enum|typedef) / b;s@^[a-z]@static &@'  out/argon2.c.new.1 > out/argon2.c.new.2
	rm -f out/argon2.c.new.1
	mv out/argon2.c.new.2 out/argon2.c

out/argon2.h: src/argon2.h src/blamka-round-ref.h src/core.h src/encoding.h
	mkdir -p out
	cat src/argon2.h > out/argon2.h.new.1
	echo '#ifdef ARGON2_INTERNAL_ONLY' >> out/argon2.h.new.1
	cat src/blamka-round-ref.h src/core.h src/encoding.h >> out/argon2.h.new.1
	echo '#endif' >> out/argon2.h.new.1
	sed -r '/^extern int FLAG/ d;/#include "/ d;/( |\*)argon(2_ctx|2_verify|2_hash|2_type2|2_error_message|2_encodedlen|2i_|2d_|2id_)/ b;/:/ b;/^(static|extern|enum|typedef) / b;s@^[a-z]@static &@' out/argon2.h.new.1 > out/argon2.h.new.2
	rm -f out/argon2.h.new.1
	mv out/argon2.h.new.2 out/argon2.h

install: out/argon2.c out/argon2.h
	mkdir -p '$(PREFIX)'
	cp out/argon2.c out/argon2.h '$(PREFIX)'

clean:
	rm -f out/argon2.c out/argon2.h
	rm -f out/argon2.c.new.1 out/argon2.c.new.2
	rm -f out/argon2.h.new.1 out/argon2.h.new.2
	-rmdir out

distclean: clean

.PHONY: all install clean distclean
