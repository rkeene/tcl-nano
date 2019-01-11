PREFIX := $(shell pwd)/INST

all: out/argon2.c out/argon2.h

src-patched/argon2.c src-patched/argon2.h src-patched/blake2b.c src-patched/blamka-round-ref.h src-patched/core.c src-patched/core.h src-patched/encoding.c src-patched/encoding.h src-patched/ref.c: src-patched Makefile

src-patched: src/argon2.c src/argon2.h src/blake2b.c src/blamka-round-ref.h src/core.c src/core.h src/encoding.c src/encoding.h src/ref.c patches/argon2-20181109-tclamalgamation.diff Makefile
	rm -rf src-patched src-patched.new
	mkdir src-patched.new
	cp $^ src-patched.new/
	cd src-patched.new && patch --batch --posix -p1 < ../patches/argon2-20181109-tclamalgamation.diff
	mv src-patched.new src-patched

out/argon2.c: src-patched/argon2.c src-patched/ref.c src-patched/core.c src-patched/blake2b.c src-patched/encoding.c monocypher-blake2b.h Makefile
	mkdir -p out
	echo '#define ARGON2_NO_THREADS 1' > out/argon2.c.new.1
	echo '#define ARGON2_INTERNAL_ONLY 1' >> out/argon2.c.new.1
	cat monocypher-blake2b.h >> out/argon2.c.new.1
	echo '#include "argon2.h"' >> out/argon2.c.new.1
	sed '/^#include "/ d' src-patched/argon2.c >> out/argon2.c.new.1
	sed '/^#include "/ d' src-patched/encoding.c >> out/argon2.c.new.1
	sed '/^#include "/ d' src-patched/ref.c >> out/argon2.c.new.1
	sed '/#include "/ d;/#include/ b;/Argon2 Team - Begin Code/,/Argon2 Team - End Code/ b;d' src-patched/blake2b.c >> out/argon2.c.new.1
	sed '/^#include "/ d' src-patched/core.c >> out/argon2.c.new.1
	sed -r '/( |\*)argon(2_ctx|2_verify|2_hash|2_type2|2_error_message|2_encodedlen|2i_|2d_|2id_)/ b;/:/ b;/^(static|extern|enum|typedef) / b;s@^[a-z]@static &@'  out/argon2.c.new.1 > out/argon2.c.new.2
	rm -f out/argon2.c.new.1
	sed 's@malloc(@(void *) Tcl_AttemptAlloc(@g;s@free(@Tcl_Free((void *) @g;s@\.v\[@.a[@g;s@->v\[@->a[@g;s@->v)@->a)@g;s@->v,@->a,@g;s@\.v,@.a,@g' out/argon2.c.new.2 > out/argon2.c.new.1
	rm -f out/argon2.c.new.2
	mv out/argon2.c.new.1 out/argon2.c

out/argon2.h: src-patched/argon2.h src-patched/blamka-round-ref.h src-patched/core.h src-patched/encoding.h Makefile
	mkdir -p out
	cat src-patched/argon2.h > out/argon2.h.new.1
	echo '#ifdef ARGON2_INTERNAL_ONLY' >> out/argon2.h.new.1
	cat src-patched/blamka-round-ref.h src-patched/core.h src-patched/encoding.h >> out/argon2.h.new.1
	echo '#endif' >> out/argon2.h.new.1
	sed -r '/^extern int FLAG/ d;/#include "/ d;/( |\*)argon(2_ctx|2_verify|2_hash|2_type2|2_error_message|2_encodedlen|2i_|2d_|2id_)/ b;/:/ b;/^(static|extern|enum|typedef) / b;s@^[a-z]@static &@' out/argon2.h.new.1 > out/argon2.h.new.2
	rm -f out/argon2.h.new.1
	sed '/^typedef struct .* block;$$/ {i \'$$'\n''#ifndef TCL_NANO_AMALGAMATION'$$'\n''s@ v\[@ a[@;p;i \'$$'\n''#endif'$$'\n''d}' out/argon2.h.new.2 > out/argon2.h.new.1
	rm -f out/argon2.h.new.2
	mv out/argon2.h.new.1 out/argon2.h

install: out/argon2.c out/argon2.h
	mkdir -p '$(PREFIX)'
	cp out/argon2.c out/argon2.h '$(PREFIX)'

clean:
	rm -f out/argon2.c out/argon2.h
	rm -f out/argon2.c.new.1 out/argon2.c.new.2
	rm -f out/argon2.h.new.1 out/argon2.h.new.2
	rm -rf src-patched src-patched.new
	-rmdir out

distclean: clean

.PHONY: all install clean distclean
