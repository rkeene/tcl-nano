CFLAGS = -Wall
LIBS = -ltcl8.6
export CFLAGS

all: nano.so

nano.so: tweetnacl/tweetnacl.o blake2b/blake2b.o nano.c Makefile
	$(CC) $(CPPFLAGS) $(CFLAGS) -shared -o nano.so nano.c tweetnacl/tweetnacl.o blake2b/blake2b.o $(LDFLAGS) $(LIBS)

tweetnacl/tweetnacl.o:
	$(MAKE) -C tweetnacl tweetnacl.o

blake2b/blake2b.o:
	$(MAKE) -C blake2b blake2b.o

clean:
	rm -f nano.so
	$(MAKE) -C tweetnacl clean
	$(MAKE) -C blake2b clean

distclean:
	rm -f nano.so
	$(MAKE) -C tweetnacl distclean
	$(MAKE) -C blake2b distclean

.PHONY: all clean distclean
