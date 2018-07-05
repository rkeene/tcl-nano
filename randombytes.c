#include <limits.h>
#include <tcl.h>

#include "randombytes.h"

long long getrandom_impl(void *buf, unsigned int buflen);
void randombytes(unsigned char *buffer, unsigned long long length) {
	long long gr_ret;
	int errorCount = 0;

	if (length > UINT_MAX || length > LONG_LONG_MAX) {
		Tcl_Panic("Buffer length is too large");
	}

	while (length > 0) {
		gr_ret = getrandom_impl(buffer, length);

		if (gr_ret < 0) {
			errorCount++;
			if (errorCount > 10) {
				Tcl_Panic("Unable to generate random numbers");
			}
			continue;
		}
		errorCount = 0;

		if (gr_ret == 0) {
			continue;
		}

		buffer += gr_ret;
		length -= gr_ret;
	}

	return;
}

#if defined(HAVE_GETRANDOM)
#  ifdef HAVE_SYS_RANDOM_H
#    include <sys/random.h>
#  endif

long long getrandom_impl(void *buf, unsigned int buflen) {
	ssize_t gr_ret;

	gr_ret = getrandom(buf, buflen, 0);

	return(gr_ret);
}

#elif defined(HAVE_GETENTROPY)
#include <unistd.h>

long long getrandom_impl(void *buf, unsigned int buflen) {
	int ge_ret;

	if (buflen > 255) {
		buflen = 255;
	}

	ge_ret = getentropy(buf, buflen);
	if (ge_ret != 0) {
		return(-1);
	}

	return(buflen);
}
#elif defined(HAVE_CRYPTGENRANDOM) && 0
#include <tcl.h>
long long getrandom_impl(void *buf, unsigned int buflen) {
	Tcl_Panic("Incomplete CryptGenRandom");
}
#else
#  ifdef HAVE_SYS_TYPES_H
#    include <sys/types.h>
#  endif
#  ifdef HAVE_SYS_STAT_H
#    include <sys/stat.h>
#  endif
#  ifdef HAVE_FCNTL_H
#    include <fcntl.h>
# endif
# ifdef HAVE_UNISTD_H
#    include <unistd.h>
# endif
long long getrandom_impl(void *buf, unsigned int buflen) {
	ssize_t read_ret;
	long long retval;
	int fd = -1;

	fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0) {
		return(-1);
	}

	retval = 0;
	while (buflen > 0) {
		read_ret = read(fd, buf, buflen);
		if (read_ret <= 0) {
			continue;
		}

		buf    += read_ret;
		retval += read_ret;
		buflen -= read_ret;
	}

	close(fd);

	return(retval);
}
#endif
