#include <limits.h>
#include <tcl.h>

#include "randombytes.h"

static long getrandom_impl(void *buf, unsigned int buflen);
void randombytes(unsigned char *buffer, unsigned long long length) {
	long gr_ret;
	int errorCount = 0;

	/*
	 * Ensure that the number of bytes requested can fit within
	 * the types we pass to other calls.
	 *
	 * The interface required by randombytes() used by TweetNaCl
	 * does not give us any way to handle errors.  However,
	 * no buffer should exceed these amounts.
	 */
	if (length > UINT_MAX || length > LONG_MAX) {
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

static long getrandom_impl(void *buf, unsigned int buflen) {
	ssize_t gr_ret;

	gr_ret = getrandom(buf, buflen, 0);

	return(gr_ret);
}

#elif defined(HAVE_GETENTROPY)
#include <unistd.h>

static long getrandom_impl(void *buf, unsigned int buflen) {
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
#elif defined(HAVE_CRYPTGENRANDOM)
#  include <windows.h>
#  include <wincrypt.h>
static long getrandom_impl(void *buf, unsigned int buflen) {
	HCRYPTPROV provider;
	BOOL cac_ret, cgr_ret;

	cac_ret = CryptAcquireContextA(&provider, NULL, NULL, PROV_RSA_FULL, CRYPT_SILENT | CRYPT_VERIFYCONTEXT);
	if (cac_ret == FALSE) {
		cac_ret = CryptAcquireContextA(&provider, NULL, NULL, PROV_RSA_FULL, CRYPT_SILENT | CRYPT_VERIFYCONTEXT | CRYPT_NEWKEYSET);
	}

	if (cac_ret == FALSE) {
		return(-1);
	}

	cgr_ret = CryptGenRandom(provider, buflen, (BYTE *) buf);

	CryptReleaseContext(provider, 0);

	if (cgr_ret == FALSE) {
		return(-1);
	}

	return(buflen);
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
static long getrandom_impl(void *buf, unsigned int buflen) {
	ssize_t read_ret;
	long retval;
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
