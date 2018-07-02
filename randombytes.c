#include "randombytes.h"

#if defined(HAVE_GETRANDOM)
#  ifdef HAVE_SYS_RANDOM_H
#    include <sys/random.h>
#  endif

void randombytes(uint8_t *buffer, uint64_t length) {
	ssize_t gr_ret;

	while (length > 0) {
		gr_ret = getrandom(buffer, length, 0);
		if (gr_ret <= 0) {
			continue;
		}

		buffer += gr_ret;
		length -= gr_ret;
	}

	return;
}
#elif defined(HAVE_GETENTROPY)
void randombytes(uint8_t *buffer, uint64_t length) {
	int ge_ret;
	int current_length;

	while (length > 0) {
		current_length = length;
		if (current_length > 256) {
			current_length = 256;
		}

		ge_ret = getentropy(buffer, current_length);
		if (ge_ret != 0) {
			continue;
		}

		buffer += current_length;
		length -= current_length;
	}

	return;
}
#elif 1
#include <tcl.h>

void randombytes(uint8_t *buffer, uint64_t length) {

	Tcl_Panic("Random data is not available");

#if 0
	Tcl_Channel fd;

	fd = Tcl_FSOpenFileChannel(NULL, Tcl_NewStringObj("/dev/urandom", -1), "rb", 0644);
	if (!fd) {
		Tcl_Panic("Unable to get random data");
	}

	while (length > 0) {
		read_ret = Tcl_ReadChars(fd, buffer, length);
		if (read_ret <= 0) {
			continue;
		}

		buffer += read_ret;
		length -= read_ret;
	}

	Tcl_Close(fd);
#endif

	return;

	/* NOTREACH */
	buffer = buffer;
	length = length;
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
void randombytes(uint8_t *buffer, uint64_t length) {
	ssize_t read_ret;
	int fd = -1;

	while (fd < 0) {
		fd = open("/dev/urandom", O_RDONLY);
	}

	while (length > 0) {
		read_ret = read(fd, buffer, length);
		if (read_ret <= 0) {
			continue;
		}

		buffer += read_ret;
		length -= read_ret;
	}

	close(fd);
	return;
}
#endif
