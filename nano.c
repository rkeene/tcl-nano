#include <tcl.h>
#include <stdint.h>

#if 0
#include <sys/random.h>

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
#endif

#if 0
#include <unistd.h>
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
#endif

void randombytes(uint8_t *buffer, uint64_t length) {
	while (length > 0) {
		buffer[length - 1] = (length % 256);
		length--;
	}

	return;
}

static int nano_sign(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
	return(TCL_OK);
}

int Nano_Init(Tcl_Interp *interp) {
#ifdef USE_TCL_STUBS
	const char *tclInitStubs_ret;

	/* Initialize Stubs */
	tclInitStubs_ret = Tcl_InitStubs(interp, TCL_PATCH_LEVEL, 0);
	if (!tclInitStubs_ret) {
		return(TCL_ERROR);
	}
#endif
	Tcl_CreateObjCommand(interp, "::nano::internal::sign", nano_sign, NULL, NULL);

	return(TCL_OK);
}
