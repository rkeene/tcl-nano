#include <tcl.h>
#include <stdint.h>
#include <limits.h>
#include "tweetnacl.h"

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

/*
 * XXX:TODO: NOT RANDOM: For testing only
 */
void randombytes(uint8_t *buffer, uint64_t length) {
	while (length > 0) {
		buffer[length - 1] = (length % 256);
		length--;
	}

	return;
}

static int nano_sign(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
	int cs_ret;
	unsigned char *signature, *data, *secret_key;
	unsigned long long signature_length;
	int data_length, secret_key_length;

	if (objc != 3) {
		Tcl_WrongNumArgs(interp, 1, objv, "data secretKey");

		return(TCL_ERROR);
	}

	data = Tcl_GetByteArrayFromObj(objv[1], &data_length);
	secret_key = Tcl_GetByteArrayFromObj(objv[2], &secret_key_length);
	if (secret_key_length != crypto_sign_SECRETKEYBYTES) {
		Tcl_SetResult(interp, "Secret key is not the right size", NULL);

		return(TCL_ERROR);
	}

	signature_length = data_length + crypto_sign_BYTES;
	if (signature_length >= UINT_MAX) {
		Tcl_SetResult(interp, "Input message too long", NULL);

		return(TCL_ERROR);
	}

	signature = (unsigned char *) Tcl_AttemptAlloc(signature_length);
	if (!signature) {
		Tcl_SetResult(interp, "Unable to allocate memory", NULL);

		return(TCL_ERROR);
	}

	cs_ret = crypto_sign(signature, &signature_length, data, data_length, secret_key);
	if (cs_ret != 0) {
		Tcl_SetResult(interp, "crypto_sign failed", NULL);

		return(TCL_ERROR);
	}

	Tcl_SetObjResult(interp, Tcl_NewByteArrayObj(signature, signature_length));

	return(TCL_OK);

	/* NOTREACH */
	clientData = clientData;
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
