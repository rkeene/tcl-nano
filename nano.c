#include <stdint.h>
#include <limits.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <tcl.h>

#include "tweetnacl.h"
#include "blake2-supercop.h"

#define NANO_SECRET_KEY_LENGTH (crypto_sign_SECRETKEYBYTES - crypto_sign_PUBLICKEYBYTES)
#define NANO_PUBLIC_KEY_LENGTH (crypto_sign_PUBLICKEYBYTES)
#define TclNano_AttemptAlloc(x) ((void *) Tcl_AttemptAlloc(x))
#define TclNano_Free(x) Tcl_Free((char *) x)

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

static unsigned char *nano_parse_secret_key(Tcl_Obj *secret_key_only_obj, int *out_key_length) {
	unsigned char *secret_key, *public_key, *secret_key_only;
	int secret_key_length, secret_key_only_length;

	secret_key_only = Tcl_GetByteArrayFromObj(secret_key_only_obj, &secret_key_only_length);
	if (secret_key_only_length != NANO_SECRET_KEY_LENGTH) {
		return(NULL);
	}

	if ((NANO_SECRET_KEY_LENGTH + NANO_PUBLIC_KEY_LENGTH) != crypto_sign_SECRETKEYBYTES) {
		return(NULL);
	}

	secret_key_length = crypto_sign_SECRETKEYBYTES;
	secret_key = TclNano_AttemptAlloc(secret_key_length);
	if (!secret_key) {
		return(NULL);
	}

	memcpy(secret_key, secret_key_only, secret_key_only_length);
	public_key = secret_key + secret_key_only_length;
	crypto_sign_keypair(public_key, secret_key, 0);

	*out_key_length = secret_key_length;
	return(secret_key);
}

static int nano_tcl_generate_keypair(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
	int csk_ret;
	unsigned char secret_key[crypto_sign_SECRETKEYBYTES], public_key[crypto_sign_PUBLICKEYBYTES];

	if (objc != 1) {
		Tcl_WrongNumArgs(interp, 1, objv, "");

		return(TCL_ERROR);
	}

	csk_ret = crypto_sign_keypair(public_key, secret_key, 1);
	if (csk_ret != 0) {
		Tcl_SetResult(interp, "Internal error", NULL);

		return(TCL_ERROR);
	}

	Tcl_SetObjResult(interp, Tcl_NewByteArrayObj(secret_key, NANO_SECRET_KEY_LENGTH));

	return(TCL_OK);

	/* NOTREACH */
	clientData = clientData;
}
static int nano_tcl_secret_key_to_public_key(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
	unsigned char *secret_key, *public_key;
	int secret_key_length, public_key_length;

	if (objc != 2) {
		Tcl_WrongNumArgs(interp, 1, objv, "secretKey");

		return(TCL_ERROR);
	}

	secret_key = Tcl_GetByteArrayFromObj(objv[1], &secret_key_length);
	if (secret_key_length != NANO_SECRET_KEY_LENGTH) {
		Tcl_SetResult(interp, "Secret key is not the right size", NULL);

		return(TCL_ERROR);
	}

	public_key_length = NANO_PUBLIC_KEY_LENGTH;
	public_key = TclNano_AttemptAlloc(public_key_length);
	if (!public_key) {
		Tcl_SetResult(interp, "Internal error", NULL);

		return(TCL_ERROR);
	}

	crypto_sign_keypair(public_key, secret_key, 0);

	Tcl_SetObjResult(interp, Tcl_NewByteArrayObj(public_key, public_key_length));

	TclNano_Free(public_key);

	return(TCL_OK);

	/* NOTREACH */
	clientData = clientData;
}

static int nano_tcl_sign_detached(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
	int cs_ret;
	unsigned char *signature, *data, *secret_key;
	unsigned long long signature_length;
	int data_length, secret_key_length;

	if (objc != 3) {
		Tcl_WrongNumArgs(interp, 1, objv, "data secretKey");

		return(TCL_ERROR);
	}

	data = Tcl_GetByteArrayFromObj(objv[1], &data_length);
	signature_length = data_length + crypto_sign_BYTES;
	if (signature_length >= UINT_MAX) {
		Tcl_SetResult(interp, "Input message too long", NULL);

		return(TCL_ERROR);
	}

	secret_key = nano_parse_secret_key(objv[2], &secret_key_length);
	if (!secret_key) {
		Tcl_SetResult(interp, "Secret key is not the right size", NULL);

		return(TCL_ERROR);
	}

	signature = TclNano_AttemptAlloc(signature_length);
	if (!signature) {
		TclNano_Free(secret_key);

		Tcl_SetResult(interp, "Unable to allocate memory", NULL);

		return(TCL_ERROR);
	}

	cs_ret = crypto_sign(signature, &signature_length, data, data_length, secret_key);
	if (cs_ret != 0) {
		TclNano_Free(secret_key);
		TclNano_Free(signature);

		Tcl_SetResult(interp, "crypto_sign failed", NULL);

		return(TCL_ERROR);
	}

	Tcl_SetObjResult(interp, Tcl_NewByteArrayObj(signature, crypto_sign_BYTES));

	TclNano_Free(signature);
	TclNano_Free(secret_key);

	return(TCL_OK);

	/* NOTREACH */
	clientData = clientData;
}

static int nano_tcl_verify_detached(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
	int cso_ret;
	unsigned char *signature, *data, *signed_data, *verify_data, *public_key;
	int signature_length, data_length, signed_data_length, verify_data_length, public_key_length;
	unsigned long long verify_data_length_nacl;
	int result;

	if (objc != 4) {
		Tcl_WrongNumArgs(interp, 1, objv, "data signature publicKey");

		return(TCL_ERROR);
	}

	data = Tcl_GetByteArrayFromObj(objv[1], &data_length);
	signature = Tcl_GetByteArrayFromObj(objv[2], &signature_length);
	if (signature_length != crypto_sign_BYTES) {
		Tcl_SetResult(interp, "Signature is not the right size", NULL);

		return(TCL_ERROR);
	}

	public_key = Tcl_GetByteArrayFromObj(objv[3], &public_key_length);
	if (public_key_length != NANO_PUBLIC_KEY_LENGTH) {
		Tcl_SetResult(interp, "Public key is not the right size", NULL);

		return(TCL_ERROR);
	}

	signed_data_length = data_length + signature_length;
	signed_data = TclNano_AttemptAlloc(signed_data_length);
	if (!signed_data) {
		Tcl_SetResult(interp, "Internal error", NULL);

		return(TCL_ERROR);
	}

	memcpy(signed_data, signature, signature_length);
	memcpy(signed_data + signature_length, data, data_length);

	verify_data_length = signed_data_length;
	verify_data = TclNano_AttemptAlloc(verify_data_length);
	if (!verify_data) {
		TclNano_Free(verify_data);

		Tcl_SetResult(interp, "Internal error", NULL);

		return(TCL_ERROR);
	}

	verify_data_length_nacl = verify_data_length;
	cso_ret = crypto_sign_open(verify_data, &verify_data_length_nacl, signed_data, signed_data_length, public_key);
	result = 0;
	if (cso_ret == 0) {
		result = 1;
	}

	TclNano_Free(signed_data);
	TclNano_Free(verify_data);

	Tcl_SetObjResult(interp, Tcl_NewBooleanObj(result));

	return(TCL_OK);

	/* NOTREACH */
	clientData = clientData;
}

static int nano_tcl_hash_data(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
	unsigned char *data, result[crypto_sign_BYTES];
	int data_length, result_length;

	if (objc != 2) {
		Tcl_WrongNumArgs(interp, 1, objv, "data");

		return(TCL_ERROR);
	}

	data = Tcl_GetByteArrayFromObj(objv[1], &data_length);
	crypto_hash(result, data, data_length);
	result_length = crypto_sign_BYTES;
	Tcl_SetObjResult(interp, Tcl_NewByteArrayObj(result, result_length));

	return(TCL_OK);

	/* NOTREACH */
	clientData = clientData;
}

static int nano_tcl_self_test(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
	if (objc != 1) {
		Tcl_WrongNumArgs(interp, 1, objv, "");

		return(TCL_ERROR);
	}

	return(TCL_OK);

	/* NOTREACH */
	clientData = clientData;
}

int Nano_Init(Tcl_Interp *interp) {
	const char nanoInitScript[] = {
#include "nano.tcl.h"
		0x00
	};
#ifdef USE_TCL_STUBS
	const char *tclInitStubs_ret;

	/* Initialize Stubs */
	tclInitStubs_ret = Tcl_InitStubs(interp, TCL_PATCH_LEVEL, 0);
	if (!tclInitStubs_ret) {
		return(TCL_ERROR);
	}
#endif

	Tcl_CreateObjCommand(interp, "::nano::internal::selfTest", nano_tcl_self_test, NULL, NULL);
	Tcl_CreateObjCommand(interp, "::nano::internal::generateKey", nano_tcl_generate_keypair, NULL, NULL);
	Tcl_CreateObjCommand(interp, "::nano::internal::signDetached", nano_tcl_sign_detached, NULL, NULL);
	Tcl_CreateObjCommand(interp, "::nano::internal::publicKey", nano_tcl_secret_key_to_public_key, NULL, NULL);
	Tcl_CreateObjCommand(interp, "::nano::internal::verifyDetached", nano_tcl_verify_detached, NULL, NULL);
	Tcl_CreateObjCommand(interp, "::nano::internal::hashData", nano_tcl_hash_data, NULL, NULL);

	if (interp) {
		Tcl_Eval(interp, nanoInitScript);
	}

	return(TCL_OK);
}
