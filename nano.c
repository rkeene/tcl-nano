#include <stdint.h>
#include <limits.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <tcl.h>
#ifdef NANO_TCL_HAVE_OPENMP
#  include <omp.h>
#endif

#include "randombytes.h"
#include "tweetnacl.h"
#include "blake2.h"

#define NANO_SECRET_KEY_LENGTH (crypto_sign_SECRETKEYBYTES - crypto_sign_PUBLICKEYBYTES)
#define NANO_PUBLIC_KEY_LENGTH (crypto_sign_PUBLICKEYBYTES)
#define NANO_BLOCK_HASH_LENGTH 32
#define NANO_BLOCK_SIGNATURE_LENGTH crypto_sign_BYTES
#define NANO_WORK_VALUE_LENGTH 8
#define NANO_WORK_HASH_LENGTH  8
#define NANO_WORK_DEFAULT_MIN  0xffffffc000000000LLU

#define TclNano_AttemptAlloc(x) ((void *) Tcl_AttemptAlloc(x))
#define TclNano_Free(x) Tcl_Free((char *) x)
#define TclNano_SetIntVar(interp, name, intValue) \
	tclobj_ret = Tcl_SetVar2Ex(interp, name, NULL, Tcl_NewIntObj(intValue), TCL_GLOBAL_ONLY | TCL_LEAVE_ERR_MSG); \
	if (!tclobj_ret) { \
		return(TCL_ERROR); \
	}

#define TclNano_CreateNamespace(interp, name) \
	tclobj_ret = Tcl_CreateNamespace(interp, name, NULL, NULL); \
	if (!tclobj_ret) { \
		return(TCL_ERROR); \
	}

#define TclNano_CreateObjCommand(interp, name, functionName) \
	tclobj_ret = Tcl_CreateObjCommand(interp, name, functionName, NULL, NULL); \
	if (!tclobj_ret) { \
		return(TCL_ERROR); \
	}

#define TclNano_Eval(interp, script) \
	tclcmd_ret = Tcl_Eval(interp, script); \
	if (tclcmd_ret != TCL_OK) { \
		return(tclcmd_ret); \
	}

#define TclNano_PkgProvide(interp, name, version) \
	tclcmd_ret = Tcl_PkgProvide(interp, name, version); \
	if (tclcmd_ret != TCL_OK) { \
		return(tclcmd_ret); \
	}

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
	unsigned char secret_key[crypto_sign_SECRETKEYBYTES], public_key[crypto_sign_PUBLICKEYBYTES];
	unsigned char *seed, *buffer, buffer_s[NANO_SECRET_KEY_LENGTH + 4];
	long seed_index;
	int seed_length, buffer_length;
	int csk_ret, tglfo_ret;

	if (objc != 1 && objc != 3) {
		Tcl_WrongNumArgs(interp, 1, objv, "?seed index?");

		return(TCL_ERROR);
	}

	if (objc == 1) {
		csk_ret = crypto_sign_keypair(public_key, secret_key, 1);
		if (csk_ret != 0) {
			Tcl_SetResult(interp, "Internal error", NULL);

			return(TCL_ERROR);
		}
	} else {
		seed = Tcl_GetByteArrayFromObj(objv[1], &seed_length);
		if (seed_length != NANO_SECRET_KEY_LENGTH) {
			Tcl_SetResult(interp, "Seed is not the right size", NULL);

			return(TCL_ERROR);
		}

		tglfo_ret = Tcl_GetLongFromObj(interp, objv[2], &seed_index);
		if (tglfo_ret != TCL_OK) {
			return(tglfo_ret);
		}

		if (seed_index > 0xffffffffULL) {
			Tcl_SetResult(interp, "Seed exceed maximum value", NULL);

			return(TCL_ERROR);
		}

		buffer_length = sizeof(buffer_s);
		buffer = buffer_s;

		memcpy(buffer, seed, seed_length);
		buffer += seed_length;
		buffer[0] = (seed_index >> 24) & 0xff;
		buffer[1] = (seed_index >> 16) & 0xff;
		buffer[2] = (seed_index >> 8) & 0xff;
		buffer[3] = seed_index & 0xff;
		buffer -= seed_length;

		blake2b(secret_key, NANO_SECRET_KEY_LENGTH, buffer, buffer_length, NULL, 0);
	}

	Tcl_SetObjResult(interp, Tcl_NewByteArrayObj(secret_key, NANO_SECRET_KEY_LENGTH));

	return(TCL_OK);

	/* NOTREACH */
	clientData = clientData;
}

static int nano_tcl_generate_seed(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
	unsigned char seed[NANO_SECRET_KEY_LENGTH];
	int seed_length;

	if (objc != 1) {
		Tcl_WrongNumArgs(interp, 1, objv, "");

		return(TCL_ERROR);
	}

	seed_length = sizeof(seed);
	randombytes(seed, seed_length);

	Tcl_SetObjResult(interp, Tcl_NewByteArrayObj(seed, seed_length));

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
	signature_length = data_length + NANO_BLOCK_SIGNATURE_LENGTH;
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

	Tcl_SetObjResult(interp, Tcl_NewByteArrayObj(signature, NANO_BLOCK_SIGNATURE_LENGTH));

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
	if (signature_length != NANO_BLOCK_SIGNATURE_LENGTH) {
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
	unsigned char *data, result[NANO_BLOCK_SIGNATURE_LENGTH];
	int tgifo_ret;
	int data_length, result_length;

	if (objc < 2 || objc > 3) {
		Tcl_WrongNumArgs(interp, 1, objv, "data ?hashLength?");

		return(TCL_ERROR);
	}

	data = Tcl_GetByteArrayFromObj(objv[1], &data_length);
	if (objc == 3) {
		tgifo_ret = Tcl_GetIntFromObj(interp, objv[2], &result_length);
		if (tgifo_ret != TCL_OK) {
			return(tgifo_ret);
		}

		if (result_length > sizeof(result)) {
			Tcl_SetResult(interp, "Hash length too large", NULL);

			return(TCL_ERROR);
		}

		blake2b(result, result_length, data, data_length, NULL, 0);
	} else {
		/*
		 * Default to the same as the cryptographic primitive
		 */
		crypto_hash(result, data, data_length);
		result_length = NANO_BLOCK_SIGNATURE_LENGTH;
	}

	Tcl_SetObjResult(interp, Tcl_NewByteArrayObj(result, result_length));

	return(TCL_OK);

	/* NOTREACH */
	clientData = clientData;
}

static int nano_validate_work(const unsigned char *blockhash, const unsigned char *work, uint64_t workMin) {
	unsigned char workReversed[NANO_WORK_VALUE_LENGTH], workCheck[NANO_WORK_HASH_LENGTH];
	unsigned int idxIn, idxOut;
	blake2b_state workhash_state;
	uint64_t workValue;
	int blake2_ret;

	idxIn = sizeof(workReversed) - 1;
	idxOut = 0;
	while (idxOut < sizeof(workReversed)) {
		workReversed[idxOut] = work[idxIn];
		idxOut++;
		idxIn--;
	}

	blake2_ret = blake2b_init(&workhash_state, sizeof(workCheck));
	if (blake2_ret != 0) {
		return(0);
	}

	blake2_ret = blake2b_update(&workhash_state, workReversed, sizeof(workReversed));
	if (blake2_ret != 0) {
		return(0);
	}

	blake2_ret = blake2b_update(&workhash_state, blockhash, NANO_BLOCK_HASH_LENGTH);
	if (blake2_ret != 0) {
		return(0);
	}

	blake2_ret = blake2b_final(&workhash_state, workCheck, sizeof(workCheck));
	if (blake2_ret != 0) {
		return(0);
	}

	workValue = 0;
	for (idxIn = sizeof(workCheck); idxIn > 0; idxIn--) {
		workValue <<= 8;
		workValue |= workCheck[idxIn - 1];
	}

	if (workValue < workMin) {
		/* Fails to meet the requirements */
		return(0);
	}

	return(1);
}

static void nano_generate_work(const unsigned char *blockhash, unsigned char *workOut, uint64_t workMin) {
	unsigned char work[NANO_WORK_VALUE_LENGTH];
	unsigned int offset;
	int work_valid;

	memcpy(work, blockhash, sizeof(work));

#pragma omp target map(tofrom:work)
	while (1) {
		work_valid = nano_validate_work(blockhash, work, workMin);
		if (work_valid) {
			break;
		}

		offset = 0;
		while (work[offset] == 0xff) {
			work[offset] = 0;
			offset++;
			offset %= sizeof(work);
		}

		work[offset] = (((int) work[offset]) + 1) & 0xff;
	}

	memcpy(workOut, work, sizeof(work));

	return;
}

static int nano_tcl_validate_work(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
	unsigned char *blockhash, *work;
	Tcl_WideUInt tclWorkMin;
	uint64_t workMin = NANO_WORK_DEFAULT_MIN;
	int blockhash_length, work_length;
	int valid, result;
	int tgwifo_ret;

	if (objc < 3 || objc > 4) {
		Tcl_WrongNumArgs(interp, 1, objv, "workBlockhash work ?workMin?");

		return(TCL_ERROR);
	}

	blockhash = Tcl_GetByteArrayFromObj(objv[1], &blockhash_length);
	if (blockhash_length != NANO_BLOCK_HASH_LENGTH) {
		Tcl_SetResult(interp, "Block hash size is wrong", NULL);

		return(TCL_ERROR);
	}

	work = Tcl_GetByteArrayFromObj(objv[2], &work_length);
	if (work_length != NANO_WORK_VALUE_LENGTH) {
		Tcl_SetResult(interp, "Work size is wrong", NULL);

		return(TCL_ERROR);
	}

	if (objc == 4) {
		tgwifo_ret = Tcl_GetWideIntFromObj(interp, objv[3], (Tcl_WideInt *) &tclWorkMin);
		if (tgwifo_ret != TCL_OK) {
			return(tgwifo_ret);
		}

		workMin = tclWorkMin;
	}

	valid = nano_validate_work(blockhash, work, workMin);
	if (valid) {
		result = 1;
	} else {
		result = 0;
	}

	Tcl_SetObjResult(interp, Tcl_NewBooleanObj(result));

	return(TCL_OK);

	/* NOTREACH */
	clientData = clientData;
}

static int nano_tcl_generate_work(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
	Tcl_WideUInt tclWorkMin;
	unsigned char *blockhash;
	unsigned char work[NANO_WORK_VALUE_LENGTH];
	uint64_t workMin = NANO_WORK_DEFAULT_MIN;
	int blockhash_length;
	int tgwifo_ret;

	if (objc < 2 || objc > 3) {
		Tcl_WrongNumArgs(interp, 1, objv, "workBlockhash ?workMin?");

		return(TCL_ERROR);
	}

	blockhash = Tcl_GetByteArrayFromObj(objv[1], &blockhash_length);
	if (blockhash_length != NANO_BLOCK_HASH_LENGTH) {
		Tcl_SetResult(interp, "Block hash size is wrong", NULL);

		return(TCL_ERROR);
	}

	if (objc == 3) {
		tgwifo_ret = Tcl_GetWideIntFromObj(interp, objv[2], (Tcl_WideInt *) &tclWorkMin);
		if (tgwifo_ret != TCL_OK) {
			return(tgwifo_ret);
		}

		workMin = tclWorkMin;
	}

	nano_generate_work(blockhash, work, workMin);

	Tcl_SetObjResult(interp, Tcl_NewByteArrayObj(work, sizeof(work)));

	return(TCL_OK);

	/* NOTREACH */
	clientData = clientData;
}

static int nano_tcl_random_bytes(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
	unsigned char *buffer;
	int number_of_bytes;
	int tgifo_ret;

	if (objc != 2) {
		Tcl_WrongNumArgs(interp, 1, objv, "numberOfBytes");

		return(TCL_ERROR);
	}

	tgifo_ret = Tcl_GetIntFromObj(interp, objv[1], &number_of_bytes);
	if (tgifo_ret != TCL_OK) {
		return(tgifo_ret);
	}

	if (number_of_bytes > 128) {
		Tcl_SetResult(interp, "May only request 128 bytes of random data at once", NULL);

		return(TCL_ERROR);
	}

	buffer = TclNano_AttemptAlloc(number_of_bytes);
	if (!buffer) {
		Tcl_SetResult(interp, "memory allocation failure", NULL);

		return(TCL_ERROR);
	}

	randombytes(buffer, number_of_bytes);

	Tcl_SetObjResult(interp, Tcl_NewByteArrayObj(buffer, number_of_bytes));

	TclNano_Free(buffer);

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
	void *tclobj_ret;
	int tclcmd_ret;
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

	if (!interp) {
		return(TCL_OK);
	}

	TclNano_CreateNamespace(interp, "::nano");
	TclNano_CreateNamespace(interp, "::nano::block");
	TclNano_CreateNamespace(interp, "::nano::key");
	TclNano_CreateNamespace(interp, "::nano::work");

	TclNano_SetIntVar(interp, "::nano::block::hashLength", NANO_BLOCK_HASH_LENGTH);
	TclNano_SetIntVar(interp, "::nano::block::signatureLength", NANO_BLOCK_SIGNATURE_LENGTH);
	TclNano_SetIntVar(interp, "::nano::key::publicKeyLength", NANO_PUBLIC_KEY_LENGTH);
	TclNano_SetIntVar(interp, "::nano::key::privateKeyLength", NANO_SECRET_KEY_LENGTH);
	TclNano_SetIntVar(interp, "::nano::key::seedLength", NANO_SECRET_KEY_LENGTH);
	TclNano_SetIntVar(interp, "::nano::work::workValueLength", NANO_WORK_VALUE_LENGTH);
	TclNano_SetIntVar(interp, "::nano::work::workHashLength", NANO_WORK_HASH_LENGTH);

	TclNano_CreateObjCommand(interp, "::nano::internal::selfTest", nano_tcl_self_test);
	TclNano_CreateObjCommand(interp, "::nano::internal::generateKey", nano_tcl_generate_keypair);
	TclNano_CreateObjCommand(interp, "::nano::internal::generateSeed", nano_tcl_generate_seed);
	TclNano_CreateObjCommand(interp, "::nano::internal::publicKey", nano_tcl_secret_key_to_public_key);
	TclNano_CreateObjCommand(interp, "::nano::internal::signDetached", nano_tcl_sign_detached);
	TclNano_CreateObjCommand(interp, "::nano::internal::verifyDetached", nano_tcl_verify_detached);
	TclNano_CreateObjCommand(interp, "::nano::internal::hashData", nano_tcl_hash_data);
	TclNano_CreateObjCommand(interp, "::nano::internal::validateWork", nano_tcl_validate_work);
	TclNano_CreateObjCommand(interp, "::nano::internal::generateWork", nano_tcl_generate_work);
	TclNano_CreateObjCommand(interp, "::nano::internal::randomBytes", nano_tcl_random_bytes);

	TclNano_Eval(interp, nanoInitScript);

	TclNano_PkgProvide(interp, "nano", PACKAGE_VERSION);

	return(TCL_OK);
}
