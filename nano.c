/* XXX:TODO: OpenMP support is currently incomplete */
#undef NANO_TCL_HAVE_OPENMP

#ifdef HAVE_WS2TCPIP_H
#  include <ws2tcpip.h>
#endif
#ifdef HAVE_WINDOWS_H
#  include <windows.h>
#endif

#include <stdint.h>
#include <limits.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <tcl.h>
#ifdef NANO_TCL_HAVE_OPENMP
#  include <omp.h>
#endif

/*
 * We need both getaddrinfo and inet_ntop for DNS resolution
 */
#if defined(HAVE_GETNAMEINFO) && defined(HAVE_GETADDRINFO)
#  define NANO_TCL_CAN_RESOLVE_NAMES 1
#else
#  undef NANO_TCL_CAN_RESOLVE_NAMES
#endif

#ifdef NANO_TCL_CAN_RESOLVE_NAMES
#  ifdef HAVE_SYS_SOCKET_H
#    include <sys/socket.h>
#  endif
#  ifdef HAVE_SYS_TYPES_H
#    include <sys/types.h>
#  endif
#  ifdef HAVE_NETDB_H
#    include <netdb.h>
# endif
#endif

#include "randombytes.h"
#include "monocypher.h"
#include "argon2.h"
#include "aes.h"

#define NANO_SECRET_KEY_LENGTH 32
#define NANO_PUBLIC_KEY_LENGTH 32
#define NANO_BLOCK_HASH_LENGTH 32
#define NANO_BLOCK_SIGNATURE_LENGTH 64
#define NANO_WORK_VALUE_LENGTH 8
#define NANO_WORK_HASH_LENGTH  8
#define NANO_WORK_DEFAULT_MIN  0xffffffc000000000LLU
#define NANO_KDF_ARGON2_MEMORY 64 * 1024
#define NANO_KDF_ARGON2_TIMING 1
#define NANO_KDF_ARGON2_THREADS 1

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

static unsigned char *nano_parse_secret_key(Tcl_Obj *secret_key_only_obj, unsigned char *public_key, int public_key_length) {
	unsigned char *secret_key_only;
	int secret_key_only_length;

	secret_key_only = Tcl_GetByteArrayFromObj(secret_key_only_obj, &secret_key_only_length);
	if (secret_key_only_length != NANO_SECRET_KEY_LENGTH) {
		return(NULL);
	}

	if (public_key_length != NANO_PUBLIC_KEY_LENGTH) {
		return(NULL);
	}

	crypto_sign_public_key(public_key, secret_key_only);

	return(public_key);
}

static int nano_tcl_generate_keypair(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
	unsigned char secret_key[NANO_SECRET_KEY_LENGTH], public_key[NANO_PUBLIC_KEY_LENGTH];
	unsigned char *seed, *buffer, buffer_s[NANO_SECRET_KEY_LENGTH + 4];
	long seed_index;
	int seed_length, buffer_length;
	int tglfo_ret;

	if (objc != 1 && objc != 3) {
		Tcl_WrongNumArgs(interp, 1, objv, "?seed index?");

		return(TCL_ERROR);
	}

	if (objc == 1) {
		randombytes(secret_key, NANO_SECRET_KEY_LENGTH);
		crypto_sign_public_key(public_key, secret_key);
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

		crypto_blake2b_general(secret_key, NANO_SECRET_KEY_LENGTH, NULL, 0, buffer, buffer_length);
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
	Tcl_Obj *secret_key;
	unsigned char *public_key, public_key_buffer[NANO_PUBLIC_KEY_LENGTH];
	int public_key_length;

	if (objc != 2) {
		Tcl_WrongNumArgs(interp, 1, objv, "secretKey");

		return(TCL_ERROR);
	}

	secret_key = objv[1];

	public_key_length = sizeof(public_key_buffer);
	public_key = nano_parse_secret_key(secret_key, public_key_buffer, public_key_length);

	Tcl_SetObjResult(interp, Tcl_NewByteArrayObj(public_key, public_key_length));

	return(TCL_OK);

	/* NOTREACH */
	clientData = clientData;
}

static int nano_tcl_sign_detached(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
	unsigned char signature[NANO_BLOCK_SIGNATURE_LENGTH];
	unsigned char public_key_buffer[NANO_PUBLIC_KEY_LENGTH];
	unsigned char *data, *secret_key, *public_key;
	int data_length, public_key_length, secret_key_length;

	if (objc != 3) {
		Tcl_WrongNumArgs(interp, 1, objv, "data secretKey");

		return(TCL_ERROR);
	}

	data = Tcl_GetByteArrayFromObj(objv[1], &data_length);

	secret_key = Tcl_GetByteArrayFromObj(objv[2], &secret_key_length);
	if (secret_key_length != NANO_SECRET_KEY_LENGTH) {
		Tcl_SetResult(interp, "Secret key is not the right size", NULL);

		return(TCL_ERROR);
	}

	public_key_length = sizeof(public_key_buffer);
	public_key = nano_parse_secret_key(objv[2], public_key_buffer, public_key_length);
	if (!public_key) {
		Tcl_SetResult(interp, "Error converting secret key to public key", NULL);

		return(TCL_ERROR);
	}

	crypto_sign(signature, secret_key, public_key, data, data_length);

	Tcl_SetObjResult(interp, Tcl_NewByteArrayObj(signature, NANO_BLOCK_SIGNATURE_LENGTH));

	return(TCL_OK);

	/* NOTREACH */
	clientData = clientData;
}

static int nano_tcl_verify_detached(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
	int cc_ret;
	unsigned char *signature, *data, *public_key;
	int signature_length, data_length, public_key_length;
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

	cc_ret = crypto_check(signature, public_key, data, data_length);
	result = 0;
	if (!cc_ret) {
		result = 1;
	}

	Tcl_SetObjResult(interp, Tcl_NewBooleanObj(result));

	return(TCL_OK);

	/* NOTREACH */
	clientData = clientData;
}

static int nano_tcl_derive_key_from_password(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
	void *password, *salt;
	int password_length, salt_length;
	unsigned char result[32];
	int hash_ret;

	if (objc != 3) {
		Tcl_WrongNumArgs(interp, 1, objv, "password salt");

		return(TCL_ERROR);
	}

	password = Tcl_GetByteArrayFromObj(objv[1], &password_length);
	salt = Tcl_GetByteArrayFromObj(objv[2], &salt_length);

	hash_ret = argon2_hash(NANO_KDF_ARGON2_TIMING, NANO_KDF_ARGON2_MEMORY, NANO_KDF_ARGON2_THREADS,
	                       password, password_length,
	                       salt, salt_length,
	                       result, sizeof(result),
	                       NULL, 0, Argon2_d, 0x10);

	if (hash_ret != ARGON2_OK) {
		Tcl_SetResult(interp, (char *) argon2_error_message(hash_ret), NULL);

		return(TCL_ERROR);
	}

	Tcl_SetObjResult(interp, Tcl_NewByteArrayObj(result, sizeof(result)));

	return(TCL_OK);

	/* NOTREACH */
	clientData = clientData;
}

static int nano_tcl_aes256_ctr(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
	struct AES_ctx aes_handle;
	void *key, *iv, *data;
	int key_length, iv_length, data_length;
	unsigned char result[128];

	if (objc != 4) {
		Tcl_WrongNumArgs(interp, 1, objv, "key iv data");

		return(TCL_ERROR);
	}

	key  = Tcl_GetByteArrayFromObj(objv[1], &key_length);
	iv   = Tcl_GetByteArrayFromObj(objv[2], &iv_length);
	data = Tcl_GetByteArrayFromObj(objv[3], &data_length);

	if (key_length != AES_KEYLEN) {
		Tcl_SetResult(interp, "Key is not the right size", NULL);

		return(TCL_ERROR);
	}

	if (iv_length != AES_BLOCKLEN) {
		Tcl_SetResult(interp, "IV is not the right size", NULL);

		return(TCL_ERROR);
	}

	if (data_length > sizeof(result)) {
		Tcl_SetResult(interp, "Data exceeds maximum size", NULL);

		return(TCL_ERROR);
	}

	memcpy(result, data, data_length);

	AES_init_ctx_iv(&aes_handle, key, iv);
	AES_CTR_xcrypt_buffer(&aes_handle, result, data_length);

	Tcl_SetObjResult(interp, Tcl_NewByteArrayObj(result, AES_KEYLEN));

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

		crypto_blake2b_general(result, result_length, NULL, 0, data, data_length);
	} else {
		/*
		 * Default to the same as the cryptographic primitive
		 */
		crypto_blake2b(result, data, data_length);
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
	crypto_blake2b_ctx workhash_state;
	uint64_t workValue;

	idxIn = sizeof(workReversed) - 1;
	idxOut = 0;
	while (idxOut < sizeof(workReversed)) {
		workReversed[idxOut] = work[idxIn];
		idxOut++;
		idxIn--;
	}

	crypto_blake2b_general_init(&workhash_state, sizeof(workCheck), NULL, 0);
	crypto_blake2b_update(&workhash_state, workReversed, sizeof(workReversed));
	crypto_blake2b_update(&workhash_state, blockhash, NANO_BLOCK_HASH_LENGTH);
	crypto_blake2b_final(&workhash_state, workCheck);

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

/* XXX:TODO: INCOMPLETE OpenMP support #pragma omp target map(tofrom:work) */
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
	unsigned char buffer[128];
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

	randombytes(buffer, number_of_bytes);

	Tcl_SetObjResult(interp, Tcl_NewByteArrayObj(buffer, number_of_bytes));

	return(TCL_OK);

	/* NOTREACH */
	clientData = clientData;
}

#ifdef NANO_TCL_CAN_RESOLVE_NAMES
static int nano_tcl_resolve_name(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
	Tcl_Encoding ascii_encoding;
	Tcl_Obj *list_of_hostnames, *hostname_obj;
	struct addrinfo *gai_data, *addr_current;
	char *hostname_utf8, hostname[256];
	int hostname_utf8_length, hostname_utf8_length_processed, hostname_length;
	int tute_ret, gai_ret, gni_ret;

	if (objc != 2) {
		Tcl_WrongNumArgs(interp, 1, objv, "hostname");

		return(TCL_ERROR);
	}

	hostname_utf8 = Tcl_GetStringFromObj(objv[1], &hostname_utf8_length);
	if (!hostname_utf8) {
		return(TCL_ERROR);
	}

	/*
	 * getaddrinfo() accepts ASCII input, so convert to that encoding
	 */
	ascii_encoding = Tcl_GetEncoding(interp, "ascii");
	if (ascii_encoding == NULL) {
		return(TCL_ERROR);
	}

	tute_ret = Tcl_UtfToExternal(interp, ascii_encoding, hostname_utf8,
	               hostname_utf8_length, TCL_ENCODING_STOPONERROR, NULL,
	               hostname, sizeof(hostname),
	               &hostname_utf8_length_processed,
	               &hostname_length, NULL
	           );

	Tcl_FreeEncoding(ascii_encoding);

	if (tute_ret != TCL_OK) {
		Tcl_SetResult(interp, "Failed to convert to ASCII", NULL);

		return(TCL_ERROR);
	}

	if (hostname_utf8_length_processed != hostname_utf8_length) {
		Tcl_SetResult(interp, "Failed to convert entire buffer", NULL);

		return(TCL_ERROR);
	}

	gai_ret = getaddrinfo(hostname, NULL, NULL, &gai_data);
	if (gai_ret != 0) {
		Tcl_SetResult(interp, "", NULL);

		return(TCL_OK);
	}

	list_of_hostnames = Tcl_NewObj();
	for (addr_current = gai_data; addr_current; addr_current = addr_current->ai_next) {
		if (addr_current->ai_family != AF_INET && addr_current->ai_family != AF_INET6) {
			continue;
		}

		gni_ret = getnameinfo(addr_current->ai_addr, addr_current->ai_addrlen,
		                      hostname, sizeof(hostname),
		                      NULL, 0, NI_NUMERICHOST
		          );
		if (gni_ret != 0) {
			continue;
		}

		hostname_obj = Tcl_NewStringObj(hostname, -1);

		Tcl_ListObjAppendElement(NULL, list_of_hostnames, hostname_obj);
	}

	freeaddrinfo(gai_data);

	Tcl_SetObjResult(interp, list_of_hostnames);

	return(TCL_OK);

	/* NOTREACH */
	clientData = clientData;
}
#else
static int nano_tcl_resolve_name(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
	Tcl_SetResult(interp, "Not supported on this platform", NULL);
	
	return(TCL_ERROR);
}
#endif

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
	TclNano_CreateNamespace(interp, "::nano::internal");
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
#ifdef NANO_TCL_CAN_RESOLVE_NAMES
	TclNano_SetIntVar(interp, "::nano::internal::haveResolveName", 1);
#else
	TclNano_SetIntVar(interp, "::nano::internal::haveResolveName", 0);
#endif

	TclNano_CreateObjCommand(interp, "::nano::internal::selfTest", nano_tcl_self_test);
	TclNano_CreateObjCommand(interp, "::nano::internal::generateKey", nano_tcl_generate_keypair);
	TclNano_CreateObjCommand(interp, "::nano::internal::generateSeed", nano_tcl_generate_seed);
	TclNano_CreateObjCommand(interp, "::nano::internal::publicKey", nano_tcl_secret_key_to_public_key);
	TclNano_CreateObjCommand(interp, "::nano::internal::signDetached", nano_tcl_sign_detached);
	TclNano_CreateObjCommand(interp, "::nano::internal::verifyDetached", nano_tcl_verify_detached);
	TclNano_CreateObjCommand(interp, "::nano::internal::hashData", nano_tcl_hash_data);
	TclNano_CreateObjCommand(interp, "::nano::internal::deriveKeyFromPassword", nano_tcl_derive_key_from_password);
	TclNano_CreateObjCommand(interp, "::nano::internal::AES256-CTR", nano_tcl_aes256_ctr);
	TclNano_CreateObjCommand(interp, "::nano::internal::validateWork", nano_tcl_validate_work);
	TclNano_CreateObjCommand(interp, "::nano::internal::generateWork", nano_tcl_generate_work);
	TclNano_CreateObjCommand(interp, "::nano::internal::randomBytes", nano_tcl_random_bytes);
	TclNano_CreateObjCommand(interp, "::nano::internal::resolveName", nano_tcl_resolve_name);

	TclNano_Eval(interp, nanoInitScript);

	TclNano_PkgProvide(interp, "nano", PACKAGE_VERSION);

	return(TCL_OK);
}
