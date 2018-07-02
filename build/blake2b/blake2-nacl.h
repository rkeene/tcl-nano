#if defined(NACL_ED25519_BLAKE2B)
#ifndef BLAKE2_NACL_H
#define BLAKE2_NACL_H 1
#define crypto_hash_PRIMITIVE "blake2b"
#define crypto_hash_BYTES crypto_hash_blake2b_BYTES
#define crypto_hash_IMPLEMENTATION crypto_hash_blake2b_IMPLEMENTATION
#define crypto_hash_VERSION crypto_hash_blake2b_VERSION
#define crypto_hash_blake2b_BYTES 64
#define crypto_hash_blake2b_VERSION "-"
#define crypto_hash_blake2b_IMPLEMENTATION "blake2b-ref"
#define crypto_hash crypto_hash_blake2b
#if defined(__cplusplus)
extern "C" {
#endif
int crypto_hash_blake2b(unsigned char *,const unsigned char *,unsigned long long);
#if defined(__cplusplus)
}
#endif
#endif
#endif
