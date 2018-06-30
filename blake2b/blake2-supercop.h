#define crypto_hash_PRIMITIVE "blake2b"
#define crypto_hash_BYTES crypto_hash_blake2b_BYTES
#define crypto_hash_IMPLEMENTATION crypto_hash_blake2b_IMPLEMENTATION
#define crypto_hash_VERSION crypto_hash_blake2b_VERSION
#define crypto_hash_blake2b_BYTES 64
extern int crypto_hash(unsigned char *,const unsigned char *,unsigned long long);
#define crypto_hash_blake2b_VERSION "-"
#define crypto_hash_blake2b_IMPLEMENTATION "blake2b-ref"
