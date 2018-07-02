#if defined(NACL_ED25519_BLAKE2B)
int crypto_hash_blake2b( unsigned char *out, unsigned char *in, unsigned long long inlen )
{
  return blake2b( out, BLAKE2B_OUTBYTES, in, inlen, NULL, 0 );
}
#endif
