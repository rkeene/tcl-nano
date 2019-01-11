#define crypto_hash(out, in, inlen) crypto_blake2b(out, in, inlen)
#define blake2b(out, outlen, in, inlen, key, keylen) 0, crypto_blake2b_general(out, outlen, key, keylen, in, inlen)
#define blake2b_state crypto_blake2b_ctx
#define blake2b_init(ctx, outlen) 0; crypto_blake2b_general_init(ctx, outlen, NULL, 0)
#define blake2b_update(ctx, in, inlen) 0; crypto_blake2b_update(ctx, in, inlen)
#define blake2b_final(ctx, out, ignore1) 0; crypto_blake2b_final(ctx, out)
#define BLAKE2_INLINE
#define BLAKE2B_OUTBYTES 64
#include <stdint.h>
#include <tcl.h>
#include "monocypher.h"
static BLAKE2_INLINE uint64_t rotr64(uint64_t x, uint64_t n) { return (x >> n) ^ (x << (64 - n)); }
static BLAKE2_INLINE void store32( void *dst, uint32_t w )
{
#if defined(NATIVE_LITTLE_ENDIAN)
  memcpy(dst, &w, sizeof w);
#else
  uint8_t *p = ( uint8_t * )dst;
  p[0] = (uint8_t)(w >>  0);
  p[1] = (uint8_t)(w >>  8);
  p[2] = (uint8_t)(w >> 16);
  p[3] = (uint8_t)(w >> 24);
#endif
}

static BLAKE2_INLINE void store64( void *dst, uint64_t w )
{
#if defined(NATIVE_LITTLE_ENDIAN)
  memcpy(dst, &w, sizeof w);
#else
  uint8_t *p = ( uint8_t * )dst;
  p[0] = (uint8_t)(w >>  0);
  p[1] = (uint8_t)(w >>  8);
  p[2] = (uint8_t)(w >> 16);
  p[3] = (uint8_t)(w >> 24);
  p[4] = (uint8_t)(w >> 32);
  p[5] = (uint8_t)(w >> 40);
  p[6] = (uint8_t)(w >> 48);
  p[7] = (uint8_t)(w >> 56);
#endif
}

static BLAKE2_INLINE uint64_t load64( const void *src )
{
#if defined(NATIVE_LITTLE_ENDIAN)
  uint64_t w;
  memcpy(&w, src, sizeof w);
  return w;
#else
  const uint8_t *p = ( const uint8_t * )src;
  return (( uint64_t )( p[0] ) <<  0) |
         (( uint64_t )( p[1] ) <<  8) |
         (( uint64_t )( p[2] ) << 16) |
         (( uint64_t )( p[3] ) << 24) |
         (( uint64_t )( p[4] ) << 32) |
         (( uint64_t )( p[5] ) << 40) |
         (( uint64_t )( p[6] ) << 48) |
         (( uint64_t )( p[7] ) << 56) ;
#endif
}

