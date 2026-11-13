/* SPDX-License-Identifier: Apache-2.0 */

/*
 * dnsfilter_bihash_8_24.h — bihash with a u64 key and a 24-byte value
 * (vppinfra has 8_8 and 8_16 only): the return table's entry grew by the
 * query's VLAN tags (dnsfilter_ret_t). Same parameters as bihash_8_16.h;
 * instantiated once, in dnsfilter.c (bihash_template.c).
 */

#undef BIHASH_TYPE
#undef BIHASH_KVP_PER_PAGE
#undef BIHASH_32_64_SVM
#undef BIHASH_ENABLE_STATS
#undef BIHASH_KVP_AT_BUCKET_LEVEL
#undef BIHASH_LAZY_INSTANTIATE
#undef BIHASH_BUCKET_PREFETCH_CACHE_LINES
#undef BIHASH_USE_HEAP

#define BIHASH_TYPE			   _8_24
#define BIHASH_KVP_PER_PAGE		   4
#define BIHASH_KVP_AT_BUCKET_LEVEL	   1
#define BIHASH_LAZY_INSTANTIATE		   0
#define BIHASH_BUCKET_PREFETCH_CACHE_LINES 2
#define BIHASH_USE_HEAP			   1

#ifndef __included_dnsfilter_bihash_8_24_h__
#define __included_dnsfilter_bihash_8_24_h__

#include <vppinfra/heap.h>
#include <vppinfra/format.h>
#include <vppinfra/pool.h>
#include <vppinfra/xxhash.h>
#include <vppinfra/crc32.h>

typedef struct
{
  u64 key;
  u64 value[3];
} clib_bihash_kv_8_24_t;

static inline void
clib_bihash_mark_free_8_24 (clib_bihash_kv_8_24_t *v)
{
  v->value[0] = 0xFEEDFACE8BADF00DULL;
}

static inline int
clib_bihash_is_free_8_24 (clib_bihash_kv_8_24_t *v)
{
  return v->value[0] == 0xFEEDFACE8BADF00DULL;
}

static inline u64
clib_bihash_hash_8_24 (clib_bihash_kv_8_24_t *v)
{
#ifdef clib_crc32c_uses_intrinsics
  return clib_crc32c ((u8 *) &v->key, 8);
#else
  return clib_xxhash (v->key);
#endif
}

static inline u8 *
format_bihash_kvp_8_24 (u8 *s, va_list *args)
{
  clib_bihash_kv_8_24_t *v = va_arg (*args, clib_bihash_kv_8_24_t *);

  return format (s, "key %llx value [%llx,%llx,%llx]", v->key, v->value[0],
		 v->value[1], v->value[2]);
}

static inline int
clib_bihash_key_compare_8_24 (u64 a, u64 b)
{
  return a == b;
}

#undef __included_bihash_template_h__
#include <vppinfra/bihash_template.h>

#endif /* __included_dnsfilter_bihash_8_24_h__ */
