#ifndef NNG_SNPRINTF_H
#define NNG_SNPRINTF_H

#include <stdarg.h>  // NOLINT
#include <stdio.h>   // NOLINT

#if !defined(__cplusplus) && defined(_MSC_VER)
#define inline __inline
#endif  //__cplusplus && _MSC_VER

#ifdef __cplusplus
extern "C" {
#endif  //__cplusplus

#if !defined(_TRUNCATE)
#define _TRUNCATE ((size_t)-1)
#endif  //_TRUNCATE

inline int nng_snprintf(char* const _Buffer, int const _BufferCount, char const* const _Format, ...) {
  int ret = 0;
  va_list args;
  va_start(args, _Format);
#if _MSC_VER
  ret = vsnprintf_s(_Buffer, _BufferCount, _TRUNCATE, _Format, args);
#else
  ret = vsnprintf(_Buffer, _BufferCount, _Format, args);
#endif
  va_end(args);
  return ret;
}

#ifdef USE_NNG_SNPRINTF
#if USE_NNG_SNPRINTF
#define snprintf nng_snprintf
#endif
#endif

#ifdef __cplusplus
}
#endif  //__cplusplus

#endif  // NNG_SNPRINTF_H
