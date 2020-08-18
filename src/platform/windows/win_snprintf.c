#ifndef NNG_WIN_SNPRINTF_H
#define NNG_WIN_SNPRINTF_H

#if !NNG_HAVE_SNPRINTF
#if defined(_MSC_VER) && (_MSC_VER < 1900)

#include <stdarg.h> // NOLINT
#include <stdio.h>  // NOLINT

#if !defined(_TRUNCATE)
#define _TRUNCATE ((size_t) -1)
#endif //_TRUNCATE

// Each of these functions takes a pointer to an argument list, then formats
// and writes up to count characters of the given data to the memory pointed to
// by buffer and appends a terminating null. If count is _TRUNCATE, then these
// functions write as much of the string as will fit in buffer while leaving
// room for a terminating null. If the entire string (with terminating null)
// fits in buffer, then these functions return the number of characters written
// (not including the terminating null); otherwise, these functions return -1
// to indicate that truncation occurred.
int
snprintf(char *buffer, size_t count, const char *format, ...)
{
	va_list args;
	va_start(args, format);
	int ret = vsnprintf_s(buffer, count, _TRUNCATE, format, args);
	va_end(args);
	return ret;
}

#endif // _MSC_VER < 1900
#endif // !NNG_HAVE_SNPRINTF
#endif NNG_WIN_SNPRINTF_H