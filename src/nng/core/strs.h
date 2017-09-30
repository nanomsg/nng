//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
// Copyright 2017 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef CORE_STRS_H
#define CORE_STRS_H

// Safe string functions, in case the platform misses these.

extern char * nni_strdup(const char *);
extern void   nni_strfree(char *);
extern size_t nni_strlcpy(char *, const char *, size_t);
extern size_t nni_strlcat(char *, const char *, size_t);
extern size_t nni_strnlen(const char *, size_t);

#endif // CORE_STRS_H
