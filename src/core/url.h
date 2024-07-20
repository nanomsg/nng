//
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef CORE_URL_H
#define CORE_URL_H

#include "defs.h"

extern int         nni_url_parse(nni_url **, const char *path);
extern void        nni_url_free(nni_url *);
extern int         nni_url_clone(nni_url **, const nni_url *);
extern const char *nni_url_default_port(const char *);
extern uint16_t    nni_url_family(const char *);
extern int         nni_url_asprintf(char **, const nni_url *);
extern int         nni_url_asprintf_port(char **, const nni_url *, int);
extern size_t      nni_url_decode(uint8_t *, const char *, size_t);
extern int         nni_url_to_address(nng_sockaddr *, const nni_url *);

#endif // CORE_URL_H
