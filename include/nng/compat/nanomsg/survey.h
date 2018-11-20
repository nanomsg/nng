//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef NNG_COMPAT_SURVEY_H
#define NNG_COMPAT_SURVEY_H

// This header contains interfaces that are intended to offer compatibility
// with nanomsg v1.0.  These are not the "preferred" interfaces for nng,
// and consumers should only use these if they are porting software that
// previously used nanomsg.  New programs should use the nng native APIs.

#ifdef __cplusplus
extern "C" {
#endif

// SURVEYOR and RESPONDENT sockopt level.
#define NN_PROTO_SURVEY 6
#define NN_SURVEYOR (NN_PROTO_SURVEY * 16 + 2)
#define NN_RESPONDENT (NN_PROTO_SURVEY * 16 + 3)

// SURVEYOR options.  (RESPONDENT has none.)

#define NN_SURVEYOR_DEADLINE (NN_SURVEYOR * 16 + 1)

#ifdef __cplusplus
}
#endif

#endif // NNG_COMPAT_SURVEY_H
