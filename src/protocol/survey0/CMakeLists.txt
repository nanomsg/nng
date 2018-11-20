#
# Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
# Copyright 2018 Capitar IT Group BV <info@capitar.com>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

# Surveyor/Respondent protocol
option (NNG_PROTO_RESPONDENT0 "Enable RESPONDENTv0 protocol." ON)
mark_as_advanced(NNG_PROTO_RESPONDENT0)

option (NNG_PROTO_SURVEYOR0 "Enable SURVEYORv0 protocol." ON)
mark_as_advanced(NNG_PROTO_SURVEYOR0)

set(_DEFS)
set(_SRCS)

if (NNG_PROTO_SURVEYOR0)
    list(APPEND _DEFS -DNNG_HAVE_SURVEYOR0)
    list(APPEND _SRCS
        protocol/survey0/survey.c protocol/survey0/xsurvey.c
        ${PROJECT_SOURCE_DIR}/include/nng/protocol/survey0/survey.h)
   
endif()

if (NNG_PROTO_RESPONDENT0)
    list(APPEND _DEFS -DNNG_HAVE_RESPONDENT0)
    list(APPEND _SRCS
        protocol/survey0/respond.c protocol/survey0/xrespond.c
        ${PROJECT_SOURCE_DIR}/include/nng/protocol/survey0/respond.h)
   
endif()

set(NNG_DEFS ${NNG_DEFS} ${_DEFS} PARENT_SCOPE)
set(NNG_SRCS ${NNG_SRCS} ${_SRCS} PARENT_SCOPE)
