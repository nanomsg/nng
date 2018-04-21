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

if (NNG_PROTO_SURVEYOR0)
    set(SURV0_SOURCES protocol/survey0/survey.c protocol/survey0/xsurvey.c
    protocol/survey0/survey.h)
    set(SURV0_HEADERS protocol/survey0/survey.h)
endif()

if (NNG_PROTO_RESPONDENT0)
    set(RESP0_SOURCES protocol/survey0/respond.c protocol/survey0/xrespond.c
    protocol/survey0/respond.h)
    set(RESP0_HEADERS protocol/survey0/respond.h)
endif()

set(NNG_SOURCES ${NNG_SOURCES} ${SURV0_SOURCES} ${RESP0_SOURCES} PARENT_SCOPE)
set(NNG_HEADERS ${NNG_HEADERS} ${SURV0_HEADERS} ${RESP0_HEADERS} PARENT_SCOPE)
