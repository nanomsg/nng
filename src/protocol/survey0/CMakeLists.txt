#
# Copyright 2017 Garrett D'Amore <garrett@damore.org>
# Copyright 2017 Capitar IT Group BV <info@capitar.com>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

#  Req/Rep protocol

if (NNG_PROTO_SURVEYOR0)
    set(SURV0_SOURCES protocol/survey0/survey.c protocol/survey0/survey.h)
    install(FILES survey.h DESTINATION include/nng/protocol/survey0)
endif()

if (NNG_PROTO_RESPONDENT0)
    set(RESP0_SOURCES protocol/survey0/respond.c protocol/survey0/respond.h)
    install(FILES respond.h DESTINATION include/nng/protocol/survey0)
endif()

set(NNG_SOURCES ${NNG_SOURCES} ${SURV0_SOURCES} ${RESP0_SOURCES} PARENT_SCOPE)